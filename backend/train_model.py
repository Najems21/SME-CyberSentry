"""
Trains the SME-CyberSentry hybrid engine from the data stored in cybersentry.db.

    python database/init_db.py
    python database/import_datasets.py
    python backend/train_model.py

Two independent models are trained, each on the signal it can actually learn:

1. URL model  (Random Forest + XGBoost ensemble, multi-class)
   -> models/rf_model.pkl, xgb_model.pkl, tld_risk.json
   Classes: legit / phishing / gambling / piracy  (malware & scam domains are
   handled by the threat-intel lookup - see note in section 1).
   Trained on URL_DATASET (~75k URLs: public threat feeds + Tranco + a Malaysian
   synthetic supplement) using hostname-based lexical features
   (see features.URL_FEATURE_NAMES). Raw URL length is intentionally NOT used:
   long URLs are normal for Gmail, Google Search, Shopee, banking portals, etc.

2. Text model (TF-IDF word n-grams + Logistic Regression) -> models/text_model.pkl
   Trained on TRAINING_DATASET sentences (URLs stripped, so it learns the
   language of the scam rather than "has a link").

Evaluation notes:
   * test_data.csv uses the same sentence templates as train_data.csv, so its
     accuracy is optimistic. We therefore also report an "unseen template"
     score (GroupKFold - every template is held out from training once).
   * The URL test split is grouped by registered domain, so test domains are
     never seen during training.
"""
import json
import os
import re
import sqlite3
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

BACKEND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND)
from features import (URL_FEATURE_NAMES, extract_url_features, parse_url, registered_domain,  # noqa: E402
                      set_tld_risk, strip_urls, tld_of)

URL_CLASSES = ['legit', 'phishing', 'gambling', 'piracy']

DB_PATH = os.path.join(os.path.dirname(BACKEND), 'database', 'cybersentry.db')
MODELS_DIR = os.path.join(BACKEND, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)


def report(name, y_true, y_pred):
    print(f"\n--- {name} ---")
    print(f"Accuracy: {accuracy_score(y_true, y_pred) * 100:.2f}%   F1 (phishing): {f1_score(y_true, y_pred):.4f}")
    print("Confusion matrix [[TN FP] [FN TP]]:\n", confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, target_names=['Legitimate (0)', 'Phishing (1)'], digits=4))
    return {'accuracy': round(accuracy_score(y_true, y_pred), 4), 'f1': round(f1_score(y_true, y_pred), 4)}


conn = sqlite3.connect(DB_PATH)
metrics = {}

# =====================================================================
# 1. URL MODEL  (multi-class: legit / phishing / gambling / piracy)
# =====================================================================
print("=" * 70 + "\n1. URL MODEL (Random Forest + XGBoost, multi-class)\n" + "=" * 70)
url_df = pd.read_sql("SELECT URL, Label, Category, Source FROM URL_DATASET", conn)
if url_df.empty:
    raise SystemExit("URL_DATASET is empty - run fetch_threat_intel.py, build_url_dataset.py and import_datasets.py first.")
# Domain-only malware/scam entries (random C2, tracker and throwaway names such as
# 'homeserviceoutreachpartners.com') carry almost no lexical signal: including them
# raised false positives on legitimate sites from 8% to 17% in our experiments.
# They are detected by the THREAT_INTEL_DOMAINS lookup instead (millions of entries).
url_df = url_df[~url_df.Category.isin(['malware', 'scam'])].reset_index(drop=True)
y_url = url_df.Category.map({c: i for i, c in enumerate(URL_CLASSES)}).values
y_bin = (y_url != 0).astype(int)
hosts = [parse_url(u)[1] for u in url_df.URL]
groups = [registered_domain(h) for h in hosts]
tlds = pd.Series([tld_of(h) for h in hosts])
print("Rows per category:", url_df.Category.value_counts().to_dict())


def fit_tld_risk(idx, m=20):
    """Smoothed malicious rate per TLD, computed ONLY from the given rows."""
    prior = y_bin[idx].mean()
    g = pd.DataFrame({'tld': tlds.iloc[idx].values, 'y': y_bin[idx]}).groupby('tld').y.agg(['sum', 'count'])
    table = ((g['sum'] + m * prior) / (g['count'] + m)).round(4).to_dict()
    return table, round(float(prior), 4)


def build_X(urls):
    return pd.DataFrame([extract_url_features(u) for u in urls], columns=URL_FEATURE_NAMES)


def make_url_models():
    rf = RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_leaf=8,
                                class_weight='balanced_subsample', random_state=42, n_jobs=-1)
    xgb = XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.1, subsample=0.9,
                        colsample_bytree=0.9, objective='multi:softprob', eval_metric='mlogloss',
                        random_state=42, n_jobs=-1)
    return rf, xgb


tr_idx, te_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(url_df, y_url, groups))
set_tld_risk(*fit_tld_risk(tr_idx))
X_all = build_X(url_df.URL)
X_tr, X_te, y_tr, y_te = X_all.iloc[tr_idx], X_all.iloc[te_idx], y_url[tr_idx], y_url[te_idx]
print(f"Train: {len(X_tr)} URLs | Test: {len(X_te)} URLs (test domains never seen in training)")

rf_model, xgb_model = make_url_models()
rf_model.fit(X_tr, y_tr)
xgb_model.fit(X_tr, y_tr)
proba = (rf_model.predict_proba(X_te) + xgb_model.predict_proba(X_te)) / 2
risk = 1 - proba[:, 0]

metrics['url_rf_binary'] = report("URL Random Forest (malicious vs legit)", y_te != 0, rf_model.predict_proba(X_te)[:, 0] < 0.5)
metrics['url_xgb_binary'] = report("URL XGBoost (malicious vs legit)", y_te != 0, xgb_model.predict_proba(X_te)[:, 0] < 0.5)
metrics['url_ensemble_binary'] = report("URL Ensemble (malicious vs legit)", y_te != 0, risk >= 0.5)

pred_cat = proba.argmax(1)
print("\n--- URL Ensemble: category report ---")
print(classification_report(y_te, pred_cat, target_names=URL_CLASSES, digits=4))
print("Confusion matrix (rows = true, cols = predicted):", URL_CLASSES)
print(confusion_matrix(y_te, pred_cat))
metrics['url_category_accuracy'] = round(accuracy_score(y_te, pred_cat), 4)

te = url_df.iloc[te_idx].assign(flagged=risk >= 0.5)
print("\nDetection rate per data source (share flagged as malicious):")
print(te.groupby('Source').flagged.agg(['mean', 'size']).round(3).sort_values('mean').to_string())

imp = pd.Series(rf_model.feature_importances_, index=URL_FEATURE_NAMES).sort_values(ascending=False)
print("\nRandom Forest feature importance:\n" + imp.round(4).to_string())

# Refit on ALL data for deployment (TLD table from all rows too)
tld_table, tld_default = fit_tld_risk(np.arange(len(url_df)))
set_tld_risk(tld_table, tld_default)
X_all = build_X(url_df.URL)
rf_model, xgb_model = make_url_models()
rf_model.fit(X_all, y_url)
xgb_model.fit(X_all, y_url)
with open(os.path.join(MODELS_DIR, 'tld_risk.json'), 'w') as fh:
    json.dump({'tld_risk': tld_table, 'default': tld_default}, fh)

# =====================================================================
# 2. TEXT MODEL
# =====================================================================
print("\n" + "=" * 70 + "\n2. TEXT MODEL (TF-IDF + Logistic Regression)\n" + "=" * 70)
txt = pd.read_sql("SELECT Text, Label, Source_File, Split FROM TRAINING_DATASET", conn)
txt['clean'] = txt.Text.map(strip_urls).str.lower().str.replace(r'\s+', ' ', regex=True).str.strip()
txt['y'] = (txt.Label == 'phishing').astype(int)


def dedupe(df):
    """Collapse duplicate sentences; contradictory labels resolved by majority vote."""
    g = df.groupby('clean').agg(y=('y', 'mean'), n=('y', 'size'), src=('Source_File', 'first')).reset_index()
    conflicts = int(((g.y > 0) & (g.y < 1)).sum())
    g['y'] = (g.y >= 0.5).astype(int)
    return g, conflicts


train_txt, n_conf = dedupe(txt[txt.Split == 'train'])
test_txt, _ = dedupe(txt[txt.Split == 'test'])
print(f"Unique training sentences: {len(train_txt)} (from {int((txt.Split == 'train').sum())} rows; "
      f"{n_conf} contradictory duplicates resolved by majority vote)")
print(f"Unique test sentences: {len(test_txt)}")


def make_text_model():
    return Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2,
                                  token_pattern=r'(?u)\b[a-z][a-z0-9\-\+]+\b')),
        ('lr', LogisticRegression(C=2.0, max_iter=2000, class_weight='balanced')),
    ])


text_model = make_text_model()
text_model.fit(train_txt.clean, train_txt.y)
metrics['text_test_csv'] = report("Text model on test_data.csv (same templates as train - optimistic)",
                                  test_txt.y, text_model.predict(test_txt.clean))

# Honest generalisation estimate: hold out whole templates.
def template_key(s):
    s = re.sub(r'rm\s?\d[\d,]*|txn\d+|\d+', '#', s)
    return ' '.join(re.findall(r'[a-z#]+', s)[:3])  # opening words identify the template


groups = train_txt.clean.map(template_key)
oof = np.zeros(len(train_txt))
for tr, te in GroupKFold(n_splits=5).split(train_txt.clean, train_txt.y, groups):
    m = make_text_model().fit(train_txt.clean.iloc[tr], train_txt.y.iloc[tr])
    oof[te] = m.predict(train_txt.clean.iloc[te])
print(f"\n({groups.nunique()} distinct sentence templates)")
metrics['text_unseen_templates'] = report("Text model on UNSEEN templates (GroupKFold, realistic)", train_txt.y, oof)

# =====================================================================
# 3. SANITY CHECKS on realistic URLs
# =====================================================================
print("\n" + "=" * 70 + "\n3. SANITY CHECK - URL model on hand-picked URLs\n" + "=" * 70)
checks = [
    "https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox/FMfcgzQjgznkFzWtPgsxkCJgZfLcVNWS",
    "https://www.google.com/search?q=cara+bayar+cukai+lhdn+online&oq=cara+bayar&sourceid=chrome&ie=UTF-8",
    "https://shopee.com.my/Baju-Kurung-Moden-i.123456789.987654321?sp_atk=abc-123&xptdk=def",
    "https://www.maybank2u.com.my/home/m2u/common/login.do",
    "https://www.espn.com/cricket/",
    "https://kedaikopimesra.com.my/menu",
    "https://jtp-photography.com/worldpage/indexw.php?cost=0.001099&country=MY&zoneid=10491721",
    "https://www.bintv.cc/",
    "https://win88my-slot.com/",
    "https://mega888-download.online/",
    "https://nonton-bola-live.xyz/",
    "http://semakan-lhdn-gov.top",
    "http://bit.ly/kemaskini-akaun-2026",
    "https://maybank2u-secure-login.com/m2u/login.do",
    "http://103.21.44.9/cimb/login.php",
    "https://rnaybank2u.com/login",
]
Xc = build_X(checks)
pc = (rf_model.predict_proba(Xc) + xgb_model.predict_proba(Xc)) / 2
for u, p in zip(checks, pc):
    cat = URL_CLASSES[int(p[1:].argmax()) + 1]
    print(f"  risk {100 * (1 - p[0]):5.1f}%  likely={cat:9s} {u}")

# =====================================================================
# 4. SAVE
# =====================================================================
joblib.dump(rf_model, os.path.join(MODELS_DIR, 'rf_model.pkl'), compress=3)
joblib.dump(xgb_model, os.path.join(MODELS_DIR, 'xgb_model.pkl'), compress=3)
joblib.dump(text_model, os.path.join(MODELS_DIR, 'text_model.pkl'))
with open(os.path.join(MODELS_DIR, 'model_meta.json'), 'w') as fh:
    json.dump({'trained_at': datetime.now().isoformat(timespec='seconds'),
               'url_features': URL_FEATURE_NAMES,
               'url_classes': URL_CLASSES,
               'url_training_rows': len(url_df),
               'text_training_sentences': len(train_txt),
               'metrics': metrics}, fh, indent=2)
conn.close()
print(f"\nModels saved to {MODELS_DIR}: rf_model.pkl, xgb_model.pkl, text_model.pkl, model_meta.json")
