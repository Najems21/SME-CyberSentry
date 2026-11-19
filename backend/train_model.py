"""
Trains the SME-CyberSentry hybrid engine from the data stored in cybersentry.db.

    python database/init_db.py
    python database/import_datasets.py
    python backend/train_model.py

Two independent models are trained, each on the signal it can actually learn:

1. URL model  (Random Forest + XGBoost ensemble)  -> models/rf_model.pkl, xgb_model.pkl
   Trained on URL_DATASET using hostname-based lexical features
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
from features import URL_FEATURE_NAMES, extract_url_features, registered_domain, parse_url, strip_urls  # noqa: E402

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
# 1. URL MODEL
# =====================================================================
print("=" * 70 + "\n1. URL MODEL (Random Forest + XGBoost)\n" + "=" * 70)
url_df = pd.read_sql("SELECT URL, Label FROM URL_DATASET", conn)
if url_df.empty:
    raise SystemExit("URL_DATASET is empty - run build_url_dataset.py and import_datasets.py first.")
X_url = pd.DataFrame([extract_url_features(u) for u in url_df.URL], columns=URL_FEATURE_NAMES)
y_url = (url_df.Label == 'phishing').astype(int).values
groups = [registered_domain(parse_url(u)[1]) for u in url_df.URL]

tr_idx, te_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(X_url, y_url, groups))
X_tr, X_te, y_tr, y_te = X_url.iloc[tr_idx], X_url.iloc[te_idx], y_url[tr_idx], y_url[te_idx]
print(f"Train: {len(X_tr)} URLs | Test: {len(X_te)} URLs (test domains unseen in training)")

rf_model = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight='balanced',
                                  random_state=42, n_jobs=-1)
xgb_model = XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.08, subsample=0.9,
                          colsample_bytree=0.9, eval_metric='logloss', random_state=42)
rf_model.fit(X_tr, y_tr)
xgb_model.fit(X_tr, y_tr)

metrics['url_rf'] = report("URL Random Forest", y_te, rf_model.predict(X_te))
metrics['url_xgb'] = report("URL XGBoost", y_te, xgb_model.predict(X_te))
ens = (rf_model.predict_proba(X_te)[:, 1] + xgb_model.predict_proba(X_te)[:, 1]) / 2
metrics['url_ensemble'] = report("URL Ensemble (average)", y_te, (ens >= 0.5).astype(int))

imp = pd.Series(rf_model.feature_importances_, index=URL_FEATURE_NAMES).sort_values(ascending=False)
print("Random Forest feature importance:\n" + imp.round(4).to_string())

# Refit on all data for deployment
rf_model.fit(X_url, y_url)
xgb_model.fit(X_url, y_url)

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
    "https://kedaikopimesra.com.my/menu",
    "http://semakan-lhdn-gov.top",
    "http://bit.ly/kemaskini-akaun-2026",
    "https://maybank2u-secure-login.com/m2u/login.do",
    "http://www.maybank2u.com.my.verify-acc.xyz/login.php",
    "http://103.21.44.9/cimb/login.php",
    "https://rnaybank2u.com/login",
    "https://shopee-claim-hadiah.web.app/claim",
]
Xc = pd.DataFrame([extract_url_features(u) for u in checks], columns=URL_FEATURE_NAMES)
pc = (rf_model.predict_proba(Xc)[:, 1] + xgb_model.predict_proba(Xc)[:, 1]) / 2 * 100
for u, p in zip(checks, pc):
    print(f"  {p:5.1f}%  {u}")

# =====================================================================
# 4. SAVE
# =====================================================================
joblib.dump(rf_model, os.path.join(MODELS_DIR, 'rf_model.pkl'))
joblib.dump(xgb_model, os.path.join(MODELS_DIR, 'xgb_model.pkl'))
joblib.dump(text_model, os.path.join(MODELS_DIR, 'text_model.pkl'))
with open(os.path.join(MODELS_DIR, 'model_meta.json'), 'w') as fh:
    json.dump({'trained_at': datetime.now().isoformat(timespec='seconds'),
               'url_features': URL_FEATURE_NAMES,
               'url_training_rows': len(url_df),
               'text_training_sentences': len(train_txt),
               'metrics': metrics}, fh, indent=2)
conn.close()
print(f"\nModels saved to {MODELS_DIR}: rf_model.pkl, xgb_model.pkl, text_model.pkl, model_meta.json")
