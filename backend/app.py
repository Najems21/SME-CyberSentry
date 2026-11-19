import os
import sys
import time
import sqlite3

import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import (URL_FEATURE_NAMES, extract_url_features, is_trusted_domain,  # noqa: E402
                      parse_url, registered_domain, split_sentences)

app = Flask(__name__)
CORS(app)

BACKEND = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(os.path.dirname(BACKEND), 'database', 'cybersentry.db')
MODELS_DIR = os.path.join(BACKEND, 'models')

rf_model = joblib.load(os.path.join(MODELS_DIR, 'rf_model.pkl'))
xgb_model = joblib.load(os.path.join(MODELS_DIR, 'xgb_model.pkl'))
text_model = joblib.load(os.path.join(MODELS_DIR, 'text_model.pkl'))
rf_model.n_jobs = 1  # single-row predictions: thread start-up costs more than it saves
_vocab = text_model.named_steps['tfidf'].vocabulary_
_tokenize = text_model.named_steps['tfidf'].build_tokenizer()

MAX_TEXT_CHARS = 5000            # Section 3.5.1.2: limit DOM text to first 5,000 characters
MIN_VOCAB_COVERAGE = 0.6         # skip sentences the text model has never seen words of
TRUSTED_CONTENT_CAP = 60.0       # trusted domains can reach "Medium Risk" from content, never "Danger"
KEYWORD_DAMPING = 0.75           # one dictionary hit alone should not exceed the default threshold

FLAG_TEXT = {
    'Is_IP_Host': "Hostname is a raw IP address",
    'Has_At_Symbol': "'@' in the URL hides the real destination",
    'Uses_HTTP': "Connection is not encrypted (HTTP)",
    'Suspicious_TLD': "High-risk domain ending",
    'Is_URL_Shortener': "URL shortener hides the real destination",
    'Free_Hosting': "Hosted on a free website builder",
    'Brand_Impersonation': "Brand name used on a domain the brand does not own",
    'Brand_Lookalike': "Look-alike of an official brand domain (typosquat)",
    'Phishy_Host_Words': "Hostname contains phishing words (login / verify / semakan...)",
    'Is_Punycode': "Punycode / homograph domain",
    'Brand_In_Path': "Brand name in the path of an unrelated website",
}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_threat_dictionary(conn):
    rows = conn.execute("SELECT Keyword_Text, Risk_Weight, Category, Language_Type FROM THREAT_DICTIONARY").fetchall()
    return [dict(r) for r in rows]


def is_allowlisted(conn, host):
    """Allowlisting 'company.com.my' also covers 'mail.company.com.my'."""
    candidates = {host}
    parts = host.split('.')
    for i in range(1, len(parts) - 1):
        candidates.add('.'.join(parts[i:]))
    q = "SELECT 1 FROM USER_ALLOWLIST WHERE Domain_Name IN (%s) LIMIT 1" % ','.join('?' * len(candidates))
    return conn.execute(q, tuple(candidates)).fetchone() is not None


def url_flags(feats, host):
    flags = [txt for name, txt in FLAG_TEXT.items() if feats.get(name)]
    if feats.get('Suspicious_TLD'):
        flags[flags.index(FLAG_TEXT['Suspicious_TLD'])] += f" (.{host.rsplit('.', 1)[-1]})"
    if feats['Num_Subdomains'] >= 3:
        flags.append(f"Many subdomain levels ({feats['Num_Subdomains']})")
    if feats['Hostname_Hyphens'] >= 2:
        flags.append(f"Multiple hyphens in hostname ({feats['Hostname_Hyphens']})")
    if feats['Suspicious_Path'] >= 2:
        flags.append("Suspicious path (login kit / .php / verify)")
    return flags


def score_url(url):
    feats = extract_url_features(url)
    X = pd.DataFrame([feats], columns=URL_FEATURE_NAMES)
    prob = (rf_model.predict_proba(X)[0][1] + xgb_model.predict_proba(X)[0][1]) / 2.0
    return float(prob) * 100, feats


def score_text(text):
    """Score each sentence on the page; return the most suspicious ones."""
    scored = []
    sentences = split_sentences(text, max_chars=MAX_TEXT_CHARS)
    candidates = []
    for s in sentences:
        toks = [t for t in _tokenize(s.lower())]
        if len(toks) >= 4 and sum(t in _vocab for t in toks) / len(toks) >= MIN_VOCAB_COVERAGE:
            candidates.append(s)
    if candidates:
        probs = text_model.predict_proba([c.lower() for c in candidates])[:, 1] * 100
        scored = sorted(zip(candidates, probs), key=lambda x: -x[1])
    top = [{"sentence": s, "probability": round(float(p), 1)} for s, p in scored[:3] if p >= 50]
    return (float(scored[0][1]) if scored else 0.0), top, len(candidates)


def match_keywords(conn, url, text):
    combined = (url + " " + text[:MAX_TEXT_CHARS]).lower()
    combined = ' '.join(combined.split())
    hits = []
    for item in get_threat_dictionary(conn):
        if item['Keyword_Text'].lower() in combined:
            hits.append({"keyword": item['Keyword_Text'], "weight": item['Risk_Weight'],
                         "category": item['Category'], "language": item['Language_Type']})
    # Noisy-OR: several independent phrases compound, one phrase alone stays moderate
    p_safe = 1.0
    for h in hits:
        p_safe *= 1 - h['weight'] * KEYWORD_DAMPING
    return hits, (1 - p_safe) * 100


@app.route('/scan', methods=['POST'])
def scan_website():
    start_time = time.perf_counter()
    data = request.json or {}
    url = data.get('url', '') or ''
    dom_text = data.get('text', '') or ''

    _, host, _, _ = parse_url(url)
    domain = host or url
    reg_domain = registered_domain(host)

    conn = get_db_connection()

    # USER_ALLOWLIST bypass (Use Case TC-04)
    if host and is_allowlisted(conn, host):
        conn.close()
        return jsonify({
            "status": "Safe", "allowlisted": True, "domain": domain,
            "registered_domain": reg_domain, "risk_score": 0.0,
            "latency_ms": round((time.perf_counter() - start_time) * 1000, 2),
            "detected_keywords": [], "suspicious_sentences": [], "url_flags": [], "features": {},
        })

    settings = conn.execute("SELECT Risk_Threshold FROM USER_SETTINGS WHERE Setting_ID = 1").fetchone()
    risk_threshold = settings['Risk_Threshold'] if settings else 70.0

    trusted = is_trusted_domain(host)

    # --- 1. URL model (RF + XGB on hostname-structure features) ---
    url_score, url_feats = score_url(url)
    if trusted:
        url_score = min(url_score, 5.0)

    # --- 2. Text model + localized threat dictionary ---
    text_ml_score, suspicious_sentences, n_sentences = score_text(dom_text)
    matched_keywords, keyword_score = match_keywords(conn, url, dom_text)
    text_score = max(text_ml_score, keyword_score)

    # --- 3. Fusion ---
    note = ""
    if trusted:
        # Official site: the address is fine, but the page may still DISPLAY scam
        # content (e.g. a phishing email open in Gmail) -> at most a warning,
        # always below the user's Danger threshold.
        final_score = min(text_score, TRUSTED_CONTENT_CAP, risk_threshold - 0.1)
        if text_score >= 40:
            note = (f"{reg_domain} is an official site, but this page displays scam-like content. "
                    "Do not click links or share details from it.")
    else:
        final_score = max(url_score, text_score)
        if url_score >= 50 and text_score >= 50:
            final_score += 10  # both engines agree -> more confident
    final_score = round(min(max(final_score, 0.0), 99.5), 1)

    if final_score >= risk_threshold:
        status = "Danger"
    elif final_score >= 40.0:
        status = "Medium Risk"
    else:
        status = "Safe"

    flags = [] if trusted else url_flags(url_feats, host)

    # Log scan into FORENSIC_SCAN_LOGS & EXTRACTED_ML_FEATURES
    cur = conn.cursor()
    cur.execute('''INSERT INTO FORENSIC_SCAN_LOGS (Scanned_URL, NLP_Keyword_Hits, ML_Risk_Score, Final_Status)
                   VALUES (?, ?, ?, ?)''', (url, len(matched_keywords), final_score, status))
    log_id = cur.lastrowid
    logged = dict(url_feats, URL_Model_Score=round(url_score, 2), Text_Model_Score=round(text_ml_score, 2),
                  Keyword_Score=round(keyword_score, 2), NLP_Threat_Keywords=len(matched_keywords),
                  Trusted_Domain=int(trusted))
    cur.executemany('INSERT INTO EXTRACTED_ML_FEATURES (Log_ID, Feature_Name, Feature_Value) VALUES (?, ?, ?)',
                    [(log_id, k, float(v)) for k, v in logged.items()])
    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "allowlisted": False,
        "trusted_domain": trusted,
        "note": note,
        "domain": domain,
        "registered_domain": reg_domain,
        "risk_score": final_score,
        "url_score": round(url_score, 1),
        "text_score": round(text_score, 1),
        "threshold": risk_threshold,
        "latency_ms": round((time.perf_counter() - start_time) * 1000, 2),
        "url_flags": flags,
        "detected_keywords": matched_keywords,
        "suspicious_sentences": suspicious_sentences,
        "sentences_analyzed": n_sentences,
        "features": url_feats,
    })


@app.route('/logs', methods=['GET'])
def get_logs():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM FORENSIC_SCAN_LOGS ORDER BY Log_ID DESC LIMIT 15").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/allowlist', methods=['GET', 'POST', 'DELETE'])
def manage_allowlist():
    conn = get_db_connection()
    if request.method == 'POST':
        domain = (request.json or {}).get('domain', '').lower().strip()
        if domain:
            conn.execute("INSERT OR IGNORE INTO USER_ALLOWLIST (Domain_Name) VALUES (?)", (domain,))
            conn.commit()
    elif request.method == 'DELETE':
        domain = (request.json or {}).get('domain', '').lower().strip()
        conn.execute("DELETE FROM USER_ALLOWLIST WHERE Domain_Name = ?", (domain,))
        conn.commit()

    rows = conn.execute("SELECT * FROM USER_ALLOWLIST ORDER BY Date_Added DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/settings', methods=['GET', 'POST'])
def manage_settings():
    conn = get_db_connection()
    if request.method == 'POST':
        threshold = float((request.json or {}).get('risk_threshold', 70.0))
        conn.execute("UPDATE USER_SETTINGS SET Risk_Threshold = ? WHERE Setting_ID = 1", (threshold,))
        conn.commit()
    row = conn.execute("SELECT * FROM USER_SETTINGS WHERE Setting_ID = 1").fetchone()
    conn.close()
    return jsonify(dict(row))


if __name__ == '__main__':
    app.run(port=5000, debug=True)
