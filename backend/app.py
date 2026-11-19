import json
import os
import sys
import time
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import (URL_FEATURE_NAMES, extract_url_features, is_trusted_domain,  # noqa: E402
                      parse_url, registered_domain, split_sentences)
from threat_rules import (CONTENT_CATEGORIES, INTEL_LABELS, INTEL_SCORES,  # noqa: E402
                          ThreatIntel, analyze_page, verify_tls)

app = Flask(__name__)
CORS(app)

BACKEND = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(os.path.dirname(BACKEND), 'database', 'cybersentry.db')
MODELS_DIR = os.path.join(BACKEND, 'models')

rf_model = joblib.load(os.path.join(MODELS_DIR, 'rf_model.pkl'))
xgb_model = joblib.load(os.path.join(MODELS_DIR, 'xgb_model.pkl'))
text_model = joblib.load(os.path.join(MODELS_DIR, 'text_model.pkl'))
rf_model.n_jobs = 1  # single-row predictions: thread start-up costs more than it saves
with open(os.path.join(MODELS_DIR, 'model_meta.json')) as _fh:
    URL_CLASSES = json.load(_fh).get('url_classes', ['legit', 'phishing'])
_vocab = text_model.named_steps['tfidf'].vocabulary_
_tokenize = text_model.named_steps['tfidf'].build_tokenizer()

intel = ThreatIntel()
_tls_pool = ThreadPoolExecutor(max_workers=4)

MAX_TEXT_CHARS = 5000            # Section 3.5.1.2: limit DOM text to first 5,000 characters
MIN_VOCAB_COVERAGE = 0.6         # skip sentences the text model has never seen words of
TRUSTED_CONTENT_CAP = 60.0       # trusted domains can reach "Medium Risk" from content, never "Danger"
KEYWORD_DAMPING = 0.75           # one dictionary hit alone should not exceed the default threshold

CATEGORY_LABELS = {'phishing': 'Phishing', 'gambling': 'Online Gambling', 'piracy': 'Illegal Streaming / Piracy'}

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
    'Gambling_Host_Words': "Gambling words in the domain name",
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


def calibrate_url_risk(raw):
    """
    The URL model is trained on a 50/50 mix, but on the real web legitimate
    sites vastly outnumber malicious ones. Measured on 2,000 unseen legitimate
    (Tranco) and 2,000 unseen phishing URLs:
        raw >= 50 : 10.3% of legit, 71.6% of phishing  -> mapped to 40 (Medium starts)
        raw >= 80 :  1.3% of legit, 49.6% of phishing  -> mapped to 70 (Danger starts)
    so the URL model alone rarely raises a false alarm; content, download and
    blocklist evidence push genuinely bad pages higher.
    """
    if raw <= 50:
        return raw * 0.8
    if raw <= 80:
        return 40 + (raw - 50)
    return 70 + (raw - 80) * 1.5


def score_url(url):
    """Returns (calibrated risk 0-100, most likely malicious category, features)."""
    feats = extract_url_features(url)
    X = pd.DataFrame([feats], columns=URL_FEATURE_NAMES)
    proba = (rf_model.predict_proba(X)[0] + xgb_model.predict_proba(X)[0]) / 2.0
    risk = calibrate_url_risk(float(1 - proba[0]) * 100)
    category = URL_CLASSES[int(proba[1:].argmax()) + 1] if len(proba) > 2 else 'phishing'
    return risk, category, feats


def score_text(text):
    """Score each sentence on the page; return the most suspicious ones."""
    scored = []
    candidates = []
    for s in split_sentences(text, max_chars=MAX_TEXT_CHARS):
        toks = _tokenize(s.lower())
        if len(toks) >= 4 and sum(t in _vocab for t in toks) / len(toks) >= MIN_VOCAB_COVERAGE:
            candidates.append(s)
    if candidates:
        probs = text_model.predict_proba([c.lower() for c in candidates])[:, 1] * 100
        scored = sorted(zip(candidates, probs), key=lambda x: -x[1])
    top = [{"sentence": s, "probability": round(float(p), 1)} for s, p in scored[:3] if p >= 50]
    return (float(scored[0][1]) if scored else 0.0), top, len(candidates)


def match_keywords(dictionary, url, text):
    """Phishing phrases (content categories such as Gambling are handled in threat_rules)."""
    combined = ' '.join((url + " " + text[:MAX_TEXT_CHARS]).lower().split())
    hits = []
    for item in dictionary:
        if item['Category'] in CONTENT_CATEGORIES:
            continue
        if item['Keyword_Text'].lower() in combined:
            hits.append({"keyword": item['Keyword_Text'], "weight": item['Risk_Weight'],
                         "category": item['Category'], "language": item['Language_Type']})
    p_safe = 1.0
    for h in hits:  # noisy-OR: several phrases compound, one alone stays moderate
        p_safe *= 1 - h['weight'] * KEYWORD_DAMPING
    return hits, (1 - p_safe) * 100


@app.route('/scan', methods=['POST'])
def scan_website():
    start_time = time.perf_counter()
    data = request.json or {}
    url = data.get('url', '') or ''
    dom_text = data.get('text', '') or ''
    signals = data.get('signals') or {}

    scheme, host, _, _ = parse_url(url)
    domain = host or url
    reg_domain = registered_domain(host)

    conn = get_db_connection()

    # USER_ALLOWLIST bypass (Use Case TC-04)
    if host and is_allowlisted(conn, host):
        conn.close()
        return jsonify({
            "status": "Safe", "allowlisted": True, "domain": domain, "category": "Allowlisted",
            "registered_domain": reg_domain, "risk_score": 0.0, "reasons": [],
            "latency_ms": round((time.perf_counter() - start_time) * 1000, 2),
            "detected_keywords": [], "suspicious_sentences": [], "url_flags": [], "features": {},
        })

    # Start the HTTPS certificate check in parallel (network round-trip)
    tls_future = _tls_pool.submit(verify_tls, host) if scheme == 'https' and host else None

    settings = conn.execute("SELECT Risk_Threshold FROM USER_SETTINGS WHERE Setting_ID = 1").fetchone()
    risk_threshold = settings['Risk_Threshold'] if settings else 70.0
    trusted = is_trusted_domain(host)
    rank = intel.popularity_rank(host)
    dictionary = get_threat_dictionary(conn)

    # --- 1. Reputation: public threat-intel blocklists ---
    intel_hit = None if trusted else intel.lookup(host)

    # --- 2. URL model ---
    url_raw, url_category, url_feats = score_url(url)
    url_score = url_raw
    if trusted:
        url_score = min(url_score, 5.0)
    elif rank and rank <= 10000:
        url_score *= 0.4      # very popular site: lexical red flags are far less meaningful
    elif rank and rank <= 100000:
        url_score *= 0.7

    # --- 3. Text model + phishing phrase dictionary ---
    text_ml_score, suspicious_sentences, n_sentences = score_text(dom_text)
    matched_keywords, keyword_score = match_keywords(dictionary, url, dom_text)
    text_score = max(text_ml_score, keyword_score)

    # --- 4. Behaviour / content / certificate checks ---
    tls = tls_future.result() if tls_future else None
    findings = analyze_page(url, dom_text, signals,
                            [d for d in dictionary if d['Category'] in CONTENT_CATEGORIES], tls, trusted)
    if intel_hit:
        findings.insert(0, {
            'category': INTEL_LABELS.get(intel_hit['category'], 'Malicious'),
            'score': INTEL_SCORES.get(intel_hit['category'], 90),
            'reason': f"Listed in public threat-intelligence feeds as {intel_hit['category']} "
                      f"({intel_hit['domain']}; sources: {', '.join(s.rsplit('.', 1)[0] for s in intel_hit['sources'][:3])})"})
    # A domain that merely *sounds* like gambling/streaming (jdsports.my, buletintv3.my)
    # while its actual page content shows no such evidence -> trust the content more.
    content_cats = {f['category'] for f in findings}
    if (not intel_hit and url_category in ('gambling', 'piracy') and len(dom_text) >= 200
            and not content_cats & {'Online Gambling', 'Illegal Streaming / Piracy'}):
        url_score *= 0.5
    rule_score = max((f['score'] for f in findings), default=0.0)

    # --- 5. Fusion ---
    note = ""
    if trusted:
        # Official site: the address is fine, but the page may still DISPLAY scam
        # content (e.g. a phishing email open in Gmail) -> at most a warning,
        # always below the user's Danger threshold.
        final_score = min(max(text_score, rule_score), TRUSTED_CONTENT_CAP, risk_threshold - 0.1)
        if final_score >= 40:
            note = (f"{reg_domain} is an official site, but this page shows scam-like content or downloads. "
                    "Do not click links or share details from it.")
    else:
        engines = [url_score, text_score, rule_score]
        final_score = max(engines)
        if sum(e >= 50 for e in engines) >= 2:
            final_score += 10  # independent engines agree -> more confident
    final_score = round(min(max(final_score, 0.0), 99.5), 1)

    if final_score >= risk_threshold:
        status = "Danger"
    elif final_score >= 40.0:
        status = "Medium Risk"
    else:
        status = "Safe"

    # Threat type: concrete evidence (blocklist, download, content, certificate)
    # beats the URL model's statistical guess.
    category = "None"
    if status != "Safe":
        evidence = [(f['score'], f['category']) for f in findings if f['score'] >= 40]
        if evidence:
            category = max(evidence)[1]
        else:
            candidates = [(text_score, 'Phishing (scam text)')]
            if not trusted:
                candidates.append((url_score, CATEGORY_LABELS.get(url_category, 'Phishing')))
            category = max(candidates)[1]

    flags = [] if trusted else url_flags(url_feats, host)
    reasons = [f['reason'] for f in sorted(findings, key=lambda f: -f['score'])]

    # Log scan into FORENSIC_SCAN_LOGS & EXTRACTED_ML_FEATURES
    cur = conn.cursor()
    cur.execute('''INSERT INTO FORENSIC_SCAN_LOGS (Scanned_URL, NLP_Keyword_Hits, ML_Risk_Score, Final_Status)
                   VALUES (?, ?, ?, ?)''', (url, len(matched_keywords), final_score, status))
    log_id = cur.lastrowid
    logged = dict(url_feats, URL_Model_Score=round(url_score, 2), Text_Model_Score=round(text_ml_score, 2),
                  Keyword_Score=round(keyword_score, 2), Rule_Score=rule_score,
                  NLP_Threat_Keywords=len(matched_keywords), Trusted_Domain=int(trusted),
                  Threat_Intel_Match=int(bool(intel_hit)), Popularity_Rank=rank or 0,
                  TLS_Valid=-1 if not tls or not tls.get('checked') else int(tls.get('valid', False)),
                  Downloads_Detected=len(signals.get('downloads', [])))
    cur.executemany('INSERT INTO EXTRACTED_ML_FEATURES (Log_ID, Feature_Name, Feature_Value) VALUES (?, ?, ?)',
                    [(log_id, k, float(v)) for k, v in logged.items()])
    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "category": category,
        "allowlisted": False,
        "trusted_domain": trusted,
        "popularity_rank": rank,
        "note": note,
        "domain": domain,
        "registered_domain": reg_domain,
        "risk_score": final_score,
        "url_score": round(url_score, 1),
        "url_category": CATEGORY_LABELS.get(url_category, url_category),
        "text_score": round(text_score, 1),
        "rule_score": rule_score,
        "threshold": risk_threshold,
        "latency_ms": round((time.perf_counter() - start_time) * 1000, 2),
        "https": {"scheme": scheme, **(tls or {})},
        "threat_intel": intel_hit,
        "reasons": reasons,
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
