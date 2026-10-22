from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import time
import joblib
import pandas as pd
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'cybersentry.db')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')

rf_model = joblib.load(os.path.join(MODELS_DIR, 'rf_model.pkl'))
xgb_model = joblib.load(os.path.join(MODELS_DIR, 'xgb_model.pkl'))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_threat_dictionary():
    conn = get_db_connection()
    rows = conn.execute("SELECT Keyword_Text, Risk_Weight, Category, Language_Type FROM THREAT_DICTIONARY").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def extract_features(url_str, text_str=""):
    url_length = len(url_str)
    num_dots = url_str.count('.')
    num_dash = url_str.count('-')
    num_special = url_str.count('@') + url_str.count('?') + url_str.count('%')
    
    try:
        parsed = urlparse(url_str if url_str.startswith('http') else 'http://' + url_str)
        hostname = parsed.netloc.lower()
        https_in_host = 1 if 'https' in hostname else 0
    except Exception:
        hostname = ""
        https_in_host = 0

    # Limit DOM text to first 5,000 characters as specified in Section 3.5.1.2
    combined = (url_str + " " + text_str[:5000]).lower()
    threat_dict = get_threat_dictionary()
    
    matched_keywords = []
    for item in threat_dict:
        if item['Keyword_Text'].lower() in combined:
            matched_keywords.append({
                "keyword": item['Keyword_Text'],
                "weight": item['Risk_Weight'],
                "category": item['Category'],
                "language": item['Language_Type']
            })
            
    feature_names = ['URL_Length', 'NumDots', 'NumDash', 'NumSpecialChars', 'HttpsInHostname', 'NLP_Threat_Keywords']
    feature_values = [url_length, num_dots, num_dash, num_special, https_in_host, len(matched_keywords)]
    df_features = pd.DataFrame([feature_values], columns=feature_names)
    
    feature_dict = dict(zip(feature_names, feature_values))
    return df_features, feature_dict, matched_keywords, hostname

@app.route('/scan', methods=['POST'])
def scan_website():
    start_time = time.perf_counter()
    data = request.json or {}
    url = data.get('url', '')
    dom_text = data.get('text', '')

    # Parse domain to check against USER_ALLOWLIST
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower()
    except Exception:
        domain = url

    conn = get_db_connection()
    
    # Check if domain is in USER_ALLOWLIST (Use Case TC-04)
    allowlisted = conn.execute("SELECT * FROM USER_ALLOWLIST WHERE Domain_Name = ?", (domain,)).fetchone()
    if allowlisted:
        conn.close()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return jsonify({
            "status": "Safe",
            "allowlisted": True,
            "domain": domain,
            "risk_score": 0.0,
            "latency_ms": latency_ms,
            "detected_keywords": [],
            "features": {
                "URL_Length": len(url),
                "NumDots": url.count('.'),
                "NumDash": url.count('-'),
                "HttpsInHostname": 0
            }
        })

    # Fetch user configured Risk_Threshold
    settings = conn.execute("SELECT Risk_Threshold FROM USER_SETTINGS WHERE Setting_ID = 1").fetchone()
    risk_threshold = settings['Risk_Threshold'] if settings else 70.0

    # Extract features & run hybrid ML/NLP engine
    features_df, feature_dict, matched_keywords, _ = extract_features(url, dom_text)

    rf_prob = float(rf_model.predict_proba(features_df)[0][1]) * 100
    xgb_prob = float(xgb_model.predict_proba(features_df)[0][1]) * 100
    ml_score = (rf_prob + xgb_prob) / 2.0

    # Combine ML probability with localized NLP keyword weights
    nlp_boost = sum(item['weight'] * 35 for item in matched_keywords)
    final_score = round(min(max(ml_score, nlp_boost), 99.5), 1)

    if final_score >= risk_threshold:
        status = "Danger"
    elif final_score >= 40.0:
        status = "Medium Risk"
    else:
        status = "Safe"

    # Log scan into FORENSIC_SCAN_LOGS & EXTRACTED_ML_FEATURES
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO FORENSIC_SCAN_LOGS (Scanned_URL, NLP_Keyword_Hits, ML_Risk_Score, Final_Status)
        VALUES (?, ?, ?, ?)
    ''', (url, len(matched_keywords), final_score, status))
    log_id = cur.lastrowid

    for fname, fval in feature_dict.items():
        cur.execute('''
            INSERT INTO EXTRACTED_ML_FEATURES (Log_ID, Feature_Name, Feature_Value)
            VALUES (?, ?, ?)
        ''', (log_id, fname, float(fval)))

    conn.commit()
    conn.close()

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return jsonify({
        "status": status,
        "allowlisted": False,
        "domain": domain,
        "risk_score": final_score,
        "threshold": risk_threshold,
        "latency_ms": latency_ms,
        "detected_keywords": matched_keywords,
        "features": feature_dict
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