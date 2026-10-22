import os
import sqlite3
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# ---------------------------------------------------------
# 1. Load Local Threat Keywords from SQLite Database
# ---------------------------------------------------------
def get_threat_keywords():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'cybersentry.db')
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT Keyword_Text FROM THREAT_DICTIONARY")
        rows = cursor.fetchall()
        conn.close()
        return [r[0].lower() for r in rows]
    except Exception:
        # Fallback if DB is not found during initial setup
        return ["akaun anda disekat", "sila kemaskini segera", "pls update ur bank info"]

LOCAL_KEYWORDS = get_threat_keywords()

# ---------------------------------------------------------
# 2. Feature Extraction Function (Table 3.7)
# ---------------------------------------------------------
# Regex to automatically find a URL hidden inside the email text
url_pattern = re.compile(r'https?://\S+|www\.\S+')

def extract_features(email_text):
    email_text = str(email_text).lower()
    
    # Locate the URL in the text. If none exists, treat as empty string.
    match = url_pattern.search(email_text)
    url_str = match.group() if match else ""
    
    # 1. URL Length (if no URL found, length is 0)
    url_length = len(url_str)
    
    # 2. Number of Dots (.)
    num_dots = url_str.count('.')
    
    # 3. Number of Dashes (-)
    num_dash = url_str.count('-')
    
    # 4. Special Characters (@, ?, %)
    num_special_chars = url_str.count('@') + url_str.count('?') + url_str.count('%')
    
    # 5. HttpsInHostname (checks if "https" is maliciously placed in hostname)
    try:
        parsed = urlparse(url_str if url_str.startswith('http') else 'http://' + url_str)
        hostname = parsed.netloc
        https_in_hostname = 1 if 'https' in hostname else 0
    except Exception:
        https_in_hostname = 0
        
    # 6. NLP_Threat_Keywords (counts localized hits across the ENTIRE email text)
    nlp_hits = sum(1 for kw in LOCAL_KEYWORDS if kw in email_text)
    
    return [url_length, num_dots, num_dash, num_special_chars, https_in_hostname, nlp_hits]

# ---------------------------------------------------------
# 3. Load Pre-Split Datasets & Prepare Vectors
# ---------------------------------------------------------
dataset_dir = os.path.join(os.path.dirname(__file__), 'dataset')
train_csv_path = os.path.join(dataset_dir, 'train_data.csv')
test_csv_path = os.path.join(dataset_dir, 'test_data.csv')

print(f"Loading datasets:\n- {train_csv_path}\n- {test_csv_path}")
train_df = pd.read_csv(train_csv_path)
test_df = pd.read_csv(test_csv_path)

# Map string labels to binary (0 = Legitimate, 1 = Phishing)
label_mapping = {'legit': 0, 'phishing': 1}
train_df['label'] = train_df['label'].map(label_mapping).fillna(0)
test_df['label'] = test_df['label'].map(label_mapping).fillna(0)

print("Extracting features from Train data...")
X_train_raw = [extract_features(text) for text in train_df['text']]
y_train = train_df['label'].values

print("Extracting features from Test data...")
X_test_raw = [extract_features(text) for text in test_df['text']]
y_test = test_df['label'].values

feature_names = ['URL_Length', 'NumDots', 'NumDash', 'NumSpecialChars', 'HttpsInHostname', 'NLP_Threat_Keywords']
X_train = pd.DataFrame(X_train_raw, columns=feature_names)
X_test = pd.DataFrame(X_test_raw, columns=feature_names)

print(f"Training set: {len(X_train)} samples | Testing set: {len(X_test)} samples")

# ---------------------------------------------------------
# 4. Train Classifiers
# ---------------------------------------------------------
print("\n--- Training Random Forest Classifier ---")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

print("\n--- Training XGBoost Classifier ---")
xgb_model = XGBClassifier(n_estimators=100, learning_rate=0.1, eval_metric='logloss', random_state=42)
xgb_model.fit(X_train, y_train)

# ---------------------------------------------------------
# 5. Evaluation & Metrics
# ---------------------------------------------------------
print("\n========== EVALUATION RESULTS ==========")
for name, model in [("Random Forest", rf_model), ("XGBoost", xgb_model)]:
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"\nModel: {name}")
    print(f"Accuracy: {acc * 100:.2f}%")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))
    print("Classification Report:")
    print(classification_report(y_test, preds, target_names=["Legitimate (0)", "Phishing (1)"]))

# ---------------------------------------------------------
# 6. Save Models
# ---------------------------------------------------------
models_dir = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(models_dir, exist_ok=True)

rf_path = os.path.join(models_dir, 'rf_model.pkl')
xgb_path = os.path.join(models_dir, 'xgb_model.pkl')

joblib.dump(rf_model, rf_path)
joblib.dump(xgb_model, xgb_path)

print(f"\nModels successfully saved to:\n- {rf_path}\n- {xgb_path}")