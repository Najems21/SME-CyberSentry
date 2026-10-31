# 🛡️ SME-CyberSentry: Web-Based System for Localized Phishing Threats in Malaysian SMEs

**Final Year Project (CSP600 / CSP650)**  
**Institution:** Universiti Teknologi MARA (UiTM) – Faculty of Computer and Mathematical Sciences  
**Author:** Ammar Najmuddin Bin Ahmad Khairo  
**Supervisor:** Dr. Waheed Yasin Mohammed Abdul-Wahid  

---

## 📌 Project Overview

**SME-CyberSentry** is an intelligent, lightweight web browser extension designed to provide real-time, localized phishing protection for Small and Medium Enterprises (SMEs) in Malaysia. 

Conventional anti-phishing solutions rely heavily on static blacklists (which fail against zero-day attacks), suffer from English-centric dataset bias, or require resource-heavy cloud API queries that cause browsing lag. Adhering to the **Least Cybersecurity Control Implementation (LCCI)** framework, SME-CyberSentry operates entirely locally on the client's machine to safeguard user privacy and maintain zero browsing latency ($\sim 15\text{ ms}$ inference time).

### ✨ Key Features
* **Hybrid ML & NLP Detection Engine:** Combines structural URL lexical analysis with semantic Natural Language Processing (NLP) using an ensemble of **Random Forest** and **XGBoost** classifiers.
* **Localized Bahasa Malaysia & Manglish Threat Dictionary:** Detects intent-based social engineering attacks crafted in local Malaysian dialects (e.g., *"Akaun anda disekat"*, *"Sila kemaskini segera"*, *"Pls update ur bank info"*, *"U got parcel stuck dekat warehouse"*).
* **Real-Time Dynamic Risk Scoring:** Evaluates webpages on the fly and displays intuitive color-coded visual warnings (**Safe**, **Medium Risk**, **High Risk**) alongside feature breakdowns and keyword risk weights.
* **Forensic Scan Logs Portal:** Stores historical scan records and extracted ML features in a local SQLite database for post-incident review.
* **Trusted Domain Allowlist & Custom Thresholds:** Allows SME users to whitelist internal company portals to bypass scanning and conserve CPU cycles, as well as customize the ML risk threshold percentage.

---

## 🏗️ System Architecture & Project Structure

```text
SME-CyberSentry/
├── backend/
│   ├── dataset/
│   │   ├── emails_cleaned.csv    # Cleaned Malay phishing email dataset
│   │   ├── train_data.csv        # 80% Training dataset split
│   │   └── test_data.csv         # 20% Testing dataset split
│   ├── models/
│   │   ├── rf_model.pkl          # Trained Random Forest model binary
│   │   └── xgb_model.pkl         # Trained XGBoost model binary
│   ├── app.py                    # Local Flask API classification engine & test routes
│   └── train_model.py            # Feature extraction, calibration & model training script
├── database/
│   ├── cybersentry.db            # Local SQLite relational database
│   └── init_db.py                # Database schema & Threat Dictionary seeding script
├── extension/
│   ├── manifest.json             # Chrome Extension Manifest V3 configuration
│   ├── content.js                # DOM text (first 5,000 chars) & URL extraction script
│   ├── popup.html                # Extension UI (Scanner, Forensic Logs, Allowlist & Settings)
│   └── popup.js                  # Frontend logic & local engine API communication
├── .gitignore                    # Excludes venv/ and cache files from Git
├── requirements.txt              # Python package dependencies
└── README.md                     # Project documentation
```

---

## 🧠 Extracted Features (ML & NLP Pipeline)

The hybrid classification engine extracts 6 core features from every scanned webpage:

| Feature Name | Type | Description |
| :--- | :--- | :--- |
| `URL_Length` | Integer | Total character length of the domain and path (flags abnormally long URLs $>75$ chars). |
| `NumDots` | Integer | Count of periods (`.`) in the hostname to detect deceptive multi-level subdomains. |
| `NumDash` | Integer | Count of hyphens (`-`) in the hostname used to mimic legitimate brands (e.g., `maybank-update.com`). |
| `NumSpecialChars` | Integer | Count of obfuscation/redirect characters (`@`, `%`, multiple `?`). |
| `HttpsInHostname` | Binary ($0/1$) | Detects deceptive placement of `"https"` inside the domain name or insecure `http://` usage. |
| `NLP_Threat_Keywords` | Integer | Frequency of localized Bahasa Malaysia and Manglish threat phrases matched against `THREAT_DICTIONARY`. |

The final probability score is computed via an ensemble average of the Random Forest and XGBoost classifiers combined with localized NLP risk weights:

$$\text{ML\_Score} = \frac{P_{\text{RF}}(\text{Phishing}) + P_{\text{XGB}}(\text{Phishing})}{2}$$

---

## 🗄️ Database Schema (SQLite)

1. **`THREAT_DICTIONARY`**: Stores localized Bahasa Malaysia & Manglish scam phrases, language types, categories (`Urgency`, `Financial`), and risk weights.
2. **`FORENSIC_SCAN_LOGS`**: Logs every scanned URL, timestamp, NLP keyword hit count, ML risk score, and final status verdict.
3. **`EXTRACTED_ML_FEATURES`**: Stores individual lexical feature values linked via Foreign Key (`Log_ID`) to `FORENSIC_SCAN_LOGS`.
4. **`USER_ALLOWLIST`**: Stores trusted domain names that bypass scanning to save CPU resources.
5. **`USER_SETTINGS`**: Stores user-configured parameters such as `Risk_Threshold`.

---

## 🚀 Getting Started (Installation & Setup)

Follow these steps to set up and run the project on a new machine (PC or Laptop):

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/SME-CyberSentry.git
cd SME-CyberSentry
```

### 2. Create and Activate the Python Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate on Windows PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize the SQLite Database & Threat Dictionary
```bash
python database/init_db.py
```

### 5. Train the Calibrated ML Models (Optional if `.pkl` files are already present)
```bash
python backend/train_model.py
```

### 6. Start the Local Classification Engine
```bash
python backend/app.py
```
The local engine will start running at `http://127.0.0.1:5000`. Keep this terminal window open while using the browser extension.

### 7. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **Load unpacked** (top-left button) and select the `extension/` folder inside this project.
4. Pin **SME-CyberSentry** to your Chrome toolbar.

---

## 🧪 Running Unit Tests & Phishing Simulation

With `python backend/app.py` running, you can safely test high-risk detection without visiting live malicious sites by navigating to the built-in academic simulation route in Chrome:

```text
http://127.0.0.1:5000/test-phishing-simulation-https-login-account-verify-update-portal?redirect=https-verify.account-update.com&user=test@sme.my
```

* **Test Safe Browsing:** Visit any legitimate site (e.g., `https://www.google.com` or `https://uitm.edu.my`) and click **Scan Website** $\rightarrow$ Returns **✅ SAFE**.
* **Test Localized Phishing Detection:** Open the simulation URL above and click **Scan Website** $\rightarrow$ Returns **⚠️ HIGH RISK** with detailed feature analysis and Bahasa Malaysia/Manglish keyword weights.
* **Test Allowlist Bypass:** Click **+ Allowlist** on any domain and scan again $\rightarrow$ Immediately bypasses ML inference and returns **✅ SAFE (0%)**.