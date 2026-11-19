"""
Creates / migrates the SME-CyberSentry SQLite schema and seeds the
hand-curated part of the Threat Dictionary.

Safe to re-run: existing scan logs, allowlist and settings are preserved.
After this, run `python database/import_datasets.py` to load the CSV datasets
and mine additional data-driven threat phrases.
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cybersentry.db')


def create_schema(cursor):
    # 1. THREAT_DICTIONARY (Keyword_Text is UNIQUE so re-seeding never duplicates)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS THREAT_DICTIONARY (
        Keyword_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Keyword_Text TEXT UNIQUE NOT NULL,
        Language_Type TEXT NOT NULL,
        Risk_Weight REAL NOT NULL,
        Category TEXT NOT NULL,
        Source TEXT NOT NULL DEFAULT 'Manual',
        Support_Count INTEGER DEFAULT 0
    )''')

    # 2. FORENSIC_SCAN_LOGS
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS FORENSIC_SCAN_LOGS (
        Log_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Scanned_URL TEXT NOT NULL,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        NLP_Keyword_Hits INTEGER,
        ML_Risk_Score REAL,
        Final_Status TEXT
    )''')

    # 3. EXTRACTED_ML_FEATURES
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS EXTRACTED_ML_FEATURES (
        Feature_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Log_ID INTEGER,
        Feature_Name TEXT NOT NULL,
        Feature_Value REAL NOT NULL,
        FOREIGN KEY(Log_ID) REFERENCES FORENSIC_SCAN_LOGS(Log_ID)
    )''')

    # 4. USER_ALLOWLIST
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS USER_ALLOWLIST (
        Allowlist_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Domain_Name TEXT UNIQUE NOT NULL,
        Date_Added DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # 5. USER_SETTINGS
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS USER_SETTINGS (
        Setting_ID INTEGER PRIMARY KEY CHECK (Setting_ID = 1),
        Risk_Threshold REAL DEFAULT 70.0,
        Enable_Notifications INTEGER DEFAULT 1,
        Auto_Scan_Enabled INTEGER DEFAULT 1
    )''')
    cursor.execute('''
    INSERT OR IGNORE INTO USER_SETTINGS (Setting_ID, Risk_Threshold, Enable_Notifications, Auto_Scan_Enabled)
    VALUES (1, 70.0, 1, 1)''')

    # 6. TRAINING_DATASET - every row of the email/sentence CSV files
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS TRAINING_DATASET (
        Sample_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Text TEXT NOT NULL,
        Label TEXT NOT NULL CHECK (Label IN ('phishing', 'legit')),
        Source_File TEXT NOT NULL,
        Split TEXT NOT NULL CHECK (Split IN ('train', 'test')),
        Contains_URL INTEGER NOT NULL DEFAULT 0
    )''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_training_split ON TRAINING_DATASET(Split)')

    # 7. URL_DATASET - labelled URLs for the URL lexical model
    #    (derived data: rebuilt by import_datasets.py, so an old layout is simply replaced)
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(URL_DATASET)")]
    if cols and 'Category' not in cols:
        cursor.execute("DROP TABLE URL_DATASET")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS URL_DATASET (
        URL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        URL TEXT UNIQUE NOT NULL,
        Label TEXT NOT NULL CHECK (Label IN ('malicious', 'legit')),
        Category TEXT NOT NULL CHECK (Category IN ('legit', 'phishing', 'malware', 'scam', 'gambling', 'piracy')),
        Source TEXT NOT NULL
    )''')


def migrate_threat_dictionary(cursor):
    """Older databases had no UNIQUE constraint (duplicate rows) and no Source column."""
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(THREAT_DICTIONARY)")]
    sql = cursor.execute(
        "SELECT sql FROM sqlite_master WHERE name='THREAT_DICTIONARY'").fetchone()
    if not cols or ('Source' in cols and 'UNIQUE' in (sql[0] or '').upper()):
        return
    print("Migrating THREAT_DICTIONARY (removing duplicates, adding UNIQUE/Source columns)...")
    cursor.execute("ALTER TABLE THREAT_DICTIONARY RENAME TO THREAT_DICTIONARY_OLD")
    create_schema(cursor)
    cursor.execute('''
        INSERT OR IGNORE INTO THREAT_DICTIONARY (Keyword_Text, Language_Type, Risk_Weight, Category)
        SELECT LOWER(TRIM(Keyword_Text)), Language_Type, MAX(Risk_Weight), Category
        FROM THREAT_DICTIONARY_OLD GROUP BY LOWER(TRIM(Keyword_Text))''')
    cursor.execute("DROP TABLE THREAT_DICTIONARY_OLD")


# Hand-curated phrases (Source = 'Manual').
# Weights are expert estimates; data-driven phrases are added by import_datasets.py
MANUAL_PHRASES = [
    # --- Bahasa Malaysia ---
    ("akaun anda disekat", "Bahasa Malaysia", 0.85, "Urgency"),
    ("sila kemaskini segera", "Bahasa Malaysia", 0.80, "Urgency"),
    ("tindakan serta-merta", "Bahasa Malaysia", 0.75, "Urgency"),
    ("sila klik pautan ini", "Bahasa Malaysia", 0.72, "Urgency"),
    ("pengesahan keselamatan", "Bahasa Malaysia", 0.70, "Urgency"),
    ("akses portal saps anda akan ditamatkan", "Bahasa Malaysia", 0.88, "Urgency"),
    ("percubaan log masuk dikesan", "Bahasa Malaysia", 0.78, "Credential"),
    ("menang cabutan bertuah", "Bahasa Malaysia", 0.90, "Reward"),
    ("tuntut hadiah rm5000", "Bahasa Malaysia", 0.92, "Reward"),
    ("bank in ke akaun", "Bahasa Malaysia", 0.85, "Financial"),
    ("kemaskini kad kredit anda", "Bahasa Malaysia", 0.89, "Financial"),
    ("bayaran tertunggak lhdn", "Bahasa Malaysia", 0.86, "Financial"),
    ("masukkan nombor tac", "Bahasa Malaysia", 0.88, "Credential"),
    ("berikan kod otp", "Bahasa Malaysia", 0.88, "Credential"),
    ("sila masukkan kata laluan", "Bahasa Malaysia", 0.75, "Credential"),
    ("akaun anda telah dibekukan", "Bahasa Malaysia", 0.85, "Urgency"),
    ("waran tangkap", "Bahasa Malaysia", 0.85, "Impersonation"),
    ("pegawai polis bukit aman", "Bahasa Malaysia", 0.80, "Impersonation"),
    ("pindahkan wang ke akaun selamat", "Bahasa Malaysia", 0.95, "Financial"),
    # --- Manglish ---
    ("pls update ur bank info", "Manglish", 0.91, "Financial"),
    ("pls update ur info", "Manglish", 0.82, "Urgency"),
    ("click dis link cepat", "Manglish", 0.85, "Urgency"),
    ("u got parcel stuck dekat warehouse", "Manglish", 0.88, "Delivery"),
    ("u got parcel sekat", "Manglish", 0.85, "Delivery"),
    ("verify akaun u skrg", "Manglish", 0.84, "Urgency"),
    ("jangan bagi tac dekat sesiapa", "Manglish", 0.65, "Financial"),
    ("claim duit bantuan sekarang", "Manglish", 0.87, "Financial"),
    ("boss pls bank in", "Manglish", 0.80, "Financial"),
    ("cepat claim before expired", "Manglish", 0.85, "Reward"),
    # --- English (common in Malaysian SME inboxes) ---
    ("verify your account", "English", 0.70, "Credential"),
    ("your account has been suspended", "English", 0.80, "Urgency"),
    ("your account will be suspended", "English", 0.80, "Urgency"),
    ("confirm your identity", "English", 0.65, "Credential"),
    ("unusual sign-in activity", "English", 0.60, "Credential"),
    ("update your payment information", "English", 0.75, "Financial"),
    ("your password will expire", "English", 0.70, "Credential"),
    ("you have won", "English", 0.75, "Reward"),
    ("claim your prize", "English", 0.85, "Reward"),
    ("failed delivery attempt", "English", 0.70, "Delivery"),
    ("pay the redelivery fee", "English", 0.85, "Delivery"),
    ("act now or your account", "English", 0.85, "Urgency"),

    # ===== Content categories used by backend/threat_rules.py =====
    # Weight >= 0.85 = "strong" term (at least one is required before the
    # category is reported); weaker terms only add supporting evidence.
    # --- Online gambling / sports betting (illegal in Malaysia) ---
    *[(p, lang, 0.9, "Gambling") for p, lang in [
        ("judi online", "Bahasa Malaysia"), ("situs judi", "Bahasa Malaysia"), ("taruhan bola", "Bahasa Malaysia"),
        ("kredit percuma", "Bahasa Malaysia"), ("sabung ayam", "Bahasa Malaysia"), ("slot gacor", "Bahasa Malaysia"),
        ("judi bola", "Bahasa Malaysia"), ("free kredit", "Manglish"), ("slot online", "English"),
        ("online casino", "English"), ("casino online", "English"), ("live casino", "English"),
        ("sportsbook", "English"), ("sports betting", "English"), ("mega888", "English"), ("918kiss", "English"),
        ("pussy888", "English"), ("xe88", "English"), ("scr888", "English"), ("togel", "English"),
        ("baccarat", "English"), ("roulette", "English"), ("1xbet", "English"), ("sbobet", "English"),
        ("maxwin", "English"), ("free credit", "English"), ("place your bet", "English"), ("bet now", "English"),
        ("betting odds", "English"), ("slot machine", "English"), ("e-sports betting", "English")]],
    *[(p, lang, 0.5, "Gambling") for p, lang in [
        ("casino", "English"), ("jackpot", "English"), ("free spins", "English"), ("welcome bonus", "English"),
        ("deposit bonus", "English"), ("min deposit", "English"), ("minimum deposit", "English"),
        ("withdrawal", "English"), ("odds", "English"), ("handicap", "English"), ("poker", "English"),
        ("betting", "English"), ("4d result", "English"), ("keputusan 4d", "Bahasa Malaysia"),
        ("cuci duit", "Manglish"), ("deposit", "English"), ("rebate", "English"), ("bonus 100%", "English")]],
    # --- Illegal / unofficial streaming ---
    *[(p, lang, 0.9, "Illegal Streaming") for p, lang in [
        ("for free in hd", "English"), ("no sign-up", "English"), ("no sign up", "English"),
        ("no subscription", "English"), ("no registration", "English"), ("free live stream", "English"),
        ("watch free", "English"), ("stream free", "English"), ("24/7 for free", "English"),
        ("live stream free", "English"), ("tonton percuma", "Bahasa Malaysia"), ("nonton bola", "Bahasa Malaysia"),
        ("siaran langsung percuma", "Bahasa Malaysia"), ("free movies online", "English")]],
    *[(p, lang, 0.4, "Illegal Streaming") for p, lang in [
        ("watch live", "English"), ("live stream", "English"), ("live streaming", "English"), ("watch now", "English"),
        ("hd stream", "English"), ("siaran langsung", "Bahasa Malaysia"), ("just press play", "English")]],
    # --- Drive-by / automatic downloads ---
    ("download has started automatically", "English", 0.95, "Drive-by Download"),
    ("if the download does not start automatically", "English", 0.90, "Drive-by Download"),
    ("if your download does not start", "English", 0.85, "Drive-by Download"),
    ("download started", "English", 0.60, "Drive-by Download"),
    ("your download will begin", "English", 0.60, "Drive-by Download"),
    ("your file is ready to download", "English", 0.60, "Drive-by Download"),
    ("download will start shortly", "English", 0.60, "Drive-by Download"),
    ("muat turun anda akan bermula", "Bahasa Malaysia", 0.60, "Drive-by Download"),
    ("muat turun telah bermula", "Bahasa Malaysia", 0.80, "Drive-by Download"),
    # --- Fake security alerts / "click Allow" notification scams ---
    ("your computer is infected", "English", 0.95, "Fake Alert"),
    ("your pc is infected", "English", 0.95, "Fake Alert"),
    ("virus detected", "English", 0.80, "Fake Alert"),
    ("call microsoft support", "English", 0.95, "Fake Alert"),
    ("windows defender alert", "English", 0.90, "Fake Alert"),
    ("your computer has been blocked", "English", 0.90, "Fake Alert"),
    ("click allow if you are not a robot", "English", 0.95, "Fake Alert"),
    ("press allow to verify", "English", 0.90, "Fake Alert"),
    ("click allow to continue", "English", 0.85, "Fake Alert"),
    ("flash player update required", "English", 0.80, "Fake Alert"),
    ("komputer anda dijangkiti virus", "Bahasa Malaysia", 0.95, "Fake Alert"),
]


def seed_manual_phrases(cursor):
    # Remove the old misspelt seed that could never match ("tindakan merta")
    cursor.execute("DELETE FROM THREAT_DICTIONARY WHERE Keyword_Text = 'tindakan merta'")
    cursor.executemany('''
        INSERT INTO THREAT_DICTIONARY (Keyword_Text, Language_Type, Risk_Weight, Category, Source)
        VALUES (?, ?, ?, ?, 'Manual')
        ON CONFLICT(Keyword_Text) DO NOTHING''', MANUAL_PHRASES)


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    create_schema(cur)
    migrate_threat_dictionary(cur)
    seed_manual_phrases(cur)
    conn.commit()
    n = cur.execute("SELECT COUNT(*) FROM THREAT_DICTIONARY").fetchone()[0]
    conn.close()
    print(f"Schema ready (7 tables). THREAT_DICTIONARY has {n} phrases.")
    print("Next: python database/import_datasets.py")


if __name__ == '__main__':
    main()
