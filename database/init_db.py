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
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS URL_DATASET (
        URL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        URL TEXT UNIQUE NOT NULL,
        Label TEXT NOT NULL CHECK (Label IN ('phishing', 'legit')),
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
