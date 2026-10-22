import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'cybersentry.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 1. THREAT_DICTIONARY Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS THREAT_DICTIONARY (
    Keyword_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Keyword_Text TEXT UNIQUE NOT NULL,
    Language_Type TEXT NOT NULL,
    Risk_Weight REAL NOT NULL,
    Category TEXT NOT NULL
)
''')

# 2. FORENSIC_SCAN_LOGS Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS FORENSIC_SCAN_LOGS (
    Log_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Scanned_URL TEXT NOT NULL,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    NLP_Keyword_Hits INTEGER,
    ML_Risk_Score REAL,
    Final_Status TEXT
)
''')

# 3. EXTRACTED_ML_FEATURES Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS EXTRACTED_ML_FEATURES (
    Feature_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Log_ID INTEGER,
    Feature_Name TEXT NOT NULL,
    Feature_Value REAL NOT NULL,
    FOREIGN KEY(Log_ID) REFERENCES FORENSIC_SCAN_LOGS(Log_ID)
)
''')

# 4. USER_ALLOWLIST Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS USER_ALLOWLIST (
    Allowlist_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Domain_Name TEXT UNIQUE NOT NULL,
    Date_Added DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# 5. USER_SETTINGS Table
cursor.execute('''
CREATE TABLE IF NOT EXISTS USER_SETTINGS (
    Setting_ID INTEGER PRIMARY KEY CHECK (Setting_ID = 1),
    Risk_Threshold REAL DEFAULT 70.0,
    Enable_Notifications INTEGER DEFAULT 1,
    Auto_Scan_Enabled INTEGER DEFAULT 1
)
''')

# Insert default settings row
cursor.execute('''
INSERT OR IGNORE INTO USER_SETTINGS (Setting_ID, Risk_Threshold, Enable_Notifications, Auto_Scan_Enabled)
VALUES (1, 70.0, 1, 1)
''')

# Seed comprehensive Bahasa Malaysia & Manglish threat phrases
sample_phrases = [
    ("akaun anda disekat", "Bahasa Malaysia", 0.85, "Urgency"),
    ("sila kemaskini segera", "Bahasa Malaysia", 0.80, "Urgency"),
    ("tindakan merta", "Bahasa Malaysia", 0.75, "Urgency"),
    ("sila klik pautan ini", "Bahasa Malaysia", 0.72, "Urgency"),
    ("pengesahan keselamatan", "Bahasa Malaysia", 0.70, "Urgency"),
    ("akses portal saps anda akan ditamatkan", "Bahasa Malaysia", 0.88, "Urgency"),
    ("percubaan log masuk dikesan", "Bahasa Malaysia", 0.78, "Urgency"),
    ("menang cabutan bertuah", "Bahasa Malaysia", 0.90, "Financial"),
    ("tuntut hadiah rm5000", "Bahasa Malaysia", 0.92, "Financial"),
    ("bank in ke akaun", "Bahasa Malaysia", 0.85, "Financial"),
    ("kemaskini kad kredit anda", "Bahasa Malaysia", 0.89, "Financial"),
    ("bayaran tertunggak lhdn", "Bahasa Malaysia", 0.86, "Financial"),
    ("pls update ur bank info", "Manglish", 0.91, "Financial"),
    ("pls update ur info", "Manglish", 0.82, "Urgency"),
    ("click dis link cepat", "Manglish", 0.85, "Urgency"),
    ("u got parcel stuck dekat warehouse", "Manglish", 0.88, "Urgency"),
    ("u got parcel sekat", "Manglish", 0.85, "Urgency"),
    ("verify akaun u skrg", "Manglish", 0.84, "Urgency"),
    ("jangan bagi tac dekat sesiapa", "Manglish", 0.65, "Financial"),
    ("claim duit bantuan sekarang", "Manglish", 0.87, "Financial")
]

cursor.executemany('''
INSERT OR IGNORE INTO THREAT_DICTIONARY (Keyword_Text, Language_Type, Risk_Weight, Category)
VALUES (?, ?, ?, ?)
''', sample_phrases)

conn.commit()
conn.close()
print("All 5 tables and expanded localized Threat Dictionary initialized successfully!")