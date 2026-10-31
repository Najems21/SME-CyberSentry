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
    # --- BAHASA MALAYSIA: URGENCY & SECURITY ---
    ("akaun anda disekat", "Bahasa Malaysia", 0.85, "Urgency"),
    ("sila kemaskini segera", "Bahasa Malaysia", 0.80, "Urgency"),
    ("akaun anda dibekukan", "Bahasa Malaysia", 0.90, "Urgency"),
    ("tindakan merta", "Bahasa Malaysia", 0.75, "Urgency"),
    ("tindakan undang-undang akan diambil", "Bahasa Malaysia", 0.88, "Urgency"),
    ("pengesahan keselamatan diperlukan", "Bahasa Malaysia", 0.82, "Urgency"),
    ("log masuk segera", "Bahasa Malaysia", 0.78, "Urgency"),
    ("kemaskini butiran peribadi anda", "Bahasa Malaysia", 0.75, "Urgency"),
    ("akaun tamat tempoh", "Bahasa Malaysia", 0.80, "Urgency"),
    ("pembatalan perkhidmatan", "Bahasa Malaysia", 0.85, "Urgency"),
    ("sila sahkan identiti", "Bahasa Malaysia", 0.77, "Urgency"),
    ("kegagalan berbuat demikian", "Bahasa Malaysia", 0.81, "Urgency"),
    ("amaran keselamatan portal", "Bahasa Malaysia", 0.79, "Urgency"),

    # --- BAHASA MALAYSIA: FINANCIAL & FRAUD ---
    ("tahniah anda terpilih", "Bahasa Malaysia", 0.88, "Financial"),
    ("menang cabutan bertuah", "Bahasa Malaysia", 0.90, "Financial"),
    ("bantuan tunai e-madani", "Bahasa Malaysia", 0.95, "Financial"),
    ("bantuan kewangan diluluskan", "Bahasa Malaysia", 0.89, "Financial"),
    ("semakan lhdn bayaran balik", "Bahasa Malaysia", 0.92, "Financial"),
    ("tuntut hadiah rm", "Bahasa Malaysia", 0.91, "Financial"),
    ("akaun m2u anda digantung", "Bahasa Malaysia", 0.95, "Urgency"),
    ("cimb clicks kemaskini", "Bahasa Malaysia", 0.94, "Urgency"),
    ("pakej anda ditahan kastam", "Bahasa Malaysia", 0.87, "Financial"),
    ("tolong bayar kastam", "Bahasa Malaysia", 0.82, "Financial"),
    ("tebus mata ganjaran", "Bahasa Malaysia", 0.86, "Financial"),
    ("bank in ke akaun", "Bahasa Malaysia", 0.85, "Financial"),

    # --- MANGLISH: URGENCY & SECURITY ---
    ("pls update ur info", "Manglish", 0.82, "Urgency"),
    ("click dis link cepat", "Manglish", 0.85, "Urgency"),
    ("urgent boss parcel sangkut", "Manglish", 0.85, "Urgency"),
    ("u got parcel stuck dekat warehouse", "Manglish", 0.88, "Urgency"),
    ("pls verify your account", "Manglish", 0.84, "Urgency"),
    ("account suspended boss", "Manglish", 0.89, "Urgency"),
    ("click here to unlock", "Manglish", 0.86, "Urgency"),
    ("system flag ur account", "Manglish", 0.81, "Urgency"),
    ("verify akaun u skrg", "Manglish", 0.84, "Urgency"),
    
    # --- MANGLISH: FINANCIAL & FRAUD ---
    ("pls update ur bank info", "Manglish", 0.91, "Financial"),
    ("link untuk claim e-madani", "Manglish", 0.89, "Financial"),
    ("claim free credit", "Manglish", 0.88, "Financial"),
    ("lucky draw winner click link", "Manglish", 0.87, "Financial"),
    ("tng ewallet free claim", "Manglish", 0.93, "Financial"),
    ("bank in ur money", "Manglish", 0.83, "Financial"),
    ("jangan bagi tac dekat sesiapa", "Manglish", 0.65, "Financial")
]

cursor.executemany('''
INSERT OR IGNORE INTO THREAT_DICTIONARY (Keyword_Text, Language_Type, Risk_Weight, Category)
VALUES (?, ?, ?, ?)
''', sample_phrases)

conn.commit()
conn.close()
print("All 5 tables and expanded localized Threat Dictionary initialized successfully!")