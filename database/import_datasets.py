"""
Loads every CSV in backend/dataset/ into cybersentry.db and updates the
Threat Dictionary with data-driven phrases.

    python database/init_db.py          # schema (run once / safe to re-run)
    python database/import_datasets.py  # this script (re-run after CSV changes)

Tables filled:
    TRAINING_DATASET  <- train_data.csv, test_data.csv, emails_cleaned.csv
    URL_DATASET       <- url_dataset.csv (built by backend/build_url_dataset.py)
    THREAT_DICTIONARY <- phrases mined from the phishing sentences

How dictionary weights are computed:
    Each candidate phrase is matched against every training sentence.
        Risk_Weight = precision = (#phishing sentences containing it) / (#sentences containing it)
    capped at 0.95. A phrase is only accepted when it appears at least
    MIN_SUPPORT times and its precision is >= MIN_PRECISION, so phrases that
    also show up in legitimate messages (e.g. "untuk keselamatan akaun anda")
    are rejected automatically.
"""
import os
import re
import sqlite3

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, 'database', 'cybersentry.db')
DATASET_DIR = os.path.join(ROOT, 'backend', 'dataset')

# CSV -> split. Any other CSV with text,label columns is imported as 'train'.
EMAIL_SPLITS = {'train_data.csv': 'train', 'test_data.csv': 'test', 'emails_cleaned.csv': 'train'}
URL_CSV = 'url_dataset.csv'

MIN_SUPPORT = 15
MIN_PRECISION = 0.85
MAX_WEIGHT = 0.95

# Candidate phrases (expert-curated from the phishing templates); their weights
# come from the data, not from this list.
CANDIDATES = [
    # (phrase, category)
    ("akan ditamatkan dalam masa 24 jam", "Urgency"),
    ("sila log masuk di", "Credential"),
    ("tunggakan cukai", "Financial"),
    ("sila bayar segera", "Financial"),
    ("semak status kelayakan", "Financial"),
    ("di pautan rasmi ini", "Impersonation"),
    ("percubaan log masuk dikesan", "Credential"),
    ("jika bukan anda, klik", "Credential"),
    ("tindakan segera diperlukan", "Urgency"),
    ("anda telah disekat", "Urgency"),
    ("sila sahkan identiti", "Credential"),
    ("gagal diperbaharui", "Financial"),
    ("kemaskini kad kredit anda", "Financial"),
    ("penghantaran bungkusan anda gagal", "Delivery"),
    ("kos penghantaran semula", "Delivery"),
    ("anda terpilih memenangi hadiah", "Reward"),
    ("akaun anda berisiko digodam", "Urgency"),
    ("amaran keselamatan dikesan", "Urgency"),
    ("akaun anda akan disekat", "Urgency"),
    ("elak sekatan", "Urgency"),
    ("elakkan sekatan", "Urgency"),
    ("akses akaun anda akan ditamatkan", "Urgency"),
    ("pengesahan akaun diperlukan segera", "Credential"),
    ("makluman keselamatan penting daripada sistem", "Impersonation"),
    ("login segera", "Credential"),
    ("tekan link", "Urgency"),
    ("sila klik pautan di bawah", "Urgency"),
    ("kemas kini kata laluan sekarang", "Credential"),
    ("sahkan maklumat peribadi anda", "Credential"),
    # Negative controls: appear in both classes and SHOULD be rejected
    ("untuk keselamatan akaun anda", "Urgency"),
    ("dalam tempoh 24 jam", "Urgency"),
    ("sila simpan", "Urgency"),
]


def import_email_csvs(cur):
    cur.execute("DELETE FROM TRAINING_DATASET")
    total = 0
    for name in sorted(os.listdir(DATASET_DIR)):
        if not name.endswith('.csv') or name == URL_CSV:
            continue
        df = pd.read_csv(os.path.join(DATASET_DIR, name))
        if not {'text', 'label'} <= set(df.columns):
            print(f"  skipped {name}: no text/label columns")
            continue
        df = df.dropna(subset=['text', 'label'])
        df['label'] = df['label'].str.strip().str.lower()
        df = df[df['label'].isin(['phishing', 'legit'])]
        split = EMAIL_SPLITS.get(name, 'train')
        rows = [(t, l, name, split, 1 if re.search(r'https?://|www\.', t) else 0)
                for t, l in zip(df['text'].astype(str), df['label'])]
        cur.executemany('''INSERT INTO TRAINING_DATASET (Text, Label, Source_File, Split, Contains_URL)
                           VALUES (?, ?, ?, ?, ?)''', rows)
        print(f"  {name:22s} -> TRAINING_DATASET ({split}): {len(rows)} rows")
        total += len(rows)
    return total


def import_url_csv(cur):
    path = os.path.join(DATASET_DIR, URL_CSV)
    if not os.path.exists(path):
        print(f"  {URL_CSV} not found - run: python backend/build_url_dataset.py")
        return 0
    df = pd.read_csv(path)
    cur.execute("DELETE FROM URL_DATASET")
    cur.executemany("INSERT OR IGNORE INTO URL_DATASET (URL, Label, Source) VALUES (?, ?, ?)",
                    df[['url', 'label', 'source']].itertuples(index=False, name=None))
    print(f"  {URL_CSV:22s} -> URL_DATASET: {len(df)} rows")
    return len(df)


def mine_dictionary(cur):
    rows = cur.execute("SELECT LOWER(Text), Label FROM TRAINING_DATASET WHERE Split='train'").fetchall()
    texts = [r[0] for r in rows]
    labels = [r[1] == 'phishing' for r in rows]

    # Phrases from earlier imports are recomputed from scratch
    cur.execute("DELETE FROM THREAT_DICTIONARY WHERE Source LIKE 'Mined%'")
    accepted, rejected = [], []
    for phrase, category in CANDIDATES:
        hits = [lab for t, lab in zip(texts, labels) if phrase in t]
        support = len(hits)
        precision = sum(hits) / support if support else 0.0
        if support >= MIN_SUPPORT and precision >= MIN_PRECISION:
            weight = round(min(precision, MAX_WEIGHT), 2)
            cur.execute('''
                INSERT INTO THREAT_DICTIONARY (Keyword_Text, Language_Type, Risk_Weight, Category, Source, Support_Count)
                VALUES (?, 'Bahasa Malaysia', ?, ?, 'Mined (precision on training data)', ?)
                ON CONFLICT(Keyword_Text) DO UPDATE SET Support_Count = excluded.Support_Count''',
                        (phrase, weight, category, support))
            accepted.append((phrase, support, precision))
        else:
            rejected.append((phrase, support, precision))

    # Record evidence for manual phrases too (weights unchanged)
    for (kid, kw) in cur.execute("SELECT Keyword_ID, Keyword_Text FROM THREAT_DICTIONARY WHERE Source='Manual'").fetchall():
        n = sum(1 for t in texts if kw in t)
        cur.execute("UPDATE THREAT_DICTIONARY SET Support_Count=? WHERE Keyword_ID=?", (n, kid))

    print(f"\n  Dictionary mining: {len(accepted)} accepted, {len(rejected)} rejected")
    for p, s, pr in accepted:
        print(f"    + {p:48s} n={s:5d} precision={pr:.3f}")
    for p, s, pr in rejected:
        print(f"    - {p:48s} n={s:5d} precision={pr:.3f}  (rejected)")


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'TRAINING_DATASET', 'URL_DATASET'} <= tables:
        raise SystemExit("Run `python database/init_db.py` first.")
    print("Importing CSV files into cybersentry.db ...")
    import_email_csvs(cur)
    import_url_csv(cur)
    mine_dictionary(cur)
    conn.commit()
    n = cur.execute("SELECT COUNT(*) FROM THREAT_DICTIONARY").fetchone()[0]
    conn.close()
    print(f"\nDone. THREAT_DICTIONARY now has {n} phrases.")


if __name__ == '__main__':
    main()
