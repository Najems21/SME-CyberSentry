"""
Downloads PUBLIC threat-intelligence feeds and builds:

  1. database/threat_intel.db
        THREAT_INTEL_DOMAINS (Domain, Category, Sources)  ~ millions of known-bad hostnames
        POPULAR_DOMAINS      (Domain, Rank)               Tranco top-100k (popularity)
     Used at scan time for an instant, offline blocklist lookup.

  2. backend/dataset/url_dataset_public.csv
        A balanced, labelled URL training sample (url, label, category, source)
        drawn from the same feeds + Tranco legitimate domains.

Only public, openly published lists are used. Nothing is fetched from the
listed malicious sites themselves - every URL is handled as plain text.

    python backend/fetch_threat_intel.py                 # download + build
    python backend/fetch_threat_intel.py --feeds-dir DIR # reuse already-downloaded files

Sources (see SOURCES below for URLs and licences):
    OpenPhish Community, Phishing.Database, Phishing Army, HaGeZi DNS blocklists
    (Threat Intelligence Feeds, Gambling, Anti-Piracy), The Block List Project
    (gambling, piracy, scam, malware), Citizen Lab test list for Malaysia (GMB),
    Tranco top-1M list (legitimate / popular domains).
"""
import argparse
import csv
import io
import os
import random
import re
import sqlite3
import sys
import urllib.request
import zipfile

BACKEND = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BACKEND)
sys.path.insert(0, BACKEND)
from features import (FREE_HOSTING, TRUSTED_DOMAINS, URL_SHORTENERS,  # noqa: E402
                      parse_url, registered_domain)

INTEL_DB = os.path.join(ROOT, 'database', 'threat_intel.db')
OUT_CSV = os.path.join(BACKEND, 'dataset', 'url_dataset_public.csv')
DEFAULT_FEEDS_DIR = os.path.join(BACKEND, 'dataset', 'raw_feeds')

# name -> (url, kind, category, licence/terms page)
SOURCES = {
    'openphish.txt': ('https://openphish.com/feed.txt', 'urls', 'phishing',
                      'https://openphish.com/terms.html'),
    'phishdb_links.txt': ('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt',
                          'urls', 'phishing', 'https://github.com/mitchellkrogza/Phishing.Database'),
    'phishing_army.txt': ('https://phishing.army/download/phishing_army_blocklist.txt', 'domains', 'phishing',
                          'https://phishing.army/license/'),
    'hagezi_tif.txt': ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt',
                       'domains', 'malware', 'https://github.com/hagezi/dns-blocklists/blob/main/LICENSE'),
    'hagezi_gambling.txt': ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt',
                            'domains', 'gambling', 'https://github.com/hagezi/dns-blocklists/blob/main/LICENSE'),
    'hagezi_piracy.txt': ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti.piracy-onlydomains.txt',
                          'domains', 'piracy', 'https://github.com/hagezi/dns-blocklists/blob/main/LICENSE'),
    'blp_gambling.txt': ('https://blocklistproject.github.io/Lists/gambling.txt', 'domains', 'gambling',
                         'https://github.com/blocklistproject/Lists/blob/master/LICENSE'),
    'blp_piracy.txt': ('https://blocklistproject.github.io/Lists/piracy.txt', 'domains', 'piracy',
                       'https://github.com/blocklistproject/Lists/blob/master/LICENSE'),
    'blp_scam.txt': ('https://blocklistproject.github.io/Lists/scam.txt', 'domains', 'scam',
                     'https://github.com/blocklistproject/Lists/blob/master/LICENSE'),
    'blp_malware.txt': ('https://blocklistproject.github.io/Lists/malware.txt', 'domains', 'malware',
                        'https://github.com/blocklistproject/Lists/blob/master/LICENSE'),
    'citizenlab_my.csv': ('https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/my.csv',
                          'citizenlab', 'gambling', 'https://github.com/citizenlab/test-lists/blob/master/LICENSE'),
    'top-1m.csv': ('https://tranco-list.eu/top-1m.csv.zip', 'tranco', 'legit', 'https://tranco-list.eu/'),
    'top-1m-subdomains.csv': ('https://tranco-list.eu/top-1m-incl-subdomains.csv.zip', 'tranco', 'legit',
                              'https://tranco-list.eu/'),
}

# Generic paths given to a share of legitimate samples, so that "has a path",
# "/login" or "index.php" are not learned as phishing-only signals.
LEGIT_PATHS = ['/about', '/about-us', '/contact', '/news/{s}', '/blog/{s}', '/products/{s}', '/en/',
               '/search?q={w}', '/login', '/account/login', '/signin', '/help/{s}', '/support/{s}',
               '/2026/{m}/{s}.html', '/index.php?page={w}', '/wp-content/uploads/2026/{m}/{w}.jpg',
               '/category/{w}/', '/user/profile', '/cart', '/checkout', '/events/{s}', '/careers']
PATH_WORDS = ['home', 'promo', 'raya', 'update', 'annual', 'report', 'guide', 'travel', 'food',
              'sale', 'student', 'portal', 'service', 'download', 'event', 'news', 'merdeka']


def legit_path():
    p = rng.choice(LEGIT_PATHS)
    return (p.replace('{s}', '-'.join(rng.sample(PATH_WORDS, rng.randint(2, 4))))
             .replace('{w}', rng.choice(PATH_WORDS)).replace('{m}', f"{rng.randint(1, 12):02d}"))

# If a domain is in several lists, the most specific/severe category wins
CATEGORY_PRIORITY = ['phishing', 'scam', 'malware', 'gambling', 'piracy']

# Training-sample sizes per category (url_dataset_public.csv)
SAMPLE_SIZES = {'phishing': 14000, 'malware': 6000, 'scam': 2000, 'gambling': 9000, 'piracy': 4000,
                'legit': 34000}

_DOMAIN_RE = re.compile(r'^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')
rng = random.Random(2026)


def download(feeds_dir):
    os.makedirs(feeds_dir, exist_ok=True)
    for name, (url, *_rest) in SOURCES.items():
        path = os.path.join(feeds_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            continue
        print(f"  downloading {name} ...")
        req = urllib.request.Request(url, headers={'User-Agent': 'SME-CyberSentry-research'})
        with urllib.request.urlopen(req, timeout=300) as r:
            data = r.read()
        if url.endswith('.zip'):
            data = zipfile.ZipFile(io.BytesIO(data)).read('top-1m.csv')
        with open(path, 'wb') as fh:
            fh.write(data)


def clean_domain(line):
    line = line.strip().lower()
    if not line or line.startswith(('#', '!', '[')):
        return None
    if line.startswith(('0.0.0.0 ', '127.0.0.1 ')):
        line = line.split(None, 1)[1].strip()
    line = line.lstrip('*.').split('#')[0].strip().rstrip('.')
    if line in ('localhost', '0.0.0.0') or not _DOMAIN_RE.match(line):
        return None
    return line


def read_domains(path):
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            d = clean_domain(line)
            if d:
                yield d


def read_urls(path):
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            u = line.strip()
            if u.startswith(('http://', 'https://')) and len(u) < 600 and ' ' not in u:
                yield u


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--feeds-dir', default=DEFAULT_FEEDS_DIR)
    args = ap.parse_args()
    feeds = args.feeds_dir
    print("1. Fetching public feeds ->", feeds)
    download(feeds)

    # ---------------- Tranco (legit / popularity) ----------------
    def read_tranco(name):
        out = []
        with open(os.path.join(feeds, name), encoding='utf-8') as fh:
            for row in csv.reader(fh):
                if len(row) == 2:
                    out.append((int(row[0]), row[1].strip().lower()))
        return out

    tranco = read_tranco('top-1m.csv')
    tranco_sub = read_tranco('top-1m-subdomains.csv')
    top10k = {d for r, d in tranco if r <= 10000}

    # ---------------- Threat domains ----------------
    print("2. Normalising threat domain lists ...")
    intel = {}            # domain -> (category index, source bitmask)  - compact for millions of rows
    phishing_urls = []
    source_names = list(SOURCES)
    for name, (_url, kind, cat, _lic) in SOURCES.items():
        path = os.path.join(feeds, name)
        bit = 1 << source_names.index(name)
        cat_i = CATEGORY_PRIORITY.index(cat) if cat in CATEGORY_PRIORITY else None
        if kind == 'domains':
            items = read_domains(path)
        elif kind == 'urls':
            urls = list(read_urls(path))
            phishing_urls += [(u, name) for u in urls]
            items = (parse_url(u)[1] for u in urls)
        elif kind == 'citizenlab':
            with open(path, encoding='utf-8') as fh:
                items = [parse_url(r['url'])[1] for r in csv.DictReader(fh) if r['category_code'] == 'GMB']
        else:
            continue
        n = 0
        for d in items:
            if not d or _DOMAIN_RE.match(d) is None:
                continue
            n += 1
            prev = intel.get(d)
            if prev is None:
                intel[d] = (cat_i, bit)
            else:
                intel[d] = (min(prev[0], cat_i), prev[1] | bit)
        print(f"   {name:22s} {n:>9,d} entries ({cat})")

    # Never let a blocklist entry condemn a whole popular platform/official domain
    # (e.g. 'docs.google.com' hosting one phishing form). Exact sub-hosts stay.
    protected = TRUSTED_DOMAINS | top10k | FREE_HOSTING | URL_SHORTENERS
    removed = [d for d in intel if d in protected]
    for d in removed:
        del intel[d]
    print(f"   removed {len(removed):,} entries that are popular/official platforms")
    print(f"   TOTAL unique threat hostnames: {len(intel):,}")

    # ---------------- Write threat_intel.db ----------------
    print("3. Writing", INTEL_DB)
    if os.path.exists(INTEL_DB):
        os.remove(INTEL_DB)
    conn = sqlite3.connect(INTEL_DB)
    conn.execute('''CREATE TABLE THREAT_INTEL_DOMAINS (
                        Domain TEXT PRIMARY KEY, Category TEXT NOT NULL, Sources TEXT NOT NULL
                    ) WITHOUT ROWID''')
    conn.execute('CREATE TABLE POPULAR_DOMAINS (Domain TEXT PRIMARY KEY, Rank INTEGER NOT NULL) WITHOUT ROWID')
    conn.execute('''CREATE TABLE FEED_SOURCES (File TEXT PRIMARY KEY, URL TEXT, Category TEXT,
                        Licence TEXT, Retrieved DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.executemany('INSERT INTO THREAT_INTEL_DOMAINS VALUES (?, ?, ?)',
                     ((d, CATEGORY_PRIORITY[c], ','.join(n for i, n in enumerate(source_names) if m >> i & 1))
                      for d, (c, m) in intel.items()))
    conn.executemany('INSERT OR IGNORE INTO POPULAR_DOMAINS VALUES (?, ?)',
                     ((d, r) for r, d in tranco if r <= 100000))
    conn.executemany('INSERT INTO FEED_SOURCES (File, URL, Category, Licence) VALUES (?, ?, ?, ?)',
                     ((n, u, c, l) for n, (u, _k, c, l) in SOURCES.items()))
    conn.commit()
    counts = conn.execute('SELECT Category, COUNT(*) FROM THREAT_INTEL_DOMAINS GROUP BY 1').fetchall()
    conn.execute('VACUUM')
    conn.close()
    print("   per category:", dict(counts))

    # ---------------- Training sample ----------------
    print("4. Sampling training URLs ->", OUT_CSV)
    rows, seen_url = [], set()

    def add(url, label, cat, src):
        if url not in seen_url:
            seen_url.add(url)
            rows.append((url, label, cat, src))

    # 4a. Phishing URLs with full paths (most realistic). Cap per registered
    #     domain so one mass campaign doesn't dominate, and skip phishing that
    #     lives on official platforms (docs.google.com forms etc.): the URL
    #     itself carries no signal there - content analysis handles it.
    per_domain = {}
    rng.shuffle(phishing_urls)
    target = SAMPLE_SIZES['phishing'] * 3 // 4
    n = 0
    for u, src in sorted(phishing_urls, key=lambda x: x[1] != 'openphish.txt'):  # OpenPhish first
        host = parse_url(u)[1]
        reg = registered_domain(host)
        if not host or reg in TRUSTED_DOMAINS or (reg in top10k and reg not in FREE_HOSTING):
            continue
        if per_domain.get(reg, 0) >= 2:
            continue
        per_domain[reg] = per_domain.get(reg, 0) + 1
        add(u, 'malicious', 'phishing', src)
        n += 1
        if n >= target:
            break

    # 4b. Domain-only lists -> root URLs (scheme mix as observed in the wild)
    by_cat = {}
    for d, (c, m) in intel.items():
        first_src = next(n for i, n in enumerate(source_names) if m >> i & 1)
        by_cat.setdefault(CATEGORY_PRIORITY[c], []).append((d, first_src))
    for cat, items in by_cat.items():
        want = SAMPLE_SIZES[cat] - (n if cat == 'phishing' else 0)
        for d, src in rng.sample(items, min(want, len(items))):
            scheme = 'https' if rng.random() < 0.75 else 'http'
            add(f"{scheme}://{d}/", 'malicious', cat, src)

    # 4c. Legitimate: Tranco popular + long-tail + real subdomain hosts
    #     (excluding anything blocklisted, at host or registered-domain level)
    bad = set(intel)
    ok = lambda d: d not in bad and registered_domain(d) not in bad
    head = [d for r, d in tranco if r <= 20000 and ok(d)]
    tail = [d for r, d in tranco if r > 20000 and ok(d)]
    subs = [d for r, d in tranco_sub
            if d.count('.') >= 2 and not d.startswith('www.') and d != registered_domain(d) and ok(d)]
    third = SAMPLE_SIZES['legit'] // 3
    picks = ([(d, 'tranco') for d in rng.sample(head, third)] + [(d, 'tranco') for d in rng.sample(tail, third)]
             + [(d, 'tranco_subdomains') for d in rng.sample(subs, third)])
    for d, src in picks:
        www = 'www.' if src == 'tranco' and rng.random() < 0.4 else ''
        path = legit_path() if rng.random() < 0.3 else '/'
        add(f"https://{www}{d}{path}", 'legit', 'legit', src + ('_path' if path != '/' else ''))

    rng.shuffle(rows)
    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['url', 'label', 'category', 'source'])
        w.writerows(rows)
    from collections import Counter
    print("   rows:", len(rows), dict(Counter(r[2] for r in rows)))


if __name__ == '__main__':
    main()
