"""
Shared feature extraction for SME-CyberSentry.

Used by BOTH train_model.py and app.py so the features the models were trained
on are always identical to the features computed at scan time.

Design note (why there is no URL_Length feature any more):
    Raw URL length is not a reliable phishing signal. Legitimate sites such as
    Gmail, Google Search, Shopee product pages or bank portals routinely have
    URLs well over 75 characters because of paths, session IDs and tracking
    parameters. Instead, the features below look at the *hostname* - the part
    an attacker actually controls and has to disguise.
"""
import math
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Domain knowledge
# ---------------------------------------------------------------------------

# Multi-label public suffixes we need to understand to find the registered domain
MULTI_PART_SUFFIXES = {
    'com.my', 'gov.my', 'edu.my', 'org.my', 'net.my', 'mil.my', 'name.my',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'com.sg', 'gov.sg', 'edu.sg',
    'co.id', 'go.id', 'ac.id', 'com.br', 'co.jp', 'co.in', 'com.cn', 'com.hk',
    'co.th', 'com.ph', 'com.vn', 'co.nz',
}

# TLDs heavily abused by phishing campaigns (cheap / free registration)
SUSPICIOUS_TLDS = {
    'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'icu', 'buzz', 'cyou',
    'rest', 'sbs', 'vip', 'pw', 'monster', 'support', 'live', 'online', 'site',
    'shop', 'club', 'work', 'info', 'cc', 'ru', 'cn', 'su', 'zip', 'mov', 'lol',
    'quest', 'bond', 'cfd', 'beauty', 'hair', 'skin', 'today', 'win', 'loan',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rb.gy', 't.ly', 'shorturl.at', 's.id', 'rebrand.ly', 'tiny.cc',
    'bl.ink', 'short.io', 'v.gd', 'qr.co', 'lnkd.in', 'shorturl.asia',
}

# Free hosting / site builders: legitimate services, but heavily abused to host
# phishing kits because they give the attacker a free HTTPS subdomain.
FREE_HOSTING = {
    '000webhostapp.com', 'weebly.com', 'wixsite.com', 'firebaseapp.com',
    'web.app', 'pages.dev', 'vercel.app', 'netlify.app', 'github.io',
    'glitch.me', 'repl.co', 'herokuapp.com', 'blogspot.com', 'wordpress.com',
    'square.site', 'webflow.io', 'framer.website', 'godaddysites.com',
    'ngrok.io', 'ngrok-free.app', 'r2.dev', 'workers.dev', 'surge.sh',
}

# Brand keyword -> registered domains that the brand officially owns.
BRAND_OFFICIAL_DOMAINS = {
    'maybank': {'maybank2u.com.my', 'maybank.com', 'maybank.com.my', 'maybank2u.com'},
    'm2u': {'maybank2u.com.my', 'maybank2u.com'},
    'cimb': {'cimbclicks.com.my', 'cimb.com.my', 'cimb.com', 'cimbbank.com.my'},
    'pbebank': {'pbebank.com', 'publicbank.com.my'},
    'publicbank': {'pbebank.com', 'publicbank.com.my'},
    'rhb': {'rhbgroup.com', 'rhb.com.my'},
    'hlb': {'hlb.com.my', 'hongleong.com.my'},
    'hongleong': {'hlb.com.my', 'hongleong.com.my'},
    'bankislam': {'bankislam.com', 'bankislam.com.my'},
    'bsn': {'mybsn.com.my', 'bsn.com.my'},
    'ambank': {'ambank.com.my', 'ambankgroup.com'},
    'lhdn': {'hasil.gov.my'},
    'hasil': {'hasil.gov.my'},
    'kwsp': {'kwsp.gov.my'},
    'epf': {'kwsp.gov.my'},
    'jpj': {'jpj.gov.my'},
    'mysejahtera': {'mysejahtera.gov.my'},
    'poslaju': {'pos.com.my'},
    'jtexpress': {'jtexpress.my', 'jet.com.my'},
    'jnt': {'jtexpress.my'},
    'ninjavan': {'ninjavan.co'},
    'shopee': {'shopee.com.my', 'shopee.com', 'shopee.sg', 'shopee.co.id'},
    'lazada': {'lazada.com.my', 'lazada.com', 'lazada.sg'},
    'grab': {'grab.com'},
    'touchngo': {'touchngo.com.my', 'tngdigital.com.my'},
    'tngdigital': {'tngdigital.com.my'},
    'unifi': {'unifi.com.my', 'tm.com.my'},
    'netflix': {'netflix.com'},
    'spotify': {'spotify.com'},
    'icloud': {'icloud.com', 'apple.com'},
    'apple': {'apple.com', 'icloud.com'},
    'disney': {'disneyplus.com', 'disney.com', 'hotstar.com'},
    'hotstar': {'hotstar.com', 'disneyplus.com'},
    'paypal': {'paypal.com', 'paypal.me'},
    'microsoft': {'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com'},
    'office365': {'office.com', 'microsoft.com'},
    'outlook': {'outlook.com', 'live.com', 'office.com'},
    'google': {'google.com', 'google.com.my', 'googleusercontent.com', 'gmail.com'},
    'gmail': {'gmail.com', 'google.com'},
    'facebook': {'facebook.com', 'fb.com'},
    'instagram': {'instagram.com'},
    'whatsapp': {'whatsapp.com', 'whatsapp.net'},
    'amazon': {'amazon.com', 'amazon.sg'},
}

# Short brand tokens only count when they are a whole hostname token
# (avoids "pos" in "posts.example.com" or "rhb" inside random strings).
SHORT_BRAND_MIN_LEN = 5

# Well-known official domains. Matching registered domains never receive a
# URL-based "Danger" verdict (page content can still raise a warning).
TRUSTED_DOMAINS = set().union(*BRAND_OFFICIAL_DOMAINS.values()) | {
    'youtube.com', 'googleapis.com', 'gstatic.com', 'github.com', 'gitlab.com',
    'stackoverflow.com', 'wikipedia.org', 'linkedin.com', 'x.com', 'twitter.com',
    'reddit.com', 'tiktok.com', 'yahoo.com', 'bing.com', 'duckduckgo.com',
    'zoom.us', 'canva.com', 'notion.so', 'dropbox.com', 'openai.com',
    'chatgpt.com', 'claude.ai', 'anthropic.com', 'bnm.gov.my', 'tm.com.my',
    'tnb.com.my', 'astro.com.my', 'celcom.com.my', 'maxis.com.my',
    'digi.com.my', 'celcomdigi.com', 'u.com.my', 'airasia.com',
    'malaysiaairlines.com', 'mudah.my', 'carousell.com.my', 'thestar.com.my',
    'bharian.com.my', 'hmetro.com.my', 'malaysiakini.com', 'nst.com.my',
    'booking.com', 'agoda.com', 'office.com', 'microsoftonline.com',
    'sharepoint.com', 'live.com', 'uitm.edu.my', 'unisza.edu.my', 'um.edu.my',
}
TRUSTED_SUFFIXES = ('.gov.my', '.edu.my', '.mil.my')

# Words that phishing kits like to put in hostnames
PHISHY_HOST_WORDS = (
    'login', 'logon', 'signin', 'sign-in', 'secure', 'verify', 'verification',
    'update', 'account', 'akaun', 'semakan', 'semak', 'kemaskini', 'sahkan',
    'tuntut', 'claim', 'bonus', 'hadiah', 'reward', 'wallet', 'billing',
    'unlock', 'suspend', 'confirm', 'auth', 'recovery', 'reset', 'bantuan',
    'support', 'helpdesk', 'webscr', 'validation', 'security', 'alert',
)

URL_FEATURE_NAMES = [
    'Hostname_Length',        # length of hostname only (not the path/query)
    'Num_Subdomains',         # labels in front of the registered domain
    'Hostname_Hyphens',       # '-' inside hostname (e.g. maybank-secure-login.com)
    'Hostname_Digits',        # digits inside hostname
    'Is_IP_Host',             # http://103.4.5.6/login
    'Has_At_Symbol',          # https://maybank2u.com.my@evil.top/
    'Uses_HTTP',              # no TLS
    'Suspicious_TLD',         # .top .xyz .tk ...
    'Is_URL_Shortener',       # bit.ly, tinyurl ...
    'Free_Hosting',           # *.weebly.com, *.web.app ...
    'Brand_Impersonation',    # brand name in host but domain not owned by brand
    'Brand_Lookalike',        # typosquat e.g. maybamk2u, paypa1
    'Phishy_Host_Words',      # count of login/verify/semakan... in hostname
    'Is_Punycode',            # xn-- homograph domains
    'Host_Entropy',           # randomness of registered domain label
    'Brand_In_Path',          # /maybank/login.php on a domain the brand doesn't own
    'Suspicious_Path',        # .php kits, wp-content uploads, login/verify words in path
]

SUSPICIOUS_PATH_TOKENS = ('.php', 'wp-content', 'wp-includes', 'wp-admin', '/~', '//',
                          'login', 'signin', 'verify', 'secure', 'account', 'update',
                          'confirm', 'billing', 'semakan', 'kemaskini', 'claim', 'tuntut')

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_URL_IN_TEXT_RE = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_url(url_str):
    """Return (scheme, hostname, path, raw_netloc) for a URL-ish string."""
    url_str = (url_str or '').strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_str):
        url_str = 'http://' + url_str
    try:
        p = urlparse(url_str)
        host = (p.hostname or '').lower().rstrip('.')
        return p.scheme.lower(), host, p.path or '', p.netloc
    except ValueError:
        return 'http', '', '', ''


def registered_domain(host):
    """'mail.google.com' -> 'google.com', 'www.hasil.gov.my' -> 'hasil.gov.my'."""
    if not host or _IP_RE.match(host):
        return host
    parts = host.split('.')
    if len(parts) >= 3 and '.'.join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def is_trusted_domain(host):
    if not host:
        return False
    if host.endswith(TRUSTED_SUFFIXES):
        return True
    return registered_domain(host) in TRUSTED_DOMAINS


def _levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _brand_hits(host):
    tokens = set(re.split(r'[.\-]', host))
    hits = set()
    for brand in BRAND_OFFICIAL_DOMAINS:
        if len(brand) >= SHORT_BRAND_MIN_LEN:
            if brand in host:
                hits.add(brand)
        elif brand in tokens:
            hits.add(brand)
    return hits


# Official second-level labels used for typosquat detection (e.g. "maybank2u")
_OFFICIAL_LABELS = {d.split('.')[0] for ds in BRAND_OFFICIAL_DOMAINS.values() for d in ds}
_OFFICIAL_LABELS = {l for l in _OFFICIAL_LABELS if len(l) >= 5}


def _is_lookalike(reg_label, reg_domain):
    """Typosquat: label is 1-2 edits from an official brand label but not owned by it."""
    if reg_domain in TRUSTED_DOMAINS or len(reg_label) < 5:
        return 0
    # Homoglyph digit swaps: g00gle, paypa1, rnaybank (rn -> m)
    variants = {
        reg_label.translate(str.maketrans('0134578', 'oieastb')),
        reg_label.translate(str.maketrans('0134578', 'oleastb')),
        reg_label.replace('rn', 'm').replace('vv', 'w'),
    }
    for official in _OFFICIAL_LABELS:
        if reg_label == official or official in variants:
            return 1  # e.g. maybank2u.xyz, g00gle.com
        # Edit-distance check only for longer names; short ones (gmail, apple,
        # hasil) are too close to ordinary words like "email" / "ample".
        if len(official) >= 7 and abs(len(reg_label) - len(official)) <= 2:
            if _levenshtein(reg_label, official) <= 2:
                return 1
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_url_features(url_str):
    """Return an ordered dict of URL features (see URL_FEATURE_NAMES)."""
    scheme, host, path, netloc = parse_url(url_str)
    path = path.lower()
    reg = registered_domain(host)
    reg_label = reg.split('.')[0] if reg else ''
    is_ip = 1 if _IP_RE.match(host or '') else 0

    sub_part = host[: -len(reg)].rstrip('.') if reg and host.endswith(reg) else ''
    num_sub = 0 if is_ip or not sub_part else len(sub_part.split('.'))
    if sub_part.split('.')[:1] == ['www']:
        num_sub -= 1  # "www." is not deceptive

    brands = _brand_hits(host)
    impersonation = 0
    if brands and not is_ip:
        official = set().union(*(BRAND_OFFICIAL_DOMAINS[b] for b in brands))
        if reg not in official:
            impersonation = 1

    brand_in_path = 0
    path_brands = _brand_hits(path.replace('/', '.').replace('_', '-'))
    if path_brands:
        official = set().union(*(BRAND_OFFICIAL_DOMAINS[b] for b in path_brands))
        brand_in_path = 0 if reg in official else 1

    free_host = 1 if any(host == d or host.endswith('.' + d) for d in FREE_HOSTING) else 0

    feats = {
        'Hostname_Length': len(host),
        'Num_Subdomains': max(num_sub, 0),
        'Hostname_Hyphens': host.count('-'),
        'Hostname_Digits': sum(c.isdigit() for c in host) if not is_ip else 0,
        'Is_IP_Host': is_ip,
        'Has_At_Symbol': 1 if '@' in netloc else 0,
        'Uses_HTTP': 1 if scheme == 'http' else 0,
        'Suspicious_TLD': 1 if host.rsplit('.', 1)[-1] in SUSPICIOUS_TLDS and not is_ip else 0,
        'Is_URL_Shortener': 1 if reg in URL_SHORTENERS or host in URL_SHORTENERS else 0,
        'Free_Hosting': free_host,
        'Brand_Impersonation': impersonation,
        'Brand_Lookalike': _is_lookalike(reg_label, reg) if not is_ip else 0,
        'Phishy_Host_Words': sum(1 for w in PHISHY_HOST_WORDS if w in host),
        'Is_Punycode': 1 if 'xn--' in host else 0,
        'Host_Entropy': round(_entropy(reg_label), 3),
        'Brand_In_Path': brand_in_path,
        'Suspicious_Path': sum(1 for t in SUSPICIOUS_PATH_TOKENS if t in path),
    }
    return feats


def strip_urls(text):
    """Remove URLs from text so the text model learns language, not links."""
    return _URL_IN_TEXT_RE.sub(' ', str(text))


def find_urls(text):
    return [u.rstrip('.,;)') for u in _URL_IN_TEXT_RE.findall(str(text))]


_SENT_SPLIT_RE = re.compile(r'(?<=[.!?])\s+|\n+')


def split_sentences(text, max_chars=5000, min_words=4, max_sentences=400):
    """Split page text into candidate sentences for the text model."""
    out = []
    for s in _SENT_SPLIT_RE.split(str(text)[:max_chars]):
        s = s.strip()
        if len(s.split()) >= min_words:
            out.append(s[:400])
        if len(out) >= max_sentences:
            break
    return out
