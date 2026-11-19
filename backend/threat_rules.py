"""
Behaviour / content / reputation checks that a URL-only model cannot see.

    ThreatIntel        offline lookup in database/threat_intel.db (public blocklists)
    verify_tls()       real HTTPS certificate check (not just "does the URL say https")
    analyze_page()     drive-by downloads, malvertising redirects, gambling, illegal
                       streaming, fake virus alerts, credential forms

Every check returns "findings": {category, score (0-100), reason}. app.py fuses
them with the ML scores. Phrase lists for the content checks live in the
THREAT_DICTIONARY table (categories in CONTENT_CATEGORIES) so they can be edited
without touching code.
"""
import os
import re
import socket
import ssl
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from features import FREE_HOSTING, URL_SHORTENERS, parse_url, registered_domain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTEL_DB = os.path.join(ROOT, 'database', 'threat_intel.db')

# THREAT_DICTIONARY categories handled here (not by the generic phishing keyword score)
CONTENT_CATEGORIES = ('Gambling', 'Illegal Streaming', 'Drive-by Download', 'Fake Alert')

INTEL_SCORES = {'phishing': 97, 'scam': 95, 'malware': 95, 'gambling': 92, 'piracy': 85}
INTEL_LABELS = {'phishing': 'Phishing', 'scam': 'Scam', 'malware': 'Malware / Scam',
                'gambling': 'Online Gambling', 'piracy': 'Illegal Streaming / Piracy'}

RISKY_EXTENSIONS = ('.exe', '.msi', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe', '.js',
                    '.jse', '.wsf', '.hta', '.ps1', '.jar', '.apk', '.xapk', '.dll', '.lnk', '.iso',
                    '.img', '.vhd', '.dmg', '.pkg', '.zip', '.rar', '.7z', '.cab', '.reg')

# Query keys used by ad networks / traffic distribution systems (popunder malvertising)
MALVERTISING_PARAMS = {'zoneid', 'zone_id', 'cost', 'cpm', 'cpc', 'clickid', 'click_id', 'subid',
                       'sub_id', 'subid1', 'subid2', 'campaignid', 'campaign_id', 'pubid', 'ymid',
                       'bcid', 'var', 'spot_id', 'spotid', 'placement_id', 'tds', 'lpid', 'oaid',
                       'visitor_id', 'click_hash', 'zid', 'cid_ad'}

STREAM_CONTEXT = re.compile(r'\b(cricket|football|soccer|epl|premier league|la liga|champions league|'
                            r'nba|nfl|ufc|f1|formula 1|motogp|badminton|bola|sukan|match|vs\.?|'
                            r'movie|movies|episode|anime|drama|filem)\b', re.I)


# ---------------------------------------------------------------------------
# Threat intelligence (offline)
# ---------------------------------------------------------------------------
class ThreatIntel:
    def __init__(self, path=INTEL_DB):
        self.available = os.path.exists(path)
        self._local = threading.local()
        self.path = path

    def _conn(self):
        if not self.available:
            return None
        c = getattr(self._local, 'conn', None)
        if c is None:
            c = sqlite3.connect(f'file:{self.path}?mode=ro', uri=True, check_same_thread=False)
            self._local.conn = c
        return c

    def lookup(self, host):
        """Exact host or any parent domain (down to the registered domain)."""
        conn = self._conn()
        if not conn or not host:
            return None
        reg = registered_domain(host)
        parts = host.split('.')
        cands = ['.'.join(parts[i:]) for i in range(len(parts)) if len('.'.join(parts[i:])) >= len(reg)]
        q = 'SELECT Domain, Category, Sources FROM THREAT_INTEL_DOMAINS WHERE Domain IN (%s)' % ','.join('?' * len(cands))
        rows = conn.execute(q, cands).fetchall()
        # A listing of a whole shared platform (weebly.com, bit.ly) must not condemn every user
        rows = [r for r in rows if r[0] == host or r[0] not in FREE_HOSTING | URL_SHORTENERS]
        if not rows:
            return None
        row = max(rows, key=lambda r: len(r[0]))  # most specific match
        return {'domain': row[0], 'category': row[1], 'sources': row[2].split(',')}

    def popularity_rank(self, host):
        conn = self._conn()
        if not conn or not host:
            return None
        r = conn.execute('SELECT Rank FROM POPULAR_DOMAINS WHERE Domain = ?', (registered_domain(host),)).fetchone()
        return r[0] if r else None


# ---------------------------------------------------------------------------
# HTTPS certificate verification
# ---------------------------------------------------------------------------
_TLS_CACHE, _TLS_TTL = {}, 3600


# Errors that prove the certificate is bad (vs. "couldn't build the chain locally")
_HARD_TLS_ERRORS = ('expired', 'self-signed', 'self signed', 'hostname mismatch', "doesn't match",
                    'not yet valid', 'revoked', 'unsupported certificate purpose')


def _tls_context():
    ctx = ssl.create_default_context()          # Windows / OS trust store
    try:
        import certifi                           # + Mozilla root bundle: the OS store only
        ctx.load_verify_locations(certifi.where())  # holds roots it has already downloaded
    except (ImportError, OSError):
        pass
    return ctx


def verify_tls(host, port=443, timeout=4.0):
    """
    Performs a real TLS handshake with full certificate-chain and hostname
    verification (same trust store as the OS). Returns a dict describing the
    certificate, or why it is invalid. Results are cached for an hour.
    """
    if not host:
        return {'checked': False}
    key = (host, port)
    hit = _TLS_CACHE.get(key)
    if hit and time.time() - hit[0] < _TLS_TTL:
        return hit[1]
    res = {'checked': True, 'valid': False}
    ctx = _tls_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                res['tls_version'] = tls.version()
        nb = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        na = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        res.update(valid=True, issuer=issuer.get('organizationName') or issuer.get('commonName', '?'),
                   age_days=(now - nb).days, days_left=(na - now).days)
    except ssl.SSLCertVerificationError as e:
        res['error'] = e.verify_message or str(e)
        # An incomplete chain can be a client-side limitation (browsers fetch missing
        # intermediates themselves), so only definite failures count as invalid.
        res['definite'] = any(k in res['error'].lower() for k in _HARD_TLS_ERRORS)
    except (ssl.SSLError, OSError) as e:
        res = {'checked': False, 'error': type(e).__name__}  # unreachable / no TLS on 443
    _TLS_CACHE[key] = (time.time(), res)
    return res


# ---------------------------------------------------------------------------
# Content & behaviour analysis
# ---------------------------------------------------------------------------
def _phrase_hits(text, phrases):
    hits = []
    for p in phrases:
        if re.search(r'(?<![a-z0-9])' + re.escape(p['Keyword_Text'].lower()) + r'(?![a-z0-9])', text):
            hits.append(p)
    return hits


def _noisy_or(weights):
    p = 1.0
    for w in weights:
        p *= 1 - w
    return 1 - p


def analyze_page(url, text, signals, phrases, tls, trusted):
    """
    url, text  : page address and visible text
    signals    : dict sent by the extension (downloads, iframes, forms ...)
    phrases    : THREAT_DICTIONARY rows whose Category is in CONTENT_CATEGORIES
    tls        : verify_tls() result (or None for http pages)
    """
    findings = []
    signals = signals or {}
    _, host, path, _ = parse_url(url)
    reg = registered_domain(host)
    low = ' '.join(str(text)[:8000].lower().split())
    by_cat = {c: [p for p in phrases if p['Category'] == c] for c in CONTENT_CATEGORIES}

    def add(category, score, reason):
        findings.append({'category': category, 'score': round(float(score), 1), 'reason': reason})

    # 1. Downloads actually started by this page (from chrome.downloads, via the extension)
    for d in signals.get('downloads', [])[:10]:
        src_hosts = {parse_url(d.get(k, '') or '')[1] for k in ('referrer', 'url', 'finalUrl')}
        src_hosts |= {parse_url((d.get('url') or '')[5:])[1]} if str(d.get('url', '')).startswith('blob:') else set()
        if not any(h and registered_domain(h) == reg for h in src_hosts):
            continue
        name = os.path.basename((d.get('filename') or d.get('url') or '').replace('\\', '/')).split('?')[0][:80]
        risky = name.lower().endswith(RISKY_EXTENSIONS)
        flagged_by_chrome = d.get('danger') not in (None, '', 'safe', 'accepted')
        if risky or flagged_by_chrome:
            add('Drive-by Download', 95 if not trusted else 55,
                f"This site downloaded '{name}' to your computer" +
                (" (Chrome marked it dangerous)" if flagged_by_chrome else " - executable/archive files from unknown sites often contain malware"))
        else:
            add('Drive-by Download', 45, f"This site started a download: '{name}'")

    # 2. Content phrase categories (from THREAT_DICTIONARY)
    dl_hits = _phrase_hits(low, by_cat['Drive-by Download'])
    if dl_hits and not trusted:
        add('Drive-by Download', min(80, 100 * _noisy_or([h['Risk_Weight'] for h in dl_hits])),
            "Page says a download started automatically (" + ', '.join(f'"{h["Keyword_Text"]}"' for h in dl_hits[:2]) + ")")

    alert_hits = _phrase_hits(low, by_cat['Fake Alert'])
    if alert_hits and not trusted:
        add('Fake Alert / Tech-Support Scam', min(92, 100 * _noisy_or([h['Risk_Weight'] for h in alert_hits])),
            "Fake security alert / 'click Allow' trick (" + ', '.join(f'"{h["Keyword_Text"]}"' for h in alert_hits[:2]) + ")")

    gam_hits = _phrase_hits(low, by_cat['Gambling'])
    strong = [h for h in gam_hits if h['Risk_Weight'] >= 0.85]
    if strong and not trusted:
        total = sum(h['Risk_Weight'] for h in gam_hits)
        score = 90 if total >= 2.5 else 75 if total >= 1.6 else 55
        add('Online Gambling', score, f"Online gambling / betting content ({len(gam_hits)} terms: " +
            ', '.join(h['Keyword_Text'] for h in gam_hits[:4]) + "). Online gambling is illegal in Malaysia "
            "and these sites are a common source of scams and phishing")

    st_hits = _phrase_hits(low, by_cat['Illegal Streaming'])
    st_strong = [h for h in st_hits if h['Risk_Weight'] >= 0.85]
    if st_strong and STREAM_CONTEXT.search(low) and not trusted:
        total = sum(h['Risk_Weight'] for h in st_hits)
        add('Illegal Streaming / Piracy', 78 if total >= 1.7 else 55,
            "Free unofficial sports/movie streaming (" + ', '.join(f'"{h["Keyword_Text"]}"' for h in st_hits[:3]) +
            "). These sites rely on malicious pop-up ads and fake download buttons")

    # 3. Malvertising / traffic-distribution redirect parameters in the URL
    q = {k.lower() for k in parse_qs(urlparse(url).query, keep_blank_values=True)}
    ad_keys = sorted(q & MALVERTISING_PARAMS)
    if len(ad_keys) >= 2 and not trusted:
        add('Malvertising Redirect', 72, f"Arrived via an ad-network redirect (URL parameters: {', '.join(ad_keys)}) "
            "- typical of pop-under scam/malware landing pages")

    # 4. Page structure signals
    exe_links = [l for l in signals.get('exe_links', []) if l]
    if exe_links and not trusted:
        add('Drive-by Download', 35, f"Page links directly to {len(exe_links)} executable/archive file(s), e.g. "
            f"'{os.path.basename(exe_links[0])[:60]}'")
    for m in signals.get('meta_refresh', [])[:1]:
        target = parse_url(m.split('url=', 1)[-1] if 'url=' in m.lower() else '')[1]
        if target and registered_domain(target) != reg:
            add('Malvertising Redirect', 55, f"Page auto-redirects to another site ({target})")
    if signals.get('hidden_iframes', 0) >= 3 and not trusted:
        add('Malvertising Redirect', 40, f"{signals['hidden_iframes']} hidden iframes on the page")

    pw = signals.get('password_fields', 0)
    if pw:
        if signals.get('protocol') == 'http:':
            add('Phishing', 75, "Password form on a page without HTTPS - your password is sent in plain text")
        off = {parse_url(a)[1] for a in signals.get('form_actions', [])} - {host, ''}
        off = {h for h in off if registered_domain(h) != reg}
        if off and not trusted:
            add('Phishing', 70, f"Password form sends your login to a different site ({sorted(off)[0]})")

    # 5. HTTPS certificate
    if tls and tls.get('checked') and not tls.get('valid') and tls.get('definite'):
        add('Invalid Certificate', 85, f"HTTPS certificate is NOT valid: {tls.get('error', 'verification failed')}")
    elif tls and tls.get('checked') and not tls.get('valid'):
        add('Unverified Certificate', 30, f"Could not fully verify the HTTPS certificate chain ({tls.get('error')})")
    elif tls and tls.get('valid') and tls.get('age_days', 99) <= 3 and not trusted:
        add('Suspicious Certificate', 35, f"HTTPS certificate was issued only {tls['age_days']} day(s) ago")

    return findings
