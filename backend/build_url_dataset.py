"""
Builds backend/dataset/url_dataset_synthetic.csv - a Malaysian-specific SUPPLEMENT
to the real public data in url_dataset_public.csv (see fetch_threat_intel.py).

The public feeds are global: they contain few Maybank / LHDN / Shopee-MY style
phishing URLs, and Tranco only provides bare domains (no long legitimate paths).
This generator fills exactly those two gaps.

Why this exists:
    The email CSVs only contain 4 distinct phishing URLs and the legitimate
    sentences contain no URLs at all, so a model trained on them alone learns
    "any URL = phishing" and "long URL = phishing". This script produces a
    balanced URL corpus where:
      * legitimate URLs come from real official domains (Gmail, Google, Malaysian
        banks, gov.my, e-commerce, couriers, universities, SME-style sites) and
        are deliberately given realistic LONG paths/query strings, and
      * phishing URLs follow documented real-world phishing patterns (brand
        impersonation, typosquatting, suspicious TLDs, IP hosts, shorteners,
        '@' tricks, free hosting, punycode), with both short AND long paths.
    So URL length carries no label information - the model must learn from the
    hostname structure instead.

The output is deterministic (fixed random seed). Run:
    python backend/build_url_dataset.py
"""
import csv
import os
import random
import string

rng = random.Random(2026)
OUT = os.path.join(os.path.dirname(__file__), 'dataset', 'url_dataset_synthetic.csv')
EMAIL_CSVS = ['train_data.csv', 'test_data.csv', 'emails_cleaned.csv']


def rand_str(n, chars=string.ascii_letters + string.digits):
    return ''.join(rng.choice(chars) for _ in range(n))


def rand_hex(n):
    return rand_str(n, '0123456789abcdef')


def slug(words, k):
    return '-'.join(rng.sample(words, k))


SLUG_WORDS = ['promo', 'jualan', 'baju', 'raya', 'kasut', 'murah', 'laptop', 'harga',
              'terkini', 'berita', 'ekonomi', 'sukan', 'resepi', 'nasi', 'lemak',
              'panduan', 'cukai', 'pendapatan', 'tahun', 'semasa', 'smart', 'phone',
              'review', 'best', 'kuala', 'lumpur', 'hotel', 'cheap', 'flight', 'news',
              'update', 'policy', 'annual', 'report', 'sme', 'grant', 'digital']

# ---------------------------------------------------------------------------
# LEGITIMATE URL templates (real official domains, realistic paths)
# ---------------------------------------------------------------------------
LEGIT_TEMPLATES = [
    lambda: f"https://mail.google.com/mail/u/0/#inbox/FMfcgz{rand_str(26)}",
    lambda: f"https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox/FMfcgz{rand_str(26)}",
    lambda: f"https://www.google.com/search?q={'+'.join(rng.sample(SLUG_WORDS, 3))}&oq={rng.choice(SLUG_WORDS)}&gs_lcrp={rand_str(40)}&sourceid=chrome&ie=UTF-8",
    lambda: f"https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&service=mail&flowName=GlifWebSignIn&dsh=S{rng.randint(10**8, 10**9)}%3A{rand_str(20)}",
    lambda: f"https://docs.google.com/document/d/{rand_str(44)}/edit?usp=sharing",
    lambda: f"https://drive.google.com/drive/folders/{rand_str(33)}",
    lambda: f"https://www.youtube.com/watch?v={rand_str(11)}&list=PL{rand_str(32)}&index={rng.randint(1, 40)}",
    lambda: f"https://www.maybank2u.com.my/home/m2u/common/login.do",
    lambda: f"https://www.maybank2u.com.my/maybank2u/malaysia/en/personal/cards/credit_cards/{slug(SLUG_WORDS, 2)}.page?rp={rand_hex(12)}",
    lambda: f"https://www.cimbclicks.com.my/clicks/#/login?lang=en&ref={rand_hex(16)}",
    lambda: f"https://www.cimb.com.my/en/personal/promotions/{slug(SLUG_WORDS, 3)}.html",
    lambda: f"https://www2.pbebank.com/myIBK/apppbb/servlet/BxxxServlet?RDOName=BxxxAuth&MethodName=formLogin",
    lambda: f"https://www.rhbgroup.com/malaysia/personal/{slug(SLUG_WORDS, 2)}/index.html",
    lambda: f"https://www.hlb.com.my/en/personal-banking/{slug(SLUG_WORDS, 2)}.html",
    lambda: f"https://www.bankislam.com/personal-banking/{slug(SLUG_WORDS, 2)}/",
    lambda: f"https://mytax.hasil.gov.my/?lang=ms&session={rand_hex(32)}",
    lambda: f"https://bantuantunai.hasil.gov.my/FAQ/{slug(SLUG_WORDS, 2)}.pdf",
    lambda: f"https://i-akaun.kwsp.gov.my/{rng.choice(['login', 'member', 'eservices'])}/{rand_hex(8)}",
    lambda: f"https://www.jpj.gov.my/{slug(SLUG_WORDS, 2)}/",
    lambda: f"https://tracking.pos.com.my/tracking/{rng.choice('EPRC')}{rng.choice('ABCDEFGHJK')}{rng.randint(10**8, 10**9)}MY",
    lambda: f"https://www.jtexpress.my/tracking/{rng.randint(10**11, 10**12)}",
    lambda: f"https://shopee.com.my/{slug(SLUG_WORDS, 4)}-i.{rng.randint(10**7, 10**9)}.{rng.randint(10**9, 10**10)}?sp_atk={rand_hex(8)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(12)}&xptdk={rand_hex(8)}",
    lambda: f"https://www.lazada.com.my/products/{slug(SLUG_WORDS, 4)}-i{rng.randint(10**8, 10**10)}-s{rng.randint(10**8, 10**10)}.html?spm=a2o4k.searchlist.list.{rng.randint(1, 60)}&search=1",
    lambda: f"https://www.grab.com/my/{rng.choice(['food', 'transport', 'express', 'pay'])}/",
    lambda: f"https://www.touchngo.com.my/{slug(SLUG_WORDS, 2)}/",
    lambda: f"https://unifi.com.my/{rng.choice(['home-fibre', 'mobile', 'support'])}/{slug(SLUG_WORDS, 2)}",
    lambda: f"https://www.netflix.com/browse?jbv={rng.randint(10**7, 10**8)}",
    lambda: f"https://open.spotify.com/playlist/{rand_str(22)}?si={rand_hex(16)}",
    lambda: f"https://www.icloud.com/{rng.choice(['mail', 'photos', 'drive'])}/",
    lambda: f"https://www.apple.com/my/shop/buy-iphone/{slug(SLUG_WORDS, 2)}",
    lambda: f"https://www.disneyplus.com/en-my/browse/entity-{rand_hex(8)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(12)}",
    lambda: f"https://www.paypal.com/myaccount/transactions/details/{rand_str(17).upper()}",
    lambda: f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={rand_hex(8)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(4)}-{rand_hex(12)}&response_type=code&scope=openid%20profile",
    lambda: f"https://outlook.live.com/mail/0/inbox/id/AQQkADAwATM{rand_str(60)}",
    lambda: f"https://www.facebook.com/{rand_str(10, string.ascii_lowercase)}/posts/{rng.randint(10**14, 10**15)}",
    lambda: f"https://www.instagram.com/p/{rand_str(11)}/?igsh={rand_str(16)}",
    lambda: f"https://web.whatsapp.com/",
    lambda: f"https://github.com/{rand_str(8, string.ascii_lowercase)}/{slug(SLUG_WORDS, 2)}/blob/main/src/{rand_str(6, string.ascii_lowercase)}.py",
    lambda: f"https://stackoverflow.com/questions/{rng.randint(10**7, 8 * 10**7)}/{slug(SLUG_WORDS, 5)}",
    lambda: f"https://en.wikipedia.org/wiki/{'_'.join(w.capitalize() for w in rng.sample(SLUG_WORDS, 2))}",
    lambda: f"https://ms.wikipedia.org/wiki/{rng.choice(SLUG_WORDS).capitalize()}",
    lambda: f"https://www.linkedin.com/jobs/view/{rng.randint(10**9, 10**10)}/?refId={rand_str(22)}%3D%3D&trackingId={rand_str(22)}",
    lambda: f"https://www.thestar.com.my/news/nation/2026/{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{slug(SLUG_WORDS, 6)}",
    lambda: f"https://www.bharian.com.my/berita/nasional/2026/{rng.randint(1, 12):02d}/{rng.randint(10**6, 2 * 10**6)}/{slug(SLUG_WORDS, 5)}",
    lambda: f"https://www.malaysiakini.com/news/{rng.randint(600000, 800000)}",
    lambda: f"https://www.mudah.my/{slug(SLUG_WORDS, 3)}-{rng.randint(10**8, 10**9)}.htm",
    lambda: f"https://www.airasia.com/flights/search/?origin=KUL&destination={rng.choice(['BKI', 'PEN', 'TGG', 'SIN', 'BKK'])}&departDate={rng.randint(1, 28):02d}%2F{rng.randint(1, 12):02d}%2F2026&tripType=O&adult=1",
    lambda: f"https://www.uitm.edu.my/index.php/en/{slug(SLUG_WORDS, 2)}",
    lambda: f"https://ufuture.uitm.edu.my/{rng.choice(['home', 'course', 'login'])}/{rand_hex(10)}",
    lambda: f"https://www.unisza.edu.my/{slug(SLUG_WORDS, 2)}/",
    lambda: f"https://www.bnm.gov.my/-/{slug(SLUG_WORDS, 4)}",
    lambda: f"https://www.tnb.com.my/residential/{slug(SLUG_WORDS, 2)}",
    lambda: f"https://www.booking.com/hotel/my/{slug(SLUG_WORDS, 3)}.html?aid={rng.randint(10**5, 10**6)}&label=gen173nr-{rand_str(40)}&sid={rand_hex(32)}",
    lambda: f"https://zoom.us/j/{rng.randint(10**9, 10**10)}?pwd={rand_str(32)}",
    lambda: f"https://www.canva.com/design/{rand_str(11)}/{rand_str(22)}/edit",
    lambda: f"https://www.amazon.com/dp/B0{rand_str(8, string.ascii_uppercase + string.digits)}?ref_=cm_sw_r_{rand_str(20)}",
    # legit sites that genuinely use hyphens in their domain
    lambda: f"https://www.{rng.choice(['coca-cola', 'mercedes-benz', 't-mobile', 'rolls-royce', 'harley-davidson'])}.com/{slug(SLUG_WORDS, 2)}",
    # real legitimate domains that contain digits
    lambda: f"https://www.{rng.choice(['7eleven.com.my', '99speedmart.com.my', '1utama.com.my', '3m.com', '9gag.com', 'mydin.com.my', 'ytl5g.com.my', 'web3.career', 'b2b.my', 'm1.com.sg', '24hoursclinic.com.my', 'mr-diy.com', 'kfc.com.my'])}/{slug(SLUG_WORDS, 2)}",
    lambda: f"https://www.maybank2u.com.my/maybank2u/malaysia/en/{rng.choice(['personal', 'business'])}/{slug(SLUG_WORDS, 3)}.page",
    # older legitimate sites still on plain http
    lambda: f"http://www.{rng.choice(['perpustakaan', 'koperasi', 'masjid', 'persatuan'])}{rng.choice(['negeri', 'daerah', 'kampung'])}.org.my/{slug(SLUG_WORDS, 2)}.html",
]

# Unknown-but-legitimate SME / small-business sites: prevents the model from
# learning "domain not famous = phishing".
SME_A = ['kedai', 'restoran', 'bengkel', 'klinik', 'butik', 'kopi', 'nasi', 'kek',
         'percetakan', 'hardware', 'tuisyen', 'dobi', 'kontraktor', 'pertanian',
         'tekstil', 'perabot', 'catering', 'travel', 'auto', 'solar']
SME_B = ['ahmad', 'siti', 'mesra', 'jaya', 'maju', 'gemilang', 'cemerlang', 'harmoni',
         'bestari', 'sentosa', 'murni', 'setia', 'aman', 'bintang', 'utama', 'perdana']
SME_TLD = ['com.my', 'com.my', 'my', 'com', 'net.my', 'com']


def legit_sme():
    name = rng.choice(SME_A) + rng.choice(['', '', '-']) + rng.choice(SME_B)
    if rng.random() < 0.2:  # Malaysian business names often carry lucky numbers
        name += rng.choice(['88', '99', '168', '2u', '1', '2020', '24'])
    host = ('www.' if rng.random() < 0.6 else '') + name + '.' + rng.choice(SME_TLD)
    path = rng.choice(['', '/', '/menu', '/hubungi-kami', '/produk/' + slug(SLUG_WORDS, 2),
                       '/shop/?product_id=' + str(rng.randint(1, 999)) + '&utm_source=facebook&utm_medium=social&utm_campaign=' + slug(SLUG_WORDS, 2),
                       '/blog/2026/' + slug(SLUG_WORDS, 5) + '/'])
    scheme = 'https' if rng.random() < 0.9 else 'http'
    return f"{scheme}://{host}{path}"


# ---------------------------------------------------------------------------
# PHISHING URL generators (documented real-world techniques)
# ---------------------------------------------------------------------------
BRANDS = ['maybank2u', 'maybank', 'm2u', 'cimbclicks', 'cimb', 'pbebank', 'publicbank',
          'rhb', 'hlb', 'bankislam', 'lhdn', 'hasil', 'kwsp', 'epf', 'jpj', 'poslaju',
          'jtexpress', 'jnt', 'shopee', 'lazada', 'grab', 'touchngo', 'tng', 'unifi',
          'netflix', 'spotify', 'icloud', 'apple', 'disneyplus', 'paypal', 'microsoft',
          'office365', 'outlook', 'google', 'gmail', 'facebook', 'instagram', 'whatsapp']
PHISH_WORDS = ['login', 'secure', 'verify', 'verification', 'update', 'account', 'akaun',
               'semakan', 'kemaskini', 'sahkan', 'bantuan', 'tuntut', 'claim', 'support',
               'auth', 'signin', 'wallet', 'billing', 'unlock', 'reset', 'confirm', 'service',
               'portal', 'online', 'web', 'help', 'my', 'my2u', 'rahmah', 'str', 'bonus',
               'hadiah', 'parcel', 'delivery', 'refund', 'cukai', 'security', 'alert']
BAD_TLDS = ['top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'icu', 'buzz', 'live',
            'online', 'site', 'shop', 'cyou', 'rest', 'sbs', 'info', 'vip', 'cc', 'pw',
            'club', 'monster', 'support', 'bond', 'cfd', 'win', 'quest']
COMMON_TLDS = ['com', 'net', 'org', 'my', 'co', 'com.my', 'app', 'me', 'io']
TYPO = {'maybank2u': ['maybamk2u', 'rnaybank2u', 'maybank2uu', 'mayb4nk2u', 'maybnk2u', 'maybank-2u'],
        'cimbclicks': ['cimbcliks', 'cimbclick', 'c1mbclicks', 'cimbclicsk'],
        'paypal': ['paypa1', 'paypall', 'paypai', 'paypa11'],
        'netflix': ['netfIix', 'netflx', 'neflix', 'netfliix'],
        'google': ['g00gle', 'gooogle', 'goog1e'],
        'shopee': ['sh0pee', 'shopeee', 'shoppee'],
        'facebook': ['faceb00k', 'facebok', 'facebo0k'],
        'microsoft': ['micros0ft', 'rnicrosoft', 'microsfot'],
        'spotify': ['spotlfy', 'sp0tify', 'spotifyy'],
        'lazada': ['lazadda', 'iazada', 'lazad4']}
SHORTENERS = ['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 't.ly', 'shorturl.at', 's.id',
              'is.gd', 'tiny.cc', 'rebrand.ly']
FREE_HOSTS = ['000webhostapp.com', 'weebly.com', 'wixsite.com', 'firebaseapp.com', 'web.app',
              'pages.dev', 'vercel.app', 'netlify.app', 'github.io', 'glitch.me',
              'square.site', 'ngrok-free.app', 'r2.dev', 'workers.dev']
PHISH_PATHS = ['', '/', '/login.php', '/index.html', '/secure/update/', '/m2u/login.do',
               '/verify', '/wp-includes/js/', '/wp-content/plugins/{r}/login.php',
               '/account/verify?id={r}', '/semakan/index.php?ic={d}',
               '/auth/signin?session={h}&redirect=home&lang=ms',
               '/{r}/{r}/{r}/index.php?email=user%40company.com.my&token={h}',
               '/claim/?ref={r}&utm_source=sms&utm_campaign={r}',
               '/billing/update/payment-method/?case={d}&sid={h}{h}']


def phish_path():
    p = rng.choice(PHISH_PATHS)
    return p.replace('{r}', rand_str(rng.randint(4, 10), string.ascii_lowercase + string.digits), 1) \
            .replace('{r}', rand_str(6), 1).replace('{r}', rand_str(5), 1) \
            .replace('{d}', str(rng.randint(10**5, 10**12))) \
            .replace('{h}', rand_hex(rng.randint(16, 40)))


def scheme():
    return 'https' if rng.random() < 0.6 else 'http'  # most phishing now uses TLS


def p_brand_hyphen():  # maybank2u-secure-login.top
    parts = [rng.choice(BRANDS)] + rng.sample(PHISH_WORDS, rng.randint(1, 2))
    rng.shuffle(parts)
    tld = rng.choice(BAD_TLDS) if rng.random() < 0.65 else rng.choice(COMMON_TLDS)
    sep = rng.choice(['-', '-', ''])
    sub = rng.choice(['', '', 'www.', 'secure.', 'm.', 'online.'])
    return f"{scheme()}://{sub}{sep.join(parts)}.{tld}{phish_path()}"


def p_brand_subdomain():  # www.maybank2u.com.my.verify-acc.xyz
    brand_host = rng.choice(['www.maybank2u.com.my', 'maybank2u.com.my', 'cimbclicks.com.my',
                             'www.hasil.gov.my', 'mytax.hasil.gov.my', 'secure.paypal.com',
                             'accounts.google.com', 'login.microsoftonline.com',
                             'shopee.com.my', 'appleid.apple.com', 'www.netflix.com',
                             'i-akaun.kwsp.gov.my', 'www.pos.com.my'])
    base = rand_str(rng.randint(4, 9), string.ascii_lowercase) + rng.choice(['', '-' + rng.choice(PHISH_WORDS)])
    tld = rng.choice(BAD_TLDS + COMMON_TLDS)
    return f"{scheme()}://{brand_host}.{base}.{tld}{phish_path()}"


def p_ip():
    ip = '.'.join(str(rng.randint(1, 254)) for _ in range(4))
    port = rng.choice(['', '', ':8080', ':8443'])
    return f"http://{ip}{port}/{rng.choice(BRANDS)}{phish_path()}"


def p_shortener():
    return f"{rng.choice(['https', 'http'])}://{rng.choice(SHORTENERS)}/{rand_str(rng.randint(5, 9))}"


def p_at_trick():
    fake = rng.choice(['www.maybank2u.com.my', 'cimbclicks.com.my', 'paypal.com', 'hasil.gov.my',
                       'accounts.google.com', 'shopee.com.my'])
    real = rand_str(rng.randint(5, 10), string.ascii_lowercase) + '.' + rng.choice(BAD_TLDS + COMMON_TLDS)
    return f"{scheme()}://{fake}@{real}{phish_path()}"


def p_typo():
    brand = rng.choice(list(TYPO))
    label = rng.choice(TYPO[brand])
    tld = rng.choice(['com', 'com.my', 'net', 'my', 'co', 'online', 'xyz', 'top'])
    return f"{scheme()}://{rng.choice(['', 'www.', 'secure.'])}{label}.{tld}{phish_path()}"


def p_free_host():
    label = '-'.join([rng.choice(BRANDS)] + rng.sample(PHISH_WORDS, rng.randint(0, 2)))
    if rng.random() < 0.3:
        label += str(rng.randint(1, 999))
    return f"https://{label}.{rng.choice(FREE_HOSTS)}{phish_path()}"


def p_punycode():
    return f"{scheme()}://xn--{rand_str(rng.randint(5, 10), string.ascii_lowercase)}-{rand_str(4, string.ascii_lowercase + string.digits)}.{rng.choice(COMMON_TLDS + BAD_TLDS)}{phish_path()}"


def p_random_domain():  # throwaway domains like a8f3k2q.top/login.php
    label = rand_str(rng.randint(6, 14), string.ascii_lowercase + string.digits)
    return f"{scheme()}://{label}.{rng.choice(BAD_TLDS)}{phish_path()}"


def p_compromised_site():
    """Hard case: phishing kit uploaded to a hacked ordinary SME site."""
    host = rng.choice(SME_A) + rng.choice(SME_B) + '.' + rng.choice(SME_TLD)
    return f"{scheme()}://{host}/wp-content/uploads/{rng.choice(BRANDS)}/{rng.choice(PHISH_WORDS)}/index.php?{rand_hex(20)}"


PHISH_GENERATORS = [(p_brand_hyphen, 26), (p_brand_subdomain, 12), (p_ip, 7), (p_shortener, 8),
                    (p_at_trick, 5), (p_typo, 12), (p_free_host, 10), (p_punycode, 4),
                    (p_random_domain, 11), (p_compromised_site, 5)]


def email_csv_urls():
    """Phishing URLs that appear in the provided email CSVs."""
    import re
    found = set()
    ddir = os.path.dirname(OUT)
    for name in EMAIL_CSVS:
        path = os.path.join(ddir, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding='utf-8') as fh:
            for row in csv.DictReader(fh):
                if row.get('label') == 'phishing':
                    for u in re.findall(r'https?://\S+', row['text']):
                        found.add(u.rstrip('.,'))
    return sorted(found)


def main(n_per_class=3000):
    rows, seen = [], set()

    def add(url, label, source):
        if url not in seen:
            seen.add(url)
            rows.append((url, 'legit' if label == 'legit' else 'malicious',
                         'legit' if label == 'legit' else 'phishing', 'synthetic_' + source))

    for u in email_csv_urls():
        add(u, 'phishing', 'email_csv')
    count = lambda lab: sum(1 for r in rows if r[1] == lab)

    sme_quota = int(n_per_class * 0.2)
    while sum(1 for r in rows if r[3] == 'synthetic_legit_sme') < sme_quota:
        add(legit_sme(), 'legit', 'legit_sme')
    while count('legit') < n_per_class:
        add(rng.choice(LEGIT_TEMPLATES)(), 'legit', 'legit_official')

    gens, weights = zip(*PHISH_GENERATORS)
    while count('malicious') < n_per_class:
        g = rng.choices(gens, weights)[0]
        add(g(), 'phishing', 'phish_' + g.__name__[2:])

    rng.shuffle(rows)
    with open(OUT, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['url', 'label', 'category', 'source'])
        w.writerows(rows)
    print(f"Wrote {len(rows)} URLs to {OUT}")


if __name__ == '__main__':
    main()
