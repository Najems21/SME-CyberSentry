"""
End-to-end scenario test for the /scan engine: SAFE, MEDIUM and HIGH-RISK sites.

    python backend/test_scan_scenarios.py

* Runs against a temporary COPY of cybersentry.db (your forensic logs are untouched)
  with the default 70% risk threshold.
* No connection is ever made to a malicious site: certificate checks are
  stubbed, except for cases marked live=True, which only contact well-known
  safe sites and badssl.com (a public service built for testing TLS errors).
"""
import os
import shutil
import sqlite3
import sys
import tempfile

BACKEND = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND)
import app as A  # noqa: E402
from threat_rules import verify_tls as real_verify_tls  # noqa: E402

VALID_TLS = {'checked': True, 'valid': True, 'issuer': 'stub', 'age_days': 40, 'days_left': 50}

DL = lambda name, ref: {'filename': rf'C:\Users\user\Downloads\{name}', 'url': ref.split('?')[0] + '/dl/' + name,
                        'referrer': ref, 'danger': 'safe', 'mime': 'application/octet-stream'}

JTP = "https://jtp-photography.com/worldpage/indexw.php?cost=0.001099&country=MY&zoneid=10491721"
JTP_TEXT = ("Videos, plugin files. Resources ready to download. Download started! The free download has "
            "started automatically. If the download does not start automatically, click here. "
            "© 2026 Free videos and plugin resources.")
BINTV_TEXT = ("BINTV Live Upcoming API. LIVE Live TV. Willow Cricket. Watch Willow Cricket live 24/7 for "
              "free in HD. No sign-up, no subscription, just press play. Watch Now")

# (name, expected, url, text, signals, live_tls)
CASES = [
    # ------------------------------------------------------------- SAFE
    ("Gmail inbox (screenshot 1)", "Safe",
     "https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox/FMfcgzQjgznkFzWtPgsxkCJgZfLcVNWS",
     "Inbox 7,741 Starred Snoozed Sent Drafts. Sign in to. Click the button below to finish signing in in 10 minutes.",
     {}, True),
    ("Google search, long URL", "Safe",
     "https://www.google.com/search?q=cara+bayar+cukai+lhdn+online&oq=cara+bayar&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQRRhA0gEIMzQ1N2owajSoAgCwAgE&sourceid=chrome&ie=UTF-8",
     "Cara bayar cukai LHDN secara online melalui MyTax. Panduan lengkap.", {}, True),
    ("Shopee product, very long URL", "Safe",
     "https://shopee.com.my/Baju-Kurung-Moden-Premium-Cotton-Raya-2026-i.123456789.987654321?sp_atk=0a1b2c3d-4e5f-6789-abcd-ef0123456789&xptdk=0a1b2c3d",
     "Baju Kurung Moden. Tambah ke troli. Penghantaran percuma untuk pesanan melebihi RM30.", {}, True),
    ("Maybank2u login (official)", "Safe", "https://www.maybank2u.com.my/home/m2u/common/login.do",
     "Maybank2u. Login to Maybank2u. Username. Never share your TAC with anyone.",
     {'password_fields': 1, 'form_actions': ['https://www.maybank2u.com.my/home/m2u/common/login.do'], 'protocol': 'https:'}, True),
    ("LHDN MyTax", "Safe", "https://mytax.hasil.gov.my/", "MyTax. Portal rasmi Lembaga Hasil Dalam Negeri Malaysia.", {}, True),
    ("Wikipedia article", "Safe", "https://en.wikipedia.org/wiki/Online_gambling",
     "Online gambling is any kind of gambling conducted on the internet, including online casino, sports betting and slot machine games.", {}, True),
    ("ESPN cricket (legit sports)", "Safe", "https://www.espn.com/cricket/",
     "Live cricket scores, news and highlights. Watch live on ESPN+ with a subscription. India vs Australia match report.", {}, False),
    ("The Star - 4D results news", "Safe", "https://www.thestar.com.my/news/nation/2026/11/18/keputusan-4d",
     "Keputusan 4D Magnum, Da Ma Cai dan Sports Toto hari ini. Berita terkini Malaysia.", {}, False),
    ("7-Zip download page (exe links)", "Safe", "https://www.7-zip.org/download.html",
     "Download 7-Zip 24.08 for Windows. Link Type Windows Size.",
     {'exe_links': ['https://www.7-zip.org/a/7z2408-x64.exe', 'https://www.7-zip.org/a/7z2408.exe']}, False),
    ("GitHub release with .exe (trusted)", "Safe", "https://github.com/notepad-plus-plus/notepad-plus-plus/releases",
     "Notepad++ v8.7 release. Assets npp.8.7.Installer.x64.exe",
     {'exe_links': ['https://github.com/x/releases/download/v8.7/npp.8.7.Installer.x64.exe']}, True),
    ("Unknown SME kopitiam site", "Safe", "https://kedaikopimesra.com.my/menu",
     "Menu kami. Nasi lemak ayam goreng RM8. Sila hubungi kami untuk tempahan katering.", {}, False),
    ("TNB notice (Malay legit)", "Safe", "https://www.tnb.com.my/notis",
     "Makluman: Gangguan bekalan elektrik di kawasan Besut dijangka pulih pada jam 5 PM. Terima kasih atas kerjasama pihak tuan puan.", {}, False),
    ("badssl.com valid certificate", "Safe", "https://badssl.com/", "badssl.com test page", {}, True),

    # ------------------------------------------------------------- MEDIUM
    ("Gmail showing a Malay scam email", "Medium Risk", "https://mail.google.com/mail/u/0/#inbox/FMfcgzABC",
     "Tindakan segera diperlukan! Akaun Maybank2u anda telah disekat. Sila sahkan identiti di http://bit.ly/x.", {}, False),
    ("Unknown forum page mentioning mega888", "Medium Risk", "https://forum.carigold.com/threads/5123456",
     "Anyone tried mega888? My friend lost money, is it a scam?", {}, False),
    ("Unknown site started a PDF download", "Medium Risk", "https://jadual-sekolah-2026.com.my/muat-turun",
     "Jadual waktu sekolah 2026.", {'downloads': [DL('jadual.pdf', 'https://jadual-sekolah-2026.com.my/muat-turun')]}, False),

    # ------------------------------------------------------------- HIGH RISK
    ("jtp-photography auto-download (screenshot 2)", "Danger", JTP, JTP_TEXT,
     {'downloads': [DL('VideoPlayer_Setup.exe', JTP)]}, False),
    ("jtp-photography, text + URL only", "Danger", JTP, JTP_TEXT, {}, False),
    ("bintv.cc free cricket streaming (screenshot 3)", "Danger", "https://www.bintv.cc/", BINTV_TEXT, {}, False),
    ("Unknown streaming site, not in any list", "Danger", "https://nontonbola-live88.xyz/",
     "Nonton bola live free! EPL Man United vs Arsenal live stream free in HD, no registration. Watch now.", {}, False),
    ("Gambling site (Malay)", "Danger", "https://win88my-slot.com/",
     "Mega888 & 918Kiss slot online. Free kredit RM10, min deposit RM10. Live casino, sportsbook. Daftar sekarang!", {}, False),
    ("Listed gambling domain (no gambling words)", "Danger", "https://188micro.com/", "Welcome", {}, False),
    ("Listed piracy domain", "Danger", "https://cineby.fun/", "Movies", {}, False),
    ("OpenPhish: Shopee lucky-draw on Blogspot", "Danger", "https://www.undian-hadiahshopee33.blogspot.com/",
     "Tahniah! Anda terpilih memenangi hadiah dari Shopee. Klik untuk tuntut.", {}, False),
    ("Fake LHDN (Bantuan Tunai)", "Danger", "http://semakan-lhdn-gov.top/",
     "Bantuan Tunai Rahmah: Semak status kelayakan RM2000 anda di pautan rasmi ini.", {}, False),
    ("Maybank typosquat login", "Danger", "https://rnaybank2u.com/login", "Maybank2u Login Username Password",
     {'password_fields': 1, 'form_actions': ['https://collect-data.xyz/p.php'], 'protocol': 'https:'}, False),
    ("IP-address CIMB login over HTTP", "Danger", "http://103.21.44.9/cimb/login.php", "CIMB Clicks Login",
     {'password_fields': 1, 'protocol': 'http:'}, False),
    ("Fake virus alert (tech support scam)", "Danger", "https://secure-pc-check.online/alert",
     "Windows Defender Alert! Your computer is infected with 3 viruses. Call Microsoft Support now.", {}, False),
    ("'Click Allow' notification scam", "Danger", "https://robotcheck-7731.click/",
     "Click Allow if you are not a robot. Press Allow to verify.", {}, False),
    ("Malay scam text on unknown site", "Danger", "https://promo-hebat.com/",
     "Akaun anda berisiko digodam, sila klik pautan di bawah dalam tempoh 24 jam. Sahkan maklumat peribadi anda sekarang.", {}, False),
    ("Expired certificate (badssl)", "Danger", "https://expired.badssl.com/", "expired", {}, True),
    ("Self-signed certificate (badssl)", "Danger", "https://self-signed.badssl.com/", "self-signed", {}, True),
    ("Wrong-host certificate (badssl)", "Danger", "https://wrong.host.badssl.com/", "wrong host", {}, True),
]


def main():
    tmpdir = tempfile.mkdtemp()
    tmp_db = os.path.join(tmpdir, 'cybersentry_test.db')
    shutil.copy(A.DB_PATH, tmp_db)
    with sqlite3.connect(tmp_db) as c:
        c.execute("UPDATE USER_SETTINGS SET Risk_Threshold = 70 WHERE Setting_ID = 1")
        c.execute("DELETE FROM USER_ALLOWLIST")
    A.DB_PATH = tmp_db
    client = A.app.test_client()

    passed, rows = 0, []
    for name, expected, url, text, signals, live in CASES:
        A.verify_tls = (lambda host, **k: real_verify_tls(host, timeout=10)) if live else (lambda host, **k: VALID_TLS)
        r = client.post('/scan', json={'url': url, 'text': text, 'signals': signals}).get_json()
        ok = r['status'] == expected
        passed += ok
        rows.append((ok, name, expected, r))

    for ok, name, expected, r in rows:
        mark = 'PASS' if ok else 'FAIL'
        https = r.get('https', {})
        tls = ('valid' if https.get('valid') else https.get('error', 'not checked')) if https.get('scheme') == 'https' else 'http'
        print(f"[{mark}] {name:46s} expected={expected:11s} got={r['status']:11s} {r['risk_score']:5.1f}%  "
              f"type={r.get('category', '-'):28s} url={r.get('url_score', 0):5.1f} text={r.get('text_score', 0):5.1f} "
              f"rules={r.get('rule_score', 0):5.1f} tls={tls}")
        if not ok or r['status'] != 'Safe':
            for reason in (r.get('reasons') or [])[:3]:
                print(f"         - {reason[:150]}")
    print(f"\n{passed}/{len(CASES)} scenarios passed")
    shutil.rmtree(tmpdir, ignore_errors=True)
    return passed == len(CASES)


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
