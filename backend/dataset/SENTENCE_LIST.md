# Dataset Sentence List

All sentences in the three email CSVs, collapsed into templates.
`{brand}`, `{amount}`, `{URL}` etc. are placeholders. The full rows (12,400) are in the
`TRAINING_DATASET` table of `cybersentry.db`.

URLs are shown in short form: the `http://` prefix is dropped, since it is the same for all of them.

## Phishing URLs used in the data (4 in total)

| Short form | Rows |
|---|---|
| `verify-identity.com` | 809 |
| `login-secure-web.net` | 794 |
| `bit.ly/kemaskini-akaun-2026` | 742 |
| `semakan-lhdn-gov.top` | 755 |

---

## 1. `train_data.csv` + `test_data.csv` (8 phishing + 8 legit templates)

`test_data.csv` uses exactly the same templates as `train_data.csv`.

### Phishing

| # | Template | Rows |
|---|---|---|
| P1 | Amaran: Percubaan log masuk dikesan pada akaun {brand} anda. Jika bukan anda, klik {URL}. | 437 |
| P2 | Akses portal SAPS anda akan ditamatkan dalam masa 24 jam. Sila log masuk di {URL} untuk rayuan. | 402 |
| P3 | Notis LHDN: Anda mempunyai tunggakan cukai sebanyak RM{amount}. Sila bayar segera di {URL}. | 394 |
| P4 | Tahniah! Anda terpilih memenangi hadiah RM{amount} dari {brand}. Klik {URL} untuk tuntut. | 389 |
| P5 | Tindakan segera diperlukan! Akaun {brand} anda telah disekat. Sila sahkan identiti di {URL}. | 384 |
| P6 | Kurier {brand}: Penghantaran bungkusan anda gagal. Sila bayar kos penghantaran semula di {URL}. | 383 |
| P7 | Peringatan: Langganan {brand} anda gagal diperbaharui. Kemaskini kad kredit anda di {URL}. | 362 |
| P8 | Bantuan Tunai Rahmah: Semak status kelayakan RM{amount} anda di pautan rasmi ini {URL}. | 349 |

### Legitimate

| # | Template | Rows |
|---|---|---|
| L1 | Makluman: Gangguan bekalan air di kawasan {area} dijangka pulih pada jam {time}. | 429 |
| L2 | Penyata akaun bulanan anda bagi bulan {month} kini boleh dimuat turun di portal rasmi. | 410 |
| L3 | Resit rasmi bagi transaksi TXN{id} berjaya diproses. Sila simpan untuk rujukan masa hadapan. | 394 |
| L4 | Sila hantar laporan mingguan bagi projek Pembangunan Sistem IoT sebelum hari Jumaat ini. | 390 |
| L5 | Terima kasih kerana menggunakan perkhidmatan {brand}. Sila berikan maklum balas anda di sini. | 382 |
| L6 | Pengesahan pendaftaran: Anda telah berjaya mendaftar untuk kursus Cybersecurity Forensics di portal UniSZA. | 375 |
| L7 | Notis: Penyelenggaraan sistem E-Daftar akan dijalankan pada malam ini dari jam {time} hingga {time}. | 363 |
| L8 | Peringatan mesyuarat: Perbincangan mengenai {topic} akan diadakan pada Jumaat jam {time}. | 357 |

**Placeholder values**

- `{brand}`: Bank Islam, CIMB Clicks, Disney+ Hotstar, Grab, Hong Leong Connect, iCloud, J&T Express, Lazada, Maybank2u, Netflix, Pos Laju, Public Bank, RHB Now, Shopee, Spotify, Touch 'n Go, Unifi
- `{area}`: Besut, Gong Badak, Johor Bahru, Kuala Lumpur, Kuala Terengganu
- `{topic}`: Digital Marketing, Final Year Project, Latihan Industri, SecurityX Training
- `{month}`: Januari to Jun

---

## 2. `emails_cleaned.csv` (built as *opener*, *body* *closer*)

Every sentence is `"{Opener}, {body} {closer}."`, for example:
*"Akaun anda berisiko digodam, kemas kini kata laluan sekarang untuk keselamatan akaun anda."*

### Phishing parts
- **Openers:** Akaun anda berisiko digodam · Amaran keselamatan dikesan pada akaun anda · Makluman keselamatan penting daripada sistem · SEGERA akaun anda akan disekat · Tindakan segera diperlukan untuk elak sekatan · Akses akaun anda akan ditamatkan · Pengesahan akaun diperlukan segera
- **Bodies:** login segera untuk pengesahan · tekan link untuk elakkan sekatan · sila klik pautan di bawah · kemas kini kata laluan sekarang · sahkan maklumat peribadi anda

### Legitimate parts
- **Openers:** Terima kasih atas kerjasama pihak tuan puan · Permohonan anda sedang diproses oleh pihak kami · Emel ini dihantar untuk tujuan rujukan rasmi · Makluman rasmi berkaitan urusan pentadbiran · Maklumat ini adalah pemberitahuan rasmi · Notis penting daripada pihak pengurusan syarikat · Pihak kami ingin memaklumkan perkara berikut
- **Bodies:** tiada tindakan lanjut diperlukan · maklumat ini adalah untuk simpanan · sila ambil maklum perkara berikut · sila simpan emel ini untuk rujukan · sila rujuk lampiran yang disertakan

### Shared closers (used by both classes)
untuk keselamatan akaun anda · dalam tempoh 24 jam · mengikut rekod sistem kami · untuk tindakan selanjutnya · bagi mengelakkan gangguan perkhidmatan

### Data-quality notes
- Some rows start with the prefix `perhatian`. Others have shuffled word order (e.g. *"Notis penting pihak daripada pengurusan syarikat"*) as augmentation.
- About 7% of rows have a label that contradicts their content (e.g. *"SEGERA akaun anda akan disekat, login segera untuk pengesahan…"* labelled `legit`).
- 231 identical sentences appear with **both** labels. `train_model.py` resolves these by majority vote.
- This file contains **no URLs**.
