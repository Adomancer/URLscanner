# 🔍 OSINT URL Scanner

OSINT URL Scanner adalah aplikasi berbasis Python + Flask untuk menganalisis daftar URL dari sisi keamanan.  
Alat ini dirancang untuk kegiatan investigasi dan riset keamanan siber secara _educational purpose only_.

![Badge](https://img.shields.io/badge/Powered%20By-Flask-blue)
![Badge](https://img.shields.io/badge/Scan-Shodan%20%2B%20VirusTotal-green)
![Badge](https://img.shields.io/badge/UI-TailwindCSS-38B2AC)

---

## 🚀 Fitur

- ✅ Input URL satu per satu melalui antarmuka web
- ✅ Cek HTTP headers dan deteksi header keamanan yang hilang:
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `Referrer-Policy`
- ✅ Cek redirect mencurigakan
- ✅ Lookup IP melalui Shodan API
- ✅ Reputasi domain dengan VirusTotal API
- ✅ Export hasil ke format `.csv` dan `.json`
- ✅ Antarmuka Web dengan Tailwind CSS
- ✅ Validasi dan sanitasi input URL
- ✅ Fallback aman saat Shodan/VirusTotal error

---

## 🗂️ Struktur Proyek

```
url-scanner/
├── scanner/
│   ├── core.py           # Fungsi utama scan_url()
│   ├── utils.py          # Fungsi bantu: IP resolving, validators
│   ├── shodan.py         # Integrasi API Shodan
│   └── virustotal.py     # Integrasi API VirusTotal
├── templates/
│   └── index.html        # Tampilan UI web
├── static/
│   └── tailwind.css      # Styling dengan Tailwind
├── outputs/              # (Optional) Hasil export
├── .env                  # Simpan API key (JANGAN upload ke GitHub)
├── .gitignore
├── requirements.txt
├── webapp.py             # Main Flask app
└── README.md
```

---

## ⚙️ Instalasi & Menjalankan

1. Clone repo ini:
```bash
git clone https://github.com/yourusername/osint-url-scanner.git
cd osint-url-scanner
```

2. Buat dan isi `.env`:
```
SHODAN_API_KEY=your_shodan_api_key
VT_API_KEY=your_virustotal_api_key
SECRET_KEY=your_flask_secret_key
```

3. Install dependency:
```bash
pip install -r requirements.txt
```

4. Jalankan Flask:
```bash
python webapp.py
```

---

## 🧪 Contoh URL untuk Testing

- https://www.google.com/
- https://example.com/
- https://malware.testing.google.test/testing/malware/

---

## 📦 Ekspor

- Export hasil scan ke file:
  - `outputs/report.json`
  - `outputs/report.csv`

---

## 🔒 Catatan Keamanan

- Semua input divalidasi menggunakan `validators`
- API Key disimpan aman di file `.env`
- Fallback friendly jika API error (Shodan/VirusTotal)
- Gunakan hanya untuk tujuan edukatif & riset legal

---

## 📜 Lisensi

MIT License — bebas digunakan untuk tujuan edukatif.

---

## 📅 Terakhir Diperbarui

2025-06-26
