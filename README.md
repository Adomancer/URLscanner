# 🔍 OSINT URL Scanner

OSINT URL Scanner is a Python + Flask based application for analyzing a list of URLs for security purposes.
This tool is designed for cybersecurity investigation and research activities for _educational purpose only_.

![Badge](https://img.shields.io/badge/Powered%20By-Flask-blue)
![Badge](https://img.shields.io/badge/Scan-Shodan%20%2B%20VirusTotal-green)
![Badge](https://img.shields.io/badge/UI-TailwindCSS-38B2AC)

---

## 🚀 Features

- ✅ Input URLs one by one via web interface
- ✅ Check HTTP headers and detect missing security headers:
- `X-Frame-Options`
- `Content-Security-Policy`
- `Referrer-Policy`
- ✅ Check suspicious redirects
- ✅ IP lookup via Shodan API
- ✅ Domain reputation with VirusTotal API
- ✅ Export results to `.csv` and `.json`
- ✅ Web Interface with Tailwind CSS
- ✅ URL input validation and sanitization
- ✅ Safe fallback when Shodan/VirusTotal errors

---

## 🗂️ Project Structure

```
url-scanner/
├── scanner/
│ ├── core.py # Main scan_url() function
│ ├── utils.py # Helper functions: IP resolving, validators
│ ├── shodan.py # Shodan API integration
│ └── virustotal.py # VirusTotal API integration
├── templates/
│ └── index.html # Web UI interface
├── static/
│ └── tailwind.css # Styling with Tailwind
├── outputs/ # (Optional) Export results
├── .env # Save API key (DO NOT upload to GitHub)
├── .gitignore
├── requirements.txt
├── webapp.py # Main Flask app
└── README.md
```

---

## ⚙️ Installing & Running

1. Clone this repo:
```bash
git clone https://github.com/yourusername/osint-url-scanner.git
cd osint-url-scanner
```

2. Create and populate `.env`:
```
SHODAN_API_KEY=your_shodan_api_key
VT_API_KEY=your_virustotal_api_key
SECRET_KEY=your_flask_secret_key
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run Flask:
```bash
python webapp.py
```

---

## 🧪 Example URL for Testing

- https://www.google.com/
- https://example.com/
- https://malware.testing.google.test/testing/malware/

---

## 📦 Export

- Export scan results to file: 
- `outputs/report.json` 
- `outputs/report.csv`

---

## 🔒 Notes Security

- All inputs are validated using `validators`
- API Key is stored securely in `.env` file
- Fallback friendly if API error (Shodan/VirusTotal)
- Use only for educational purposes & legal research

---

## 📜 License

MIT License — free to use for educational purposes.

---

## 📅 Last Updated

2025-06-26