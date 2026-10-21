# 🔍 OSINT URL Scanner

A self-hosted URL threat and security scanner that runs **100% locally — no third-party APIs, no
accounts, no API keys.** You give it a URL (or an email, a QR code, or a list) and it returns two
independent verdicts, with every point of the score traced back to concrete evidence and a fix.

![Offline](https://img.shields.io/badge/APIs-none%20required-35c892)
![Python](https://img.shields.io/badge/Python-3.9%2B-4f8fe0)
![License](https://img.shields.io/badge/license-MIT-7c6cf0)

> For authorized security research, incident response and education only. Active checks require you
> to confirm you are authorized to probe the target.

---

## Why it's different

Most "URL checkers" just forward your link to VirusTotal or urlscan.io. That **makes your URL public**
— which can tip off an attacker that they've been caught — and gives you a single opaque score.
This scanner is built the opposite way:

| | This scanner | VirusTotal / urlscan.io | securityheaders.com |
|---|:---:|:---:|:---:|
| URL stays private (nothing uploaded) | ✅ | ❌ (submissions are public) | ⚠️ |
| Works offline / air-gapped | ✅ | ❌ | ❌ |
| Separate **threat** vs **hardening** verdicts | ✅ | ❌ | hardening only |
| Every point explained with evidence + fix | ✅ | ❌ | ⚠️ |
| Homograph / typosquat / combosquat detection | ✅ | partial | ❌ |
| Cloaking detection (crawler vs browser) | ✅ | ⚠️ | ❌ |
| OSINT pivots (analytics IDs, favicon hash, wallets) | ✅ | ⚠️ | ❌ |
| Scan history + diff (monitoring) | ✅ | ⚠️ | ❌ |
| Email (.eml) & QR-code input | ✅ | ❌ | ❌ |

### Two verdicts, not one
- **Threat risk (0–100)** — is this phishing/malicious? Signals combine probabilistically
  (`risk = 100·(1 − Π(1 − wᵢ))`), so no single weak signal dominates and the score never runs away.
- **Security posture (A+…F)** — how well is the site hardened (headers, TLS, cookies, DNS)?

---

## What it checks

**Passive (default — only connects to the URL you enter):**
- **URL structure** — IDN **homograph** attacks, **typosquats**, **combosquats**, brand names hidden in
  subdomains/paths, `@`-userinfo tricks, raw-IP hosts, high-entropy (DGA-like) domains, abused TLDs,
  URL shorteners, free-hosting platforms.
- **TLS** — trust chain, expiry, **certificate age**, self-signed/hostname-mismatch, weak keys, SHA-1,
  Certificate Transparency, and which protocols (TLS 1.0–1.3) and weak cipher families the server accepts.
- **DNS & email** — A/AAAA/CNAME/MX/NS/CAA, SPF/DMARC/DNSSEC, reverse DNS, fast-flux heuristics.
- **Domain age** — WHOIS over port 43 (no web API); newly registered domains are a strong phishing signal.
- **Security headers** — deep grading of CSP, HSTS, cookies, CORS (with an origin-reflection probe), and more.
- **Redirects** — full hop chain, HTTPS→HTTP downgrades, open-redirect parameters, meta/JS redirects, and
  **cloaking** (serving crawlers different content than browsers).
- **Page content** — credential forms posting off-site, brand-impersonating logins, hidden iframes,
  obfuscated JavaScript, tech-support-scam text, cryptominers, wallet-drainers, seed-phrase prompts.
- **OSINT pivots** — shared analytics/ad IDs, emails, phone numbers, social links, crypto wallet
  addresses, and a Shodan-compatible **favicon hash** for manual pivoting.
- **Tech stack** — ~70 technologies fingerprinted locally, flagged against end-of-life / known-vulnerable versions.
- **Subdomain takeover** — dangling CNAMEs to unclaimed cloud services.
- **security.txt & robots.txt** — RFC 9116 vulnerability-disclosure file (Contact/Expires), and
  sensitive-looking paths named in robots.txt (reported only, never requested).
- **Offline threat feeds** — match against any blocklists you drop into `scanner/data/blocklists/`.
- **File analysis** — for downloads: hashes (MD5/SHA-1/SHA-256), known-bad hash lists, executables disguised as documents, PE imports and packed sections, macros (including legacy .doc/.xls and auto-run macros) and double extensions in archives, active PDF content, and optional YARA rules. Nothing is executed or written to disk.
- **Engines** — every result shows how many local engines (each check, plus each feed file you add) flagged the URL, for example `2 of 8`.

**Active (opt-in, authorized targets only):**
- **Port scan** of common ports with banner grabbing (replaces the old Shodan dependency).

**Browser sandbox (optional):**
- Headless Chromium renders the page like a real visitor: screenshot, JS-redirect tracking, contacted
  domains/trackers, drive-by download detection, and a **visual phishing match** (perceptual hash of the
  screenshot vs. genuine login pages). Every request the page makes is still SSRF-checked.

---

## Install & run

```bash
git clone https://github.com/Adomancer/URLscanner.git
cd URLscanner
pip install -r requirements.txt

# Web UI
python webapp.py                 # http://127.0.0.1:5000

# Command line
python cli.py scan https://example.com
```

No `.env` or API keys are required. Optional settings (all have safe defaults) go in a `.env` file:

```ini
SECRET_KEY=change-me            # auto-generated & persisted if omitted
FLASK_DEBUG=0
SCANNER_HTTP_TIMEOUT=10
SCANNER_ACCESS_TOKEN=           # set to require a token for the web UI and API (recommended for Docker)
SCANNER_WEB_ACTIVE=0            # 1 = allow port scans from the web UI (the CLI is always available)
SCANNER_TRUST_PROXY=0           # 1 = take the client IP from X-Forwarded-For (only behind your own proxy)
```

### Optional extras

```bash
# Browser sandbox (screenshots, JS redirects, visual phishing match)
pip install -r requirements-browser.txt
python -m playwright install chromium

# QR-code (quishing) input
pip install -r requirements-qr.txt
```

---

## CLI

```bash
python cli.py scan <url|file> [--browser] [--active --i-am-authorized] \
                              [--format json,csv,html,md,sarif] [--out DIR] [--fail-on 50] [-v]
python cli.py extract message.eml --scan      # pull & scan every link in an email
python cli.py extract qr.png                  # read a URL out of a QR code
python cli.py history [filter]                # recent scans
python cli.py diff https://site.test          # compare the two most recent scans
python cli.py add-brand-ref https://www.paypal.com/signin PayPal   # capture a visual reference
```

`--fail-on` makes the process exit non-zero when any risk score is at or above the threshold, so the
scanner can gate CI. Use `--format sarif` to surface findings in code-scanning dashboards.

---

## How privacy & safety are handled

- **Nothing leaves your machine** except the ordinary connection to the target itself and the standard
  DNS (53) / WHOIS (43) protocols. No URL is sent to any analysis service.
- **SSRF-hardened.** Every address (including each redirect hop and every request the headless browser
  makes) must be globally routable; loopback, RFC1918, link-local, CGNAT and cloud-metadata ranges are
  refused, and the real peer address is re-checked after connect to defeat DNS rebinding.
- **Active checks are gated.** The port scan only runs when you pass `--active --i-am-authorized`
  (CLI). The web UI hides it unless `SCANNER_WEB_ACTIVE=1`, and then still asks you to confirm authorization.
- **Optional access token.** With `SCANNER_ACCESS_TOKEN` set, every page needs a sign-in and every API call
  needs `Authorization: Bearer <token>`.
- **Browser sandbox limits.** HTTP(S) and WebSocket requests from the page are checked before they leave,
  but Chromium resolves DNS itself, so a DNS-rebinding page could still switch addresses between the check
  and the connection. Run `--browser` scans in a container or VM without access to your internal network.
- Reports show **defanged** URLs (`hxxp`, `[.]`) so they're safe to paste into tickets and chats.

---

## Offline blocklists

Drop any plain-text threat feeds (URLhaus, OpenPhish, your own IOC lists) into
`scanner/data/blocklists/*.txt`. They load locally and are matched by URL, host, domain and IP. See
the README in that folder for accepted formats.

---

## Project layout

```
scanner/
  core.py          orchestrator (normalize → run checks in parallel → score → store)
  net.py           SSRF-safe fetching & resolution
  scoring.py       threat risk + posture grade
  extract.py       refang, .eml and QR-code input
  report.py        JSON / CSV / HTML / Markdown / SARIF output + diff
  storage.py       SQLite history & WHOIS cache
  checks/          one module per check (lexical, tls, dns, whois, headers, …)
  data/            bundled offline datasets (brands, confusables, signatures, …)
templates/ static/ the web UI (no CDN — works offline)
tools/             build-time helpers (favicon hashes, top-domain list)
tests/             pytest suite
```

Run the tests with `pip install pytest && python -m pytest`.

## Docker

```bash
docker build -t url-scanner .
docker run -p 5000:5000 -v urlscanner-data:/app/outputs -e SCANNER_ACCESS_TOKEN=change-me url-scanner
```

Runs the web UI with gunicorn as a non-root user. The container listens on all interfaces, so set
`SCANNER_ACCESS_TOKEN` unless only you can reach port 5000. `.dockerignore` keeps `.env`, `outputs/` and
the scan database out of the image.

## License

MIT — for educational and authorized security use.
