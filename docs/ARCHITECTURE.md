# Architecture

How the scanner is put together, for anyone extending it.

## Layout

```
cli.py                command line (scan, extract, history, diff, gmail …)
webapp.py             Flask web UI + JSON API (background thread pool, CSRF, optional token)
config.py             every setting, read from the environment / .env
scanner/
  core.py             scan_url(): normalise → resolve → run checks in stages → score → store
  checks/             one module per check, registered with @check(...)
  scoring.py          threat risk, posture grade, correlation rules, "engines" count
  net.py              SSRF-safe DNS resolution and HTTP fetching
  extract.py          refang, URL extraction, .eml parsing, redirect unwrapping, QR decoding
  filescan.py         static file analysis (PE, OLE, ZIP, PDF, scripts, hashes, YARA)
  report.py           JSON / CSV / HTML / Markdown / SARIF output and scan diffs
  storage.py          SQLite: scans, batches, e-mails, WHOIS cache, mail state, jobs
  data/               bundled offline datasets (brands, lists, confusables, signatures …)
  mail/               the e-mail / Gmail scanner (see below)
templates/ static/    web UI: no CDN, no external fonts; works fully offline
tools/                helpers run by hand (threat-feed download, top domains, favicon hashes)
tests/                pytest; no test touches the network
```

## A URL scan

`scanner.core.scan_url(url, …)`

1. **Normalise.** Refang, add a scheme, IDNA-encode the host, and accept only http/https.
2. **Resolve.** `net.resolve_public` refuses private, loopback, link-local, CGNAT and cloud-metadata
   addresses (SSRF guard). Skipped in passive mode.
3. **Run checks in three stages**, each stage in parallel:
   - stage 1 is independent: HTTP, TLS, DNS, WHOIS, lexical;
   - stage 2 uses stage-1 data: headers, redirects, OSINT, tech, takeover, feeds, ports, sandbox;
   - stage 3 is page content, including the sandbox-rendered DOM.

   A check that raises is recorded as an error and never breaks the scan.
4. **Correlate, deduplicate, score.** Then count how many local "engines" flagged the URL.
5. **Store** the result in SQLite, unless `store=False`.

### Checks

```python
from scanner.checks import check
from scanner.models import Section

@check("mycheck", "My check", stage=2, requires="http", passive=False)
def run(ctx):                      # ctx: ScanContext (url, host, registered_domain, ips, fetch, sections …)
    s = Section()
    s.data["something"] = 42       # shown in reports
    s.flag("mycheck.bad", "Something bad", "high", weight=0.3, evidence="…", fix="…")
    return s
```

Then import the module in `checks/__init__.py:load_all()`. The decorator arguments:

- `requires="resolved"` or `"http"` skips the check when DNS or the fetch failed.
- `active=True` makes it opt-in and authorised-only (the port scan).
- `browser=True` makes it need Playwright.
- `passive=True` declares that the check never contacts the target host. Only these checks run for links
  found in e-mail.

### Scoring

- A finding's **weight** (0–1) feeds the threat risk: `risk = 100 · (1 − Π(1 − wᵢ))`, with each weight
  capped at 0.97. On well-known domains, non-critical weights are multiplied by 0.25. "Abused platforms"
  where anyone can publish (Google Forms, OneDrive shares …) never get this dampening.
- A finding's **penalty** (points) lowers the posture score: `100 − Σ penalties`, then graded A+…F.
- **Correlation rules** add findings for combinations, for example a look-alike domain together with a login
  form.
- **Passive scans** report *Unverified* instead of *Clean* below 20, because the site was never contacted.

### Network safety

`net.safe_fetch` re-checks every redirect hop against the SSRF guard. A connection-level guard (`_PeerGuard`)
also re-checks the IP actually connected to, which defeats DNS rebinding. Proxies from the environment are
ignored. Responses are capped in size, redirects and time.

## The e-mail scanner (`scanner/mail/`)

```
imap_source.py   ImapSource: read-only Gmail access (EXAMINE + BODY.PEEK[]), labels on a separate connection
pipeline.py      scan_message(raw) → parse → collect URLs → passive link scans → attachments → analyse → redact
analyze.py       analyze_email(): pure scoring of one message (no network, no database)
redact.py        Redactor: masks URL query values / token-like path parts in everything that is stored
runner.py        scan_inbox, deep_scan, watch (UIDVALIDITY-aware state, file lock, reconnect backoff)
notify.py        Windows toast; attacker-controlled text passed only through environment variables
limits.py        per-message budgets (size, attachments, URLs, 60 s time budget)
```

`scan_message` works through one message in these steps:

1. **Parse** with `extract.parse_eml(include_payloads=True, trusted_source=…)`. Only the *topmost*
   `Authentication-Results` header is used, and it counts as verified only if `mx.google.com` wrote it and
   the message came straight from Gmail.
2. **Collect URLs** from HTML and text links, unwrapped redirectors (Google, SafeLinks, Proofpoint …), HTML
   and PDF attachments, and QR codes in images. They are deduplicated, and untrusted URLs come first, up to
   30.
3. **Scan every URL** with `scan_url(passive=True)` in a thread pool under the message's time budget. The
   sender's domain is scanned the same way. A deep scan only happens when the user explicitly asked for it.
4. **Analyse attachments statically** with `filescan`, plus HTML analysis for `.html`/`.svg` files.
5. **Score** with `analyze_email` (verdicts: Dangerous ≥ 70, Suspicious ≥ 35, Low risk ≥ 10).
6. **Redact.** Every original URL and its secrets are collected, and the whole result is rewritten before
   anything is returned, stored, exported or logged.

`persist()` then stores the message in one transaction. It writes a `batches` row (the redacted summary), one
`scans` row per link scan, and upserts the `emails` row keyed by Gmail's `X-GM-MSGID`.

## Database (SQLite, WAL mode)

| Table | Holds |
|---|---|
| `scans` | every URL scan: status, verdict, risk, grade, full result JSON, optional `batch_id` |
| `batches` | a group of scans (bulk submission or one e-mail) + metadata such as the e-mail summary |
| `emails` | one row per Gmail message: verdict, label state, latest batch, redacted result |
| `mail_state` | per account/folder `UIDVALIDITY` + last processed UID, used by `gmail watch` |
| `jobs` | the single background Gmail job, so every gunicorn worker agrees on its state |
| `whois_cache` | WHOIS answers, 24 h |

## Tests

```bash
pip install pytest && python -m pytest
```

Tests never touch the network:

- IMAP runs against an in-memory fake Gmail server (`tests/test_mail_imap.py`);
- passive scanning is proven not to contact the target by monkeypatching every network entry point
  (`tests/test_mail_analyze.py`);
- the web tests check the access-token, Host-header and CSRF guards, and that attacker-controlled text is
  escaped.
