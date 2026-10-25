#!/usr/bin/env python3
"""Download public phishing / malware URL feeds into scanner/data/blocklists/ for offline matching.

    python tools/update_feeds.py            # all feeds
    python tools/update_feeds.py openphish  # just one

Bulk downloads only: the scanner never sends a URL from your mail to anyone; it compares links against
these local files. Run it now and then (or from Windows Task Scheduler); the scanner picks up changed
files automatically. Feed files are git-ignored: their licences (e.g. OpenPhish: personal use, no
redistribution) do not allow committing them.

URLhaus (abuse.ch) needs a free Auth-Key (abuse.ch account -> profile -> Auth-Key): put
ABUSECH_AUTH_KEY=... in .env. Without it that feed is skipped. The key goes into the download URL, so
it is never printed or written to the feed file.
"""
import csv
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config                  # noqa: E402  (loads .env)
from scanner import data, net  # noqa: E402

FEEDS = {
    "openphish": {"url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
                  "file": "openphish.txt", "about": "OpenPhish community feed (phishing; personal use only)"},
    "urlhaus": {"url": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", "file": "urlhaus.txt",
                "about": "URLhaus malware URLs, last 30 days (abuse.ch)", "key_env": "ABUSECH_AUTH_KEY"},
}
MAX_BYTES = 64 * 1024 * 1024


def _entries(text):
    """URLs from a plain list or a CSV export (the first http(s) field of each row)."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#"):
            continue
        url = next((c.strip() for c in row if c.strip().lower().startswith(("http://", "https://"))), "")
        if url:
            out.append(url)
    return list(dict.fromkeys(out))


def update(name, feed):
    key = ""
    if feed.get("key_env"):
        key = os.getenv(feed["key_env"], "").strip()
        if not key:
            return f"skipped: needs a free Auth-Key; set {feed['key_env']} in .env"
    url = feed["url"].replace("{key}", key)

    def scrub(s):
        return s.replace(key, "***") if key else s

    try:
        r = net.safe_fetch(url, headers={"Accept": "text/plain, text/csv"}, max_bytes=MAX_BYTES, timeout=60,
                           max_redirects=3)
    except Exception as e:
        return f"failed: {type(e).__name__}: {scrub(str(e))[:120]}"
    if r.status in (401, 403):
        return f"failed: HTTP {r.status} (check {feed.get('key_env') or 'access'})"
    if r.status != 200:
        return f"failed: HTTP {r.status}"
    if r.truncated:
        return "failed: feed larger than the download limit"
    entries = _entries(r.text)
    if not entries:
        return "failed: no URLs in the response (not updated)"
    os.makedirs(data.BLOCKLIST_DIR, exist_ok=True)
    target = os.path.join(data.BLOCKLIST_DIR, feed["file"])
    fd, tmp = tempfile.mkstemp(dir=data.BLOCKLIST_DIR, prefix=f".{name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# {feed['about']}\n# source: {feed['url'].replace('{key}', '<key>')}\n")
            f.write("\n".join(entries) + "\n")
        os.replace(tmp, target)  # atomic: a scan never sees a half-written file
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return f"{len(entries):,} URLs -> {os.path.relpath(target)}"


def main(argv):
    names = argv or list(FEEDS)
    bad = [n for n in names if n not in FEEDS]
    if bad:
        print(f"Unknown feed(s): {', '.join(bad)}. Available: {', '.join(FEEDS)}", file=sys.stderr)
        return 2
    failed = 0
    for n in names:
        msg = update(n, FEEDS[n])
        failed += msg.startswith(("failed", "skipped"))
        print(f"{n:<10} {msg}")
    return 1 if failed == len(names) else 0


if __name__ == "__main__":
    _ = config  # imported for its side effect of reading .env
    sys.exit(main(sys.argv[1:]))
