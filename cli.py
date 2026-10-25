#!/usr/bin/env python3
"""Command-line interface for the OSINT URL Scanner.

Examples:
  python cli.py scan https://example.com
  python cli.py scan inputs/urls.txt --format html,sarif --out outputs/
  python cli.py scan https://site.test --active --i-am-authorized --browser
  python cli.py extract phishing.eml --scan
  python cli.py history            # recent scans
  python cli.py diff https://site.test
  python cli.py add-brand-ref https://www.paypal.com/signin PayPal
  python cli.py gmail scan --days 7          # score your Gmail; links are never opened
  python cli.py gmail watch                  # keep checking new mail
"""
import argparse
import os
import sys

for _stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import config
from scanner import report, storage
from scanner.core import scan_many, scan_url
from scanner.extract import decode_qr, extract_urls, parse_eml, qr_available
from scanner.utils import defang

SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


def _color(txt, code):
    return f"{code}{txt}{RESET}" if sys.stdout.isatty() else str(txt)


def _verdict_color(v):
    return {"Malicious": "\033[91m", "Likely malicious": "\033[91m", "Suspicious": "\033[93m",
            "Clean": "\033[92m"}.get(v, "\033[90m")


def read_targets(arg):
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8", errors="replace") as f:
            text = f.read()
        urls = extract_urls(text) or [ln.strip() for ln in text.splitlines() if ln.strip()
                                       and not ln.startswith("#")]
        return urls
    return [arg]


def print_result(r, verbose=False):
    print()
    print(f"  {_color('●', _verdict_color(r['verdict']))} {defang(r['url'])}")
    if r.get("error"):
        print(f"    {_color('Error: ' + r['error'], SEV_COLOR['high'])}")
        return
    vc = _verdict_color(r["verdict"])
    posture = f"{r['grade']} ({r['posture_score']}/100)" if r.get("posture_score") is not None else "n/a"
    threat = f"{r['verdict']} — {r['risk_score']}/100"
    print(f"    Threat:  {_color(threat, vc)}")
    print(f"    Posture: {posture}")
    if r.get("final_url") and r["final_url"] != r["url"]:
        print(f"    Final:   {defang(r['final_url'])}")
    if r.get("ips"):
        print(f"    IP:      {', '.join(r['ips'][:4])}")
    det = r.get("detections")
    if det:
        print(f"    Engines: {det['flagged']} of {det['total']} flagged")
    fl = r.get("sections", {}).get("file", {})
    if fl.get("show"):
        print(f"    File:    {fl.get('name') or '-'} · {fl['type']} · {fl['size']} bytes · sha256 {(fl.get('sha256') or 'n/a')[:16]}…")
    counts = {}
    for f in r["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if counts:
        print("    " + "  ".join(_color(f"{k}:{v}", SEV_COLOR[k]) for k, v in counts.items() if k in SEV_COLOR))
    shown = r["findings"] if verbose else [f for f in r["findings"] if f["severity"] in ("critical", "high", "medium")]
    for f in shown:
        print(f"      {_color('•', SEV_COLOR.get(f['severity'], ''))} [{f['severity']}] {f['title']}")
        if verbose and f.get("evidence"):
            print(f"          {f['evidence']}")
    if not verbose and len(r["findings"]) > len(shown):
        print(f"      … and {len(r['findings']) - len(shown)} lower-severity finding(s); use -v to see all")


def write_outputs(results, formats, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for fmt in formats:
        ext = report.EXT[fmt]
        if fmt in report._MULTI or (fmt == "json" and len(results) > 1):
            # one combined file: CSV/SARIF take a list, JSON becomes an array
            path = os.path.join(out_dir, f"scan_report.{ext}")
            with open(path, "w", encoding="utf-8") as f:
                f.write(report.render(fmt, results))
            written.append(path)
            continue
        for r in results:  # HTML / Markdown are per-target documents
            name = (r.get("registered_domain") or "scan").replace(":", "_") + f"_{r['id']}.{ext}"
            path = os.path.join(out_dir, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(report.render(fmt, r))
            written.append(path)
    return written


def cmd_scan(args):
    targets = []
    for a in args.target:
        targets.extend(read_targets(a))
    targets = list(dict.fromkeys(targets))
    if not targets:
        print("No URLs found in input.", file=sys.stderr)
        return 2
    if args.active and not args.i_am_authorized:
        print("Refusing to run active checks without --i-am-authorized "
              "(only scan systems you own or have written permission to test).", file=sys.stderr)
        return 2
    print(f"Scanning {len(targets)} URL(s)…", file=sys.stderr)
    kwargs = dict(active=args.active, authorized=args.i_am_authorized, browser=args.browser, store=not args.no_store)
    if len(targets) == 1:
        results = [scan_url(targets[0], **kwargs)]
    else:
        results = scan_many(targets, workers=args.workers, **kwargs)
    for r in results:
        print_result(r, args.verbose)
    if args.format:
        formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
        bad = [f for f in formats if f not in report.FORMATTERS]
        if bad:
            print(f"Unknown format(s): {', '.join(bad)}", file=sys.stderr)
            return 2
        written = write_outputs(results, formats, args.out)
        print(f"\nWrote: {', '.join(written)}", file=sys.stderr)
    worst = max((r.get("risk_score") or 0) for r in results)
    print(f"\nHighest threat risk: {worst}/100", file=sys.stderr)
    if args.fail_on is not None and worst >= args.fail_on:
        return 1
    return 0


def _mail_verdict_color(v):
    return {"Dangerous": "\033[91m", "Suspicious": "\033[93m", "Low risk": "\033[94m",
            "No signals found": "\033[92m"}.get(v, "\033[90m")


def print_email(r, verbose=False):
    """One analysed e-mail (scanner.mail result; URLs in it are already redacted)."""
    vc = _mail_verdict_color(r.get("verdict"))
    print()
    print(f"  {_color('●', vc)} {r.get('subject') or '(no subject)'}")
    print(f"    From:    {r.get('from') or '-'}")
    if r.get("error"):
        print(f"    {_color('Error: ' + r['error'], SEV_COLOR['high'])}")
        return
    print(f"    Verdict: {_color(str(r['verdict']) + ' — ' + str(r['risk_score']) + '/100', vc)}"
          + ("  (allow-listed sender: never labelled)" if r.get("allowlisted") else ""))
    a = r.get("auth_info") or {}
    how = "verified by Gmail" if a.get("verified") else "unverified"
    print(f"    Auth:    SPF={a.get('spf') or '?'} DKIM={a.get('dkim') or '?'} DMARC={a.get('dmarc') or '?'} ({how})")
    shown = r["findings"] if verbose else [f for f in r["findings"] if f["weight"] >= 0.1][:8]
    for f in shown:
        print(f"      {_color('•', SEV_COLOR.get(f['severity'], ''))} [{f['severity']}] {f['title']}")
        if verbose and f.get("evidence"):
            print(f"          {f['evidence']}")
    if r.get("links"):
        print(f"    Links ({len(r['links'])}; opened: {sum(1 for l in r['links'] if l['mode'] == 'deep')}):")
        for l in r["links"] if verbose else r["links"][:10]:
            risk = "-" if l.get("risk_score") is None else l["risk_score"]
            tags = [t for t, on in (("from QR", l["source"] == "qr"), ("in attachment", l["source"] == "attachment"),
                                    ("one-time link?", l.get("token_like"))) if on]
            print(f"      {l['n']:>2}. [{l['mode']:<7}] {str(l['verdict']):<16} {risk:>3}  {defang(l['url'])}"
                  + (f"  ({', '.join(tags)})" if tags else ""))
    for n in r.get("notes") or []:
        print(f"    {_color('note: ' + n, SEV_COLOR['info'])}")


def cmd_extract(args):
    path = args.file
    data = open(path, "rb").read()
    urls = []
    is_eml = path.lower().endswith(".eml") or data[:5] in (b"From ", b"Retur", b"Date:", b"Deliv")
    if is_eml and args.scan:
        # whole-message analysis; links are only looked at passively (never opened)
        from scanner.mail.pipeline import persist, scan_message
        r = scan_message(data, trusted_source=False, network=args.network)
        print_email(r, args.verbose)
        if not r.get("error"):
            persist(r)
        print("\nLinks were analysed passively (not opened). Auth results in an uploaded file cannot be "
              "verified.", file=sys.stderr)
        return 0
    if is_eml:
        info = parse_eml(data)
        print(f"Subject: {info['subject']}")
        print(f"From:    {info['from']}")
        print(f"Auth:    SPF={info['auth']['spf'] or '?'} DKIM={info['auth']['dkim'] or '?'} "
              f"DMARC={info['auth']['dmarc'] or '?'}")
        for w in info["warnings"]:
            print(f"  {_color('⚠ ' + w, SEV_COLOR['high'])}")
        print(f"\n{len(info['links'])} link(s):")
        for l in info["links"]:
            flag = _color("  ⚠ text/href mismatch", SEV_COLOR["high"]) if l["mismatch"] else ""
            print(f"  {defang(l['url'])}{flag}")
            urls.append(l["url"])
    elif path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
        if not qr_available():
            print("QR decoding needs: pip install -r requirements-qr.txt", file=sys.stderr)
            return 2
        found = decode_qr(data)
        if not found:
            print("No QR code found.", file=sys.stderr)
            return 1
        for v in found:
            print(f"QR: {v}")
        urls = [u for v in found for u in extract_urls(v)] or [v for v in found if "://" in v]
    else:
        urls = extract_urls(data.decode("utf-8", "replace"))
        for u in urls:
            print(defang(u))
    if args.scan and urls:
        print(f"\nScanning {len(urls)} extracted URL(s)…", file=sys.stderr)
        for r in scan_many(urls, workers=args.workers):
            print_result(r, args.verbose)
    return 0


def _gmail_source():
    from scanner.mail.imap_source import ImapSource
    return ImapSource()


def _gmail_errors(fn):
    def wrapper(args):
        from scanner.mail.imap_source import ImapError
        try:
            return fn(args)
        except ImapError as e:
            print(f"Gmail: {e}", file=sys.stderr)
            return 2
    return wrapper


@_gmail_errors
def cmd_gmail_test(args):
    with _gmail_source() as src:
        folders = src.folders()
        _, uids = src.search(src.resolve_folder("inbox"), since_days=7)
        print(f"Logged in as {src.address} (IMAP, read-only).")
        for key in ("inbox", "spam", "all"):
            print(f"  {key:<6} {folders.get(key) or _color('not visible over IMAP', SEV_COLOR['high'])}")
        print(f"  {len(uids)} message(s) in the inbox from the last 7 days.")
    return 0


def _print_summary(summary):
    print(f"\n{summary['folder']}: {summary['found']} found, {summary['scanned']} analysed, "
          f"{summary['skipped']} skipped, {summary['errors']} failed.")
    for v in ("Dangerous", "Suspicious", "Low risk", "No signals found"):
        if summary["verdicts"].get(v):
            print(f"  {_color(f'{v:<17}', _mail_verdict_color(v))} {summary['verdicts'][v]}")
    if summary["label_errors"]:
        print(_color(f"  {summary['label_errors']} label(s) could not be applied (see `gmail list`).",
                     SEV_COLOR["high"]))


@_gmail_errors
def cmd_gmail_scan(args):
    from scanner.mail.runner import scan_inbox

    def show(r, item):
        if args.all or r.get("verdict") in ("Suspicious", "Dangerous"):
            print_email(r, args.verbose)
            print(f"    id: {item.msgid}")

    with _gmail_source() as src:
        print(f"Scanning {args.folder} of {src.address} (last {args.days} day(s)); links are analysed "
              f"passively, never opened.", file=sys.stderr)
        summary = scan_inbox(src, folder=args.folder, days=args.days, unread=args.unread, limit=args.limit,
                             rescan=args.rescan, label=not args.no_label, network=args.network, on_result=show)
    _print_summary(summary)
    return 1 if summary["verdicts"].get("Dangerous") else 0


@_gmail_errors
def cmd_gmail_deep(args):
    from scanner.mail.runner import TokenLinkRefused, deep_scan
    print(_color("Deep scan opens the selected links from THIS computer: the sites will see your IP address and "
                 "the full link, including any token in it. A VPN hides your IP, nothing more.",
                 SEV_COLOR["high"]), file=sys.stderr)
    links = set(args.url) if args.url else None
    with _gmail_source() as src:
        try:
            r = deep_scan(src, args.msgid, links=links, allow_token_links=args.yes_token_link,
                          label=not args.no_label, network=args.network)
        except TokenLinkRefused as e:
            print("Refusing: these links look like one-time links (password reset, login, unsubscribe...) and "
                  "opening them may use up the real token:", file=sys.stderr)
            for l in e.links:
                print(f"  {l['n']:>2}. {defang(l['url'])}", file=sys.stderr)
            print("Choose other links with --url N, or confirm with --yes-token-link.", file=sys.stderr)
            return 2
    print_email(r, args.verbose)
    return 0


@_gmail_errors
def cmd_gmail_watch(args):
    import logging
    from scanner.mail.runner import watch
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")

    def show(r, item):
        if r.get("verdict") in ("Suspicious", "Dangerous") or args.verbose:
            print_email(r)
            print(f"    id: {item.msgid}")

    def err(e):
        print(f"Gmail: {e} (retrying)", file=sys.stderr)

    print(f"Watching {args.folder} every {args.interval}s (Ctrl+C to stop). Links are never opened.",
          file=sys.stderr)
    try:
        watch(_gmail_source, args.folder, interval=args.interval, label=not args.no_label, network=args.network,
              on_result=show, on_error=err)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2
    return 0


def cmd_gmail_list(args):
    import datetime as dt
    rows = storage.list_emails(limit=args.limit, verdict=args.verdict or "")
    if not rows:
        print("No e-mails scanned yet.")
        return 0
    print(f"{'RECEIVED':<17} {'RISK':>4} {'VERDICT':<17} {'LABEL':<22} FROM / SUBJECT")
    for r in rows:
        when = dt.datetime.fromtimestamp(r["received_at"] or r["scanned_at"]).strftime("%Y-%m-%d %H:%M")
        v = _color(f"{r['verdict'] or '-':<17}", _mail_verdict_color(r["verdict"]))
        label = r["label_applied"] or (_color("error", SEV_COLOR["high"]) if r["label_error"] else "-")
        print(f"{when:<17} {r['risk_score'] if r['risk_score'] is not None else '-':>4} {v} {label:<22} "
              f"{r['from_addr']} / {r['subject'][:60]}")
        if args.verbose:
            print(f"{'':<17} id {r['msgid']}" + (f"  label error: {r['label_error']}" if r["label_error"] else ""))
    return 0


def cmd_gmail_eval(args):
    """Detection quality on a hand-labelled set: <dir>/phishing/*.eml and <dir>/legit/*.eml."""
    from scanner.mail.pipeline import scan_message
    stats = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    wrong = []
    for truth in ("phishing", "legit"):
        folder = os.path.join(args.dir, truth)
        if not os.path.isdir(folder):
            print(f"Missing folder: {folder}", file=sys.stderr)
            return 2
        for name in sorted(os.listdir(folder)):
            if not name.lower().endswith(".eml"):
                continue
            with open(os.path.join(folder, name), "rb") as f:
                r = scan_message(f.read(), trusted_source=args.trust_auth, network=args.network)
            flagged = r.get("verdict") in ("Suspicious", "Dangerous")
            key = ("tp" if flagged else "fn") if truth == "phishing" else ("fp" if flagged else "tn")
            stats[key] += 1
            if key in ("fn", "fp"):
                wrong.append((key, name, r.get("verdict"), r.get("risk_score"),
                              ", ".join(x["title"] for x in (r.get("reasons") or [])[:2])))
    tp, fn, fp, tn = stats["tp"], stats["fn"], stats["fp"], stats["tn"]
    print(f"phishing: {tp + fn} (caught {tp}, missed {fn})   legit: {fp + tn} (false alarms {fp})")
    if tp + fp:
        print(f"precision {tp / (tp + fp):.0%}", end="   ")
    if tp + fn:
        print(f"recall {tp / (tp + fn):.0%}", end="   ")
    if fp + tn:
        print(f"false-positive rate {fp / (fp + tn):.0%}", end="")
    print()
    for key, name, verdict, risk, why in wrong:
        print(f"  {'MISSED' if key == 'fn' else 'FALSE ALARM':<11} {name}: {verdict} {risk} {why}")
    return 0


def cmd_history(args):
    rows = storage.list_scans(limit=args.limit, query=args.query or "")
    if not rows:
        print("No scans recorded yet.")
        return 0
    print(f"{'WHEN':<20} {'RISK':>4} {'GRADE':<5} {'VERDICT':<17} URL")
    import datetime as dt
    for r in rows:
        when = dt.datetime.fromtimestamp(r["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        v = _color(f"{r['verdict'] or r['status']:<17}", _verdict_color(r["verdict"] or ""))
        risk = "-" if r["risk_score"] is None else str(r["risk_score"])
        print(f"{when:<20} {risk:>4} {r['grade'] or '-':<5} {v} {defang(r['url'])}")
    return 0


def cmd_diff(args):
    rows = storage.latest_scans_for(args.url, 2)
    if len(rows) < 2:
        print("Need at least two completed scans of this exact URL to diff.", file=sys.stderr)
        return 1
    d = report.diff(rows[1]["result"], rows[0]["result"])
    print(f"Diff for {defang(args.url)}")
    print(f"  {d['old_at']}  →  {d['new_at']}\n")
    if d["changed"]:
        print("Changed:")
        for c in d["changed"]:
            print(f"  {c['field']}: {c['old']} → {c['new']}")
    if d["added"]:
        print(_color("\nNew findings:", SEV_COLOR["high"]))
        for f in d["added"]:
            print(f"  + [{f['severity']}] {f['title']}")
    if d["resolved"]:
        print(_color("\nResolved findings:", "\033[92m"))
        for f in d["resolved"]:
            print(f"  - [{f['severity']}] {f['title']}")
    if not (d["changed"] or d["added"] or d["resolved"]):
        print("No changes.")
    return 0


def cmd_add_brand_ref(args):
    from scanner.checks.sandbox import available, dhash, render
    if not available():
        print("The browser sandbox is required: pip install -r requirements-browser.txt", file=sys.stderr)
        return 2
    import json
    r = render(args.url)
    if not r["screenshot"]:
        print("Could not capture a screenshot.", file=sys.stderr)
        return 1
    os.makedirs(os.path.join("scanner", "data", "brand_refs"), exist_ok=True)
    out = os.path.join("scanner", "data", "brand_refs", f"{args.brand.lower().replace(' ', '_')}.json")
    existing = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else []
    existing.append({"brand": args.brand, "url": args.url, "dhash": dhash(r["screenshot"])})
    json.dump(existing, open(out, "w", encoding="utf-8"), indent=2)
    print(f"Saved visual reference for {args.brand} → {out}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="url-scanner", description="OSINT URL Scanner — offline, no API keys.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan one or more URLs (or a file of URLs)")
    s.add_argument("target", nargs="+", help="URL(s) or path to a .txt file of URLs")
    s.add_argument("--active", action="store_true", help="run active checks (port scan) — needs --i-am-authorized")
    s.add_argument("--i-am-authorized", action="store_true", help="confirm you are authorised to actively probe the target")
    s.add_argument("--browser", action="store_true", help="render in a headless browser sandbox (needs Playwright)")
    s.add_argument("--format", help="comma-separated: json,csv,html,md,sarif")
    s.add_argument("--out", default=config.OUTPUT_DIR, help="output directory for reports")
    s.add_argument("--workers", type=int, default=6, help="parallel scans for multiple URLs")
    s.add_argument("--fail-on", type=int, metavar="RISK", help="exit non-zero if any risk score >= RISK (for CI)")
    s.add_argument("--no-store", action="store_true", help="do not save to the history database")
    s.add_argument("-v", "--verbose", action="store_true", help="show every finding with evidence")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("extract", help="extract URLs from text, .eml e-mail, or a QR-code image")
    e.add_argument("file", help="path to a .txt / .eml / image file")
    e.add_argument("--scan", action="store_true",
                   help="scan the extracted URLs (for an .eml: score the whole message; links are not opened)")
    e.add_argument("--network", choices=("dns", "none"), default=config.MAIL_NETWORK,
                   help="for .eml: 'none' makes no network connection at all (default: %(default)s)")
    e.add_argument("--workers", type=int, default=6)
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(func=cmd_extract)

    h = sub.add_parser("history", help="list recent scans")
    h.add_argument("query", nargs="?", help="filter by URL/host substring")
    h.add_argument("--limit", type=int, default=50)
    h.set_defaults(func=cmd_history)

    d = sub.add_parser("diff", help="compare the two most recent scans of a URL")
    d.add_argument("url", help="exact URL as previously scanned")
    d.set_defaults(func=cmd_diff)

    b = sub.add_parser("add-brand-ref", help="capture a genuine login page as a visual phishing reference")
    b.add_argument("url")
    b.add_argument("brand")
    b.set_defaults(func=cmd_add_brand_ref)

    g = sub.add_parser("gmail", help="scan your Gmail (IMAP + App Password, read-only; links are never opened)")
    gsub = g.add_subparsers(dest="gmail_command", required=True)
    net_help = "'none' = no network connection at all during analysis (default: %(default)s)"

    gt = gsub.add_parser("test", help="check the login and show which folders are visible")
    gt.set_defaults(func=cmd_gmail_test)

    gs = gsub.add_parser("scan", help="analyse recent messages and label suspicious ones")
    gs.add_argument("--days", type=int, default=7)
    gs.add_argument("--folder", default="inbox", help="inbox, spam, all, or a Gmail label name")
    gs.add_argument("--unread", action="store_true", help="only unread messages (they stay unread)")
    gs.add_argument("--limit", type=int, default=200, help="at most this many messages (newest first)")
    gs.add_argument("--rescan", action="store_true", help="also re-analyse messages scanned before")
    gs.add_argument("--no-label", action="store_true", help="read-only: do not add URLscanner/* labels")
    gs.add_argument("--network", choices=("dns", "none"), default=config.MAIL_NETWORK, help=net_help)
    gs.add_argument("--all", action="store_true", help="print every message, not only flagged ones")
    gs.add_argument("-v", "--verbose", action="store_true")
    gs.set_defaults(func=cmd_gmail_scan)

    gd = gsub.add_parser("deep", help="open the links of ONE message (only when you ask; sites see your IP)")
    gd.add_argument("msgid", help="message id shown by `gmail scan` / `gmail list -v`")
    gd.add_argument("--url", type=int, action="append", metavar="N", help="only link number N (repeatable)")
    gd.add_argument("--yes-token-link", action="store_true",
                    help="also open links that look like one-time links (may use up a real token)")
    gd.add_argument("--no-label", action="store_true")
    gd.add_argument("--network", choices=("dns", "none"), default=config.MAIL_NETWORK, help=net_help)
    gd.add_argument("-v", "--verbose", action="store_true")
    gd.set_defaults(func=cmd_gmail_deep)

    gw = gsub.add_parser("watch", help="keep checking for new mail; Windows toast for dangerous messages")
    gw.add_argument("--folder", default="inbox")
    gw.add_argument("--interval", type=int, default=300, help="seconds between checks (default: %(default)s)")
    gw.add_argument("--no-label", action="store_true")
    gw.add_argument("--network", choices=("dns", "none"), default=config.MAIL_NETWORK, help=net_help)
    gw.add_argument("-v", "--verbose", action="store_true")
    gw.set_defaults(func=cmd_gmail_watch)

    gl = gsub.add_parser("list", help="list scanned e-mails from the local database")
    gl.add_argument("--verdict", choices=("Dangerous", "Suspicious", "Low risk", "No signals found"))
    gl.add_argument("--limit", type=int, default=50)
    gl.add_argument("-v", "--verbose", action="store_true", help="also show message ids and label errors")
    gl.set_defaults(func=cmd_gmail_list)

    ge = gsub.add_parser("eval", help="measure detection on hand-labelled .eml files (phishing/ and legit/)")
    ge.add_argument("dir", nargs="?", default=os.path.join(config.OUTPUT_DIR, "labeled"))
    ge.add_argument("--trust-auth", action="store_true",
                    help="treat the files' Gmail auth headers as verified (your own exports from Gmail)")
    ge.add_argument("--network", choices=("dns", "none"), default="none", help=net_help)
    ge.set_defaults(func=cmd_gmail_eval)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError as e:
        print(f"File not found: {e.filename}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
