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


def cmd_extract(args):
    path = args.file
    data = open(path, "rb").read()
    urls = []
    if path.lower().endswith(".eml") or data[:5] in (b"From ", b"Retur", b"Date:", b"Deliv"):
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
    e.add_argument("--scan", action="store_true", help="scan the extracted URLs")
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
