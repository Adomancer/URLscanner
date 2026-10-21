"""Output formats: JSON, flattened CSV, a plain standalone HTML report, Markdown and SARIF 2.1.0."""
import csv
import html
import io
import json

from . import __version__
from .utils import defang


def to_json(result, indent=2):
    return json.dumps(result, indent=indent, default=str)


def _flat_row(r):
    sec = r.get("sections", {})
    counts = {}
    for f in r.get("findings", []):
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    det = r.get("detections") or {}
    return {
        "url": r.get("url", ""),
        "final_url": r.get("final_url", ""),
        "verdict": r.get("verdict", ""),
        "risk_score": r.get("risk_score", ""),
        "grade": r.get("grade", ""),
        "posture_score": r.get("posture_score", ""),
        "engines_flagged": f"{det.get('flagged', 0)}/{det.get('total', 0)}" if det else "",
        "status_code": r.get("status_code", ""),
        "ips": ";".join(r.get("ips", [])),
        "registered_domain": r.get("registered_domain", ""),
        "domain_age_days": sec.get("whois", {}).get("age_days", ""),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "top_findings": " | ".join(x["title"] for x in r.get("reasons", [])[:5]),
        "error": r.get("error") or "",
        "scanned_at": r.get("started_at", ""),
    }


def to_csv(results):
    if isinstance(results, dict):
        results = [results]
    rows = [_flat_row(r) for r in results]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else ["url"])
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def to_markdown(result):
    r = result
    out = ["# URL scan report", "", f"**Target:** `{defang(r.get('url', ''))}`  "]
    if r.get("final_url") and r["final_url"] != r["url"]:
        out.append(f"**Final URL:** `{defang(r['final_url'])}`  ")
    out.append(f"**Scanned:** {r.get('started_at', '')}  ")
    if r.get("error"):
        out += ["", f"Error: {r['error']}"]
        return "\n".join(out)
    det = r.get("detections") or {}
    posture = f"{r['grade']}" + (f" ({r['posture_score']}/100)" if r.get("posture_score") is not None else "")
    out += ["", f"**Threat risk:** {r['risk_score']}/100 ({r['verdict']})  ",
            f"**Posture:** {posture}  ",
            f"**Engines flagged:** {det.get('flagged', 0)} of {det.get('total', 0)}  "]
    if r.get("ips"):
        out.append(f"**IP:** {', '.join(r['ips'])}  ")
    out += ["", "## Findings", ""]
    if not r.get("findings"):
        out.append("No findings.")
    for f in r.get("findings", []):
        out.append(f"- [{f['severity']}] {f['title']} ({f['axis']})")
        if f.get("evidence"):
            out.append(f"  - Evidence: `{f['evidence']}`")
        if f.get("recommendation"):
            out.append(f"  - Fix: {f['recommendation']}")
    return "\n".join(out)


def to_sarif(results):
    """SARIF 2.1.0 so findings can gate CI / show up in code-scanning dashboards."""
    if isinstance(results, dict):
        results = [results]
    rules, rule_ids, sarif_results = [], set(), []
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for r in results:
        loc = r.get("url", "")
        for f in r.get("findings", []):
            rid = f["id"].split(".")[0] + "/" + f["id"]
            if rid not in rule_ids:
                rule_ids.add(rid)
                rules.append({"id": rid, "name": f["id"], "shortDescription": {"text": f["title"]},
                              "fullDescription": {"text": f.get("recommendation") or f["title"]},
                              "defaultConfiguration": {"level": level.get(f["severity"], "note")},
                              "properties": {"category": f.get("category", ""), "axis": f["axis"]}})
            sarif_results.append({
                "ruleId": rid,
                "level": level.get(f["severity"], "note"),
                "message": {"text": f["title"] + (f" — {f['evidence']}" if f.get("evidence") else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc}}}],
                "properties": {"weight": f.get("weight", 0), "penalty": f.get("penalty", 0),
                               "severity": f["severity"]},
            })
    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OSINT URL Scanner", "version": __version__,
                                "informationUri": "https://github.com/Adomancer/URLscanner",
                                "rules": rules}},
            "results": sarif_results,
        }],
    }, indent=2)


_REPORT_CSS = (
    "body{font:15px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif;max-width:720px;margin:40px auto;"
    "padding:0 16px;color:#141414;background:#fff}"
    "h1{font-size:18px;font-weight:600;margin:0 0 4px;word-break:break-all}"
    "h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#6b6b6b;margin:32px 0 8px}"
    "table{width:100%;border-collapse:collapse;font-size:14px}"
    "td,th{text-align:left;vertical-align:top;padding:8px 12px 8px 0;border-bottom:1px solid #e4e4e4}"
    "th{font-weight:500;color:#6b6b6b;width:30%}"
    ".mono{font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all}"
    ".mut{color:#6b6b6b}"
    ".sev{font-size:12px;font-weight:600;text-transform:uppercase;white-space:nowrap}"
    "@media(prefers-color-scheme:dark){body{background:#121212;color:#ececec}td,th{border-color:#2c2c2c}"
    ".mut,h2,th{color:#8f8f8f}}"
)


def to_html(result):
    """Standalone report with no external assets; prints cleanly."""
    r = result
    e = html.escape
    title = e(r.get("registered_domain") or r.get("url", ""))
    head = (f"<!doctype html><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{title} · scan report</title><style>{_REPORT_CSS}</style>")
    body = [f"<h1>{e(defang(r.get('url', '')))}</h1>",
            f"<p class='mut'>{e(r.get('started_at', ''))} · scanner {e(r.get('version', ''))}</p>"]
    if r.get("error"):
        body.append(f"<p>{e(r['error'])}</p>")
        return head + "".join(body)
    det = r.get("detections") or {}
    posture = r.get("grade", "") + (f" · {r['posture_score']}/100" if r.get("posture_score") is not None else "")
    rows = [("Threat risk", f"{r.get('risk_score')}/100 · {r.get('verdict')}"),
            ("Posture", posture),
            ("Engines flagged", f"{det.get('flagged', 0)} of {det.get('total', 0)}"),
            ("IP", ", ".join(r.get("ips", []))),
            ("Final URL", defang(r.get("final_url", "")) if r.get("final_url") != r.get("url") else "")]
    body.append("<table>")
    for k, v in rows:
        if v:
            body.append(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>")
    body.append("</table><h2>Findings</h2>")
    if not r.get("findings"):
        body.append("<p class='mut'>No findings.</p>")
    else:
        body.append("<table>")
        for f in r["findings"]:
            ev = f"<div class='mono mut'>{e(f['evidence'])}</div>" if f.get("evidence") else ""
            fx = f"<div class='mut'>{e(f['recommendation'])}</div>" if f.get("recommendation") else ""
            body.append(f"<tr><td class='sev'>{e(f['severity'])}</td><td>{e(f['title'])}{ev}{fx}</td></tr>")
        body.append("</table>")
    return head + "".join(body)


FORMATTERS = {"json": to_json, "csv": to_csv, "html": to_html, "md": to_markdown, "markdown": to_markdown,
              "sarif": to_sarif}
EXT = {"json": "json", "csv": "csv", "html": "html", "md": "md", "markdown": "md", "sarif": "sarif"}
_MULTI = {"csv", "sarif"}  # formats that take a list of results


def render(fmt, result_or_list):
    fmt = fmt.lower()
    fn = FORMATTERS[fmt]
    if fmt in _MULTI or fmt == "json":  # a JSON list stays one valid JSON document
        return fn(result_or_list)
    if isinstance(result_or_list, list):
        return "\n\n".join(fn(r) for r in result_or_list)
    return fn(result_or_list)


def diff(old, new):
    """Compare two scan result dicts; returns added/resolved findings and changed facts."""
    def fset(r):
        return {f["id"]: f for f in (r or {}).get("findings", [])}
    of, nf = fset(old), fset(new)
    added = [nf[k] for k in nf if k not in of]
    resolved = [of[k] for k in of if k not in nf]

    def fact(r, path):
        cur = r
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
        return cur

    changed = []
    facts = [("Threat risk", ("risk_score",)), ("Verdict", ("verdict",)), ("Posture grade", ("grade",)),
             ("IP address", ("ips",)), ("Final URL", ("final_url",)), ("HTTP status", ("status_code",)),
             ("Engines flagged", ("detections", "flagged")),
             ("TLS fingerprint", ("sections", "tls", "sha256")), ("TLS issuer", ("sections", "tls", "issuer")),
             ("File SHA-256", ("sections", "file", "sha256")),
             ("Domain age (days)", ("sections", "whois", "age_days"))]
    for label, path in facts:
        a, b = fact(old, path), fact(new, path)
        if a != b:
            changed.append({"field": label, "old": a, "new": b})
    return {"added": added, "resolved": resolved, "changed": changed,
            "old_at": (old or {}).get("started_at"), "new_at": (new or {}).get("started_at")}
