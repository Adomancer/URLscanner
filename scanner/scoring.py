"""Two separate verdicts:
  * Threat risk (0-100): is this URL malicious / phishing?   risk = 100 * (1 - prod(1 - w_i))
  * Security posture (A+..F): how well is the site hardened?  100 - sum(penalties)
Every point is traceable to a Finding.
"""
from .models import Finding

VERDICTS = [(80, "Malicious"), (50, "Likely malicious"), (20, "Suspicious"), (0, "Clean")]
GRADES = [(95, "A+"), (85, "A"), (75, "B"), (65, "C"), (50, "D"), (0, "F")]
_TRUSTED_DAMPING = 0.25


def correlate(findings, sections):
    """Signals that are weak alone but strong together."""
    ids = {f.id for f in findings}
    has = lambda prefix: any(i.startswith(prefix) for i in ids)  # noqa: E731
    content = sections.get("content", {})
    login = content.get("has_password") or (content.get("rendered") or {}).get("has_password")
    out = []
    lookalike = has("lexical.brand.") or has("lexical.homograph")
    if lookalike and login:
        out.append(Finding("correlation.lookalike_login", "Look-alike domain hosts a login form", "critical", weight=0.5,
                           evidence="brand-impersonating domain + credential form", category="correlation"))
    if has("whois.new_domain") and login:
        out.append(Finding("correlation.new_domain_login", "Brand-new domain asking for credentials", "high",
                           weight=0.35, evidence="domain < 30 days old + credential form", category="correlation"))
    if has("whois.new_domain") and has("tls.fresh") and (lookalike or has("content.brand")):
        out.append(Finding("correlation.fresh_infra", "Fresh domain + fresh certificate + brand signals", "high",
                           weight=0.3, category="correlation"))
    if has("redirects.cloaking") and login:
        out.append(Finding("correlation.cloaked_login", "Login page hidden from security crawlers", "critical",
                           weight=0.45, category="correlation"))
    return out


def consensus(checks_state, findings, sections):
    """VirusTotal-style detection ratio built from local engines: every check that applied, plus every
    feed file the user loaded. A finding with weight >= 0.15 counts as that engine flagging the URL."""
    applied = {}
    for name, st in checks_state.items():
        if st.get("status") != "done" or name == "blocklist":
            continue
        if (sections.get(name) or {}).get("applicable") is False:
            continue
        applied[name] = st.get("title", name)
    hits = {}
    for f in findings:
        if f.weight >= 0.15 and f.category in applied:
            hits[f.category] = hits.get(f.category, 0) + 1
    engines = [{"engine": title, "flagged": hits.get(name, 0) > 0, "hits": hits.get(name, 0)}
               for name, title in applied.items()]
    bl = sections.get("blocklist") or {}
    feed_hits = set(bl.get("feed_hits") or [])
    for feed in bl.get("feeds") or []:
        engines.append({"engine": f"Feed: {feed}", "flagged": feed in feed_hits, "hits": int(feed in feed_hits)})
    return {"flagged": sum(1 for e in engines if e["flagged"]), "total": len(engines), "engines": engines}


def score(findings, trusted=False, fetched=True, passive=False):
    """passive -- the target was never contacted, so a low score means "nothing found yet", not "clean"."""
    prod = 1.0
    for f in findings:
        if f.weight <= 0:
            continue
        w = min(f.weight, 0.97)
        if trusted and f.severity != "critical" and not f.id.startswith("blocklist."):
            w *= _TRUSTED_DAMPING
        prod *= 1 - w
    risk = round(100 * (1 - prod))
    verdict = next(v for t, v in VERDICTS if risk >= t)
    if passive and verdict == "Clean":
        verdict = "Unverified"

    if fetched:
        posture = max(0, 100 - sum(f.penalty for f in findings))
        grade = next(g for t, g in GRADES if posture >= t)
    else:
        posture, grade = None, "N/A"

    reasons = sorted((f for f in findings if f.weight > 0), key=lambda f: -f.weight)[:6]
    return {"risk_score": risk, "verdict": verdict, "posture_score": posture, "grade": grade,
            "reasons": [{"id": f.id, "title": f.title, "weight": round(f.weight, 2), "severity": f.severity}
                        for f in reasons]}
