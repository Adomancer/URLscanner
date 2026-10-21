"""Dangling-DNS / subdomain-takeover detection (passive: uses the CNAME and the page already fetched)."""
from .. import data
from ..models import Section
from . import check
from .dns_checks import nxdomain, query


@check("takeover", "Subdomain takeover", stage=2)
def run(ctx):
    s = Section()
    cnames = (ctx.sections.get("dns", {}).get("records", {}) or {}).get("CNAME") or query(ctx.host, "CNAME")[0]
    if not cnames:
        s.data["applicable"] = False
        return s
    target = cnames[0].lower().rstrip(".")
    s.data["cname"] = target
    body = ctx.fetch.text[:300_000] if ctx.fetch else ""
    for fp in data.takeover_fingerprints():
        # dotted patterns are domain suffixes; dotless ones (e.g. "s3-website") are label fragments
        if not any(target == c or target.endswith("." + c) if "." in c else c in target for c in fp["cname"]):
            continue
        s.data["service"] = fp["service"]
        if fp["nxdomain"] and nxdomain(target):
            s.flag("takeover.dangling_cname", f"Dangling CNAME to {fp['service']} (target does not exist)", "critical",
                   penalty=30, evidence=f"{ctx.host} → {target} (NXDOMAIN)",
                   fix="Remove the DNS record or re-claim the resource; anyone can register it and serve content here.")
        elif body and any(sig in body for sig in fp["fingerprint"]):
            s.flag("takeover.unclaimed", f"Subdomain points to an unclaimed {fp['service']} resource", "critical",
                   penalty=30, evidence=f"{ctx.host} → {target}",
                   fix="Delete the CNAME or claim the resource before an attacker does.")
        break
    return s
