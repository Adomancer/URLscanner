"""Redirect-chain forensics, client-side redirects, open-redirect parameters and cloaking detection."""
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlsplit

from .. import data, net
from ..htmlutil import js_redirects, meta_refresh, page_signature
from ..models import Section
from ..utils import registered_domain
from . import check

_REDIRECT_PARAMS = {"url", "u", "next", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
                    "return_to", "goto", "target", "dest", "destination", "continue", "r", "link", "out", "to"}
_UAS = {
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
}


def _cloak_probe(url, ua):
    try:
        r = net.safe_fetch(url, user_agent=ua, max_bytes=1_000_000, timeout=8)
        return r.status, page_signature(r.text if r.is_html else "", r.final_url)
    except Exception as e:
        return None, {"error": str(e)[:120]}


@check("redirects", "Redirect chain", stage=2, requires="http")
def run(ctx):
    s = Section()
    f = ctx.fetch
    chain = [{"url": h.url, "status": h.status, "location": h.location, "server": h.server,
              "elapsed_ms": h.elapsed_ms, "domain": registered_domain(h.url)} for h in f.chain]
    s.data["chain"] = chain
    domains = [c["domain"] for c in chain]
    cross = sum(1 for a, b in zip(domains, domains[1:]) if a != b)
    s.data["cross_domain_hops"] = cross
    first, final = domains[0] if domains else ctx.registered_domain, ctx.final_registered_domain
    shorteners = data.lists()["shorteners"]

    if len(chain) > 4:
        s.flag("redirects.many", f"Long redirect chain ({len(chain) - 1} redirects)", "low", weight=0.1)
    if final != first:
        expected = first in shorteners
        s.flag("redirects.offsite", f"Redirects to a different site: {final}", "info" if expected else "medium",
               weight=0.03 if expected else 0.1, evidence=" → ".join(dict.fromkeys(domains)))
    for a, b in zip(chain, chain[1:]):
        if a["url"].startswith("https://") and b["url"].startswith("http://"):
            s.flag("redirects.downgrade", "Redirect downgrades HTTPS to HTTP", "medium", weight=0.15, penalty=10,
                   evidence=f"{a['url']} → {b['url']}")
            break

    soup = ctx.soup
    mr = meta_refresh(soup, f.final_url)
    if mr and mr["url"]:
        s.data["meta_refresh"] = mr
        off = registered_domain(mr["url"]) != final
        s.flag("redirects.meta_refresh", "Page redirects with <meta refresh>" + (" to another site" if off else ""),
               "medium" if off else "low", weight=0.15 if off else 0.03, evidence=mr["url"])
    js = js_redirects(soup, f.final_url)
    if js:
        s.data["js_redirects"] = js
        off = [u for u in js if registered_domain(u) not in (final, "")]
        if off:
            s.flag("redirects.js", "JavaScript redirects to another site", "medium", weight=0.12, evidence=off[0])

    # embedded redirect targets (open-redirect abuse)
    for k, v in parse_qsl(ctx.parts.query, keep_blank_values=True):
        if k.lower() in _REDIRECT_PARAMS and (v.startswith(("http://", "https://", "//"))):
            target = registered_domain(v if "://" in v else "https:" + v)
            if target and target != ctx.registered_domain:
                s.flag("redirects.open_redirect_param", f"URL carries a redirect target in '{k}='", "medium",
                       weight=0.2, evidence=v[:200],
                       fix="Attackers chain trusted sites' open redirects to reach phishing pages.")
                break

    # cloaking: does the site show crawlers / mobile devices something different?
    browser_sig = page_signature(ctx.html, f.final_url)
    with ThreadPoolExecutor(max_workers=2) as pool:
        probes = dict(zip(_UAS, pool.map(lambda ua: _cloak_probe(ctx.url, ua), _UAS.values())))
    s.data["cloaking"] = {"browser": browser_sig, **{k: v[1] for k, v in probes.items()}}
    for name, (status, sig) in probes.items():
        if status is None:
            continue
        other_site = registered_domain(sig["final_url"]) != final
        hides_login = browser_sig["password"] and not sig["password"]
        if other_site or (hides_login and name == "googlebot"):
            s.flag("redirects.cloaking", f"Cloaking: {name} user-agent is shown different content", "high", weight=0.35,
                   evidence=f"browser → {final} (login form: {browser_sig['password']}); "
                            f"{name} → {registered_domain(sig['final_url'])} (login form: {sig['password']})",
                   fix="Phishing kits hide from security crawlers by serving them a harmless page.")
            break
        if name == "googlebot" and status != f.status and f.status == 200 and status in (403, 404, 410):
            s.flag("redirects.crawler_blocked", "Search-engine crawler is refused", "low", weight=0.05,
                   evidence=f"browser {f.status}, googlebot {status}")
    return s
