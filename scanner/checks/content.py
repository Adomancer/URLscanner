"""Page-content analysis: credential forms, brand impersonation, phishing-kit tells, obfuscated JS,
scam text, cryptominers and wallet drainers. Runs on the raw HTML and, when the browser sandbox ran,
on the rendered DOM too (catches JavaScript-built phishing pages)."""
import re
from urllib.parse import urljoin, urlsplit

from .. import data
from ..htmlutil import soup_of, visible_text
from ..models import Section
from ..utils import registered_domain, shannon_entropy
from . import check

_PW = re.compile(r"^password$", re.I)
_CARD = re.compile(r"card.?num|cc.?num|cvv|cvc|csc|expir|exp.?date|ccexp", re.I)
_SECRET = re.compile(r"seed|mnemonic|recovery.?phrase|private.?key|secret.?phrase", re.I)
_OTP = re.compile(r"otp|one.?time|2fa|sms.?code|verification.?code|pin", re.I)
_SCAM_PHRASES = ["your computer has been infected", "your pc is infected", "call microsoft", "windows defender alert",
                 "do not shut down your computer", "do not restart your computer", "your computer is blocked",
                 "call apple support", "virus detected", "toll free", "your system is at risk",
                 "access to this pc has been blocked", "error code: 0x", "contact support immediately"]
_MINERS = re.compile(r"coinhive|coin-hive|cryptonight|coinimp|webminepool|cryptoloot|minero\.cc|"
                     r"jsecoin|deepminer|new\s+Client\.Anonymous|miner\.start\(", re.I)
_DRAINER = re.compile(r"setApprovalForAll|eth_signTypedData|wallet_switchEthereumChain|permit2|"
                      r"seaport.*fulfill|drainer|increaseAllowance", re.I)
_WALLET_CONNECT = re.compile(r"eth_requestAccounts|walletconnect|web3modal|connectWallet", re.I)
_EXEC_EXT = re.compile(r"\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jse|hta|apk|dmg|pkg|iso|img|lnk|jar)(\?|$)", re.I)
_OBF = [
    (re.compile(r"eval\(function\(p,a,c,k,e,[rd]\)"), "Dean Edwards packer", 0.15),
    (re.compile(r"document\.write\(\s*unescape\(", re.I), "document.write(unescape(...))", 0.18),
    (re.compile(r"eval\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\(", re.I), "eval of decoded string", 0.18),
    (re.compile(r"(?:String\.fromCharCode\([^)]{40,}\))", re.I), "long fromCharCode payload", 0.08),
    (re.compile(r"atob\(\s*['\"][A-Za-z0-9+/=]{400,}['\"]\s*\)"), "large base64 payload decoded at runtime", 0.12),
]


def _hidden(tag):
    style = (tag.get("style") or "").replace(" ", "").lower()
    w, h = str(tag.get("width", "")), str(tag.get("height", ""))
    return ("display:none" in style or "visibility:hidden" in style or w in ("0", "1") or h in ("0", "1")
            or tag.has_attr("hidden"))


def analyze_html(html, base_url, page_domain, trusted=False):
    """Pure analysis of one HTML document. Returns a Section."""
    s = Section()
    soup = soup_of(html)
    title = soup.title.get_text(" ", strip=True)[:200] if soup.title else ""
    og_site = ""
    for m in soup.find_all("meta"):
        if (m.get("property") or m.get("name") or "").lower() in ("og:site_name", "application-name"):
            og_site = (m.get("content") or "")[:120]
    https = base_url.startswith("https://")
    lower = html.lower()

    # ---- links -------------------------------------------------------------------------
    anchors = soup.find_all("a")
    hrefs = [a.get("href") or "" for a in anchors]
    empty = sum(1 for h in hrefs if h.strip() in ("", "#", "#!", "javascript:void(0)", "javascript:void(0);", "javascript:;"))
    ext = sum(1 for h in hrefs if h.startswith(("http://", "https://", "//"))
              and registered_domain(urljoin(base_url, h)) != page_domain)
    s.data.update({"title": title, "site_name": og_site, "links": len(anchors), "empty_links": empty,
                   "external_links": ext, "scripts": len(soup.find_all("script")),
                   "iframes": len(soup.find_all("iframe")), "bytes": len(html)})

    # ---- forms -------------------------------------------------------------------------
    forms = []
    has_password = False
    for form in soup.find_all("form"):
        action_raw = (form.get("action") or "").strip()
        action = urljoin(base_url, action_raw) if action_raw else base_url
        inputs = form.find_all(["input", "select", "textarea"])
        names = " ".join(f"{i.get('name', '')} {i.get('id', '')} {i.get('placeholder', '')} {i.get('autocomplete', '')}"
                         for i in inputs)
        pw = bool(form.find("input", attrs={"type": _PW}))
        has_password |= pw
        info = {"action": action[:300], "method": (form.get("method") or "get").lower(), "password": pw,
                "inputs": len(inputs), "hidden": sum(1 for i in inputs if (i.get("type") or "").lower() == "hidden"),
                "card": bool(_CARD.search(names)), "secret": bool(_SECRET.search(names)), "otp": bool(_OTP.search(names))}
        forms.append(info)
        act_domain = registered_domain(action) if action.startswith(("http://", "https://")) else page_domain
        if pw and action.startswith("http://"):
            s.flag("content.password_over_http", "Password form submits over plain HTTP", "high", weight=0.2,
                   penalty=15, evidence=action, fix="Credentials must only ever be sent over HTTPS.")
        if pw and act_domain and act_domain != page_domain:
            s.flag("content.form_offsite", "Login form sends credentials to another domain", "high", weight=0.4,
                   evidence=f"{page_domain} → {act_domain}")
        if action_raw.lower().startswith("mailto:"):
            s.flag("content.form_mailto", "Form submits data by e-mail (mailto:)", "high", weight=0.35, evidence=action_raw)
        if info["card"] and not trusted:
            s.flag("content.card_form", "Page asks for payment-card details", "medium", weight=0.15)
        if info["secret"]:
            s.flag("content.seed_phrase", "Page asks for a wallet seed phrase / private key", "critical", weight=0.6,
                   fix="No legitimate service ever asks for a recovery phrase.")
    if not has_password and soup.find("input", attrs={"type": _PW}):
        has_password = True  # password input outside a <form> (JS-submitted)
        s.data["password_outside_form"] = True
    s.data["forms"] = forms
    s.data["has_password"] = has_password

    if has_password and len(anchors) < 5 and not trusted:
        s.flag("content.bare_login", "Login page with almost no navigation", "low", weight=0.1,
               evidence=f"{len(anchors)} links on the page")
    if has_password and not https:
        s.flag("content.login_http_page", "Login page served without HTTPS", "high", weight=0.15, penalty=10)

    # ---- brand impersonation -----------------------------------------------------------
    owned = data.brand_domains()
    if page_domain not in owned:
        haystack = f"{title} | {og_site} | " + " ".join(
            (img.get("alt") or "") for img in soup.find_all("img")[:40])
        for b in data.brands():
            name = next((n for n in b["names"] if re.search(rf"(?<![\w]){re.escape(n)}(?![\w])", haystack, re.I)), None)
            if not name:
                continue
            s.data["brand_claimed"] = b["brand"]
            if has_password:
                s.flag("content.brand_login", f"Login form impersonating {b['brand']}", "critical", weight=0.55,
                       evidence=f"page says '{name}' but is hosted on {page_domain}",
                       fix=f"Real {b['brand']} logins only live on {', '.join(b['domains'][:3])}.")
            elif name.lower() in title.lower() and not trusted:
                s.flag("content.brand_title", f"Page title claims to be {b['brand']}", "low", weight=0.1,
                       evidence=title)
            break

        # phishing kits hot-link logos/CSS straight from the brand they imitate
        hot = {}
        for tag in soup.find_all(["img", "link", "script"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith(("http://", "https://", "//")):
                d = registered_domain(urljoin(base_url, src))
                if d in owned and d != page_domain and owned[d] not in ("Google", "Facebook", "Microsoft", "Amazon"):
                    hot.setdefault(owned[d], d)
        if hot and has_password:
            brand, dom = next(iter(hot.items()))
            s.flag("content.hotlink_brand", f"Hot-links {brand} assets next to a login form", "high", weight=0.3,
                   evidence=dom, fix="Typical of phishing kits copied from the real site.")

    # ---- frames ------------------------------------------------------------------------
    for fr in soup.find_all(["iframe", "frame"]):
        src = fr.get("src") or ""
        if src.startswith("data:text/html"):
            s.flag("content.iframe_data", "Frame loads inline data: HTML", "high", weight=0.3, evidence=src[:80])
            break
        if _hidden(fr) and src.startswith(("http", "//")) and registered_domain(urljoin(base_url, src)) != page_domain:
            s.flag("content.hidden_iframe", "Hidden iframe loads a third-party page", "medium", weight=0.15,
                   evidence=src[:200])
            break

    # ---- scripts -----------------------------------------------------------------------
    inline = "\n".join(sc.get_text() for sc in soup.find_all("script") if not sc.get("src"))[:2_000_000]
    obf = []
    for rx, label, w in _OBF:
        if rx.search(inline):
            obf.append(label)
            s.flag(f"content.obfuscation.{label.split()[0].lower()}", f"Obfuscated JavaScript: {label}", "medium",
                   weight=w)
    if len(re.findall(r"\b_0x[0-9a-f]{4,6}\b", inline)) >= 25:
        obf.append("javascript-obfuscator identifiers")
        s.flag("content.obfuscation.hex_identifiers", "Obfuscated JavaScript: javascript-obfuscator identifiers",
               "medium", weight=0.12)
    long_strings = [m for m in re.findall(r"['\"]([A-Za-z0-9+/=_\-]{800,})['\"]", inline)
                    if shannon_entropy(m[:2000]) > 5.0]
    if long_strings:
        obf.append("high-entropy blobs")
        s.flag("content.obfuscation.blob", f"{len(long_strings)} large high-entropy string(s) in inline script", "low",
               weight=0.06)
    s.data["obfuscation"] = obf
    if _MINERS.search(lower):
        s.flag("content.cryptominer", "In-browser cryptocurrency miner", "high", weight=0.45)
    if _DRAINER.search(inline) and _WALLET_CONNECT.search(lower):
        s.flag("content.wallet_drainer", "Wallet-drainer patterns (asks for token approvals)", "high", weight=0.4)
    if re.search(r"oncontextmenu\s*=\s*['\"]?\s*return\s+false|event\.button\s*==\s*2", lower):
        s.flag("content.no_right_click", "Page disables right-click / inspection", "low", weight=0.05)
    if "onbeforeunload" in lower and re.search(r"onbeforeunload\s*=\s*function|addEventListener\(\s*['\"]beforeunload", lower):
        s.data["beforeunload"] = True

    # ---- text --------------------------------------------------------------------------
    text = visible_text(html).lower()
    scam = [p for p in _SCAM_PHRASES if p in text]
    if len(scam) >= 2:
        s.flag("content.tech_support_scam", "Tech-support scam wording", "high", weight=0.45, evidence="; ".join(scam[:4]))
    downloads = [h for h in hrefs if _EXEC_EXT.search(urlsplit(urljoin(base_url, h)).path or "")]
    if downloads:
        s.data["executable_links"] = downloads[:10]
        s.flag("content.exec_download", "Page links to executable / script downloads", "medium", weight=0.12,
               evidence=downloads[0][:200])

    # ---- mixed content -----------------------------------------------------------------
    if https:
        mixed = [t.get("src") or t.get("href") for t in soup.find_all(["script", "iframe", "img", "link"])
                 if (t.get("src") or (t.get("href") if t.name == "link" else "") or "").startswith("http://")]
        if mixed:
            s.flag("content.mixed_content", f"{len(mixed)} resource(s) loaded over HTTP on an HTTPS page", "low",
                   penalty=5, evidence=mixed[0][:200])
    robots = soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    if robots and "noindex" in (robots.get("content") or "").lower() and has_password and not trusted:
        s.flag("content.noindex_login", "Login page asks search engines not to index it", "low", weight=0.05)
    return s


@check("content", "Page content", stage=3, requires="http")
def run(ctx):
    if not ctx.html:
        s = Section()
        s.data["skipped"] = f"not an HTML page ({ctx.fetch.content_type or 'unknown type'})"
        return s
    s = analyze_html(ctx.html, ctx.fetch.final_url, ctx.final_registered_domain, ctx.trusted)
    if ctx.rendered_html:
        r = analyze_html(ctx.rendered_html, ctx.sections.get("sandbox", {}).get("final_url") or ctx.fetch.final_url,
                         ctx.final_registered_domain, ctx.trusted)
        seen = {f.id for f in s.findings}
        for f in r.findings:
            if f.id not in seen:
                f.evidence = (f.evidence + " " if f.evidence else "") + "(only visible after JavaScript rendering)"
                s.findings.append(f)
        s.data["rendered"] = {k: r.data.get(k) for k in ("title", "forms", "has_password", "links", "brand_claimed")}
    return s
