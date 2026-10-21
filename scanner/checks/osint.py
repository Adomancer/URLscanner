"""OSINT pivots: tracking IDs that link sites to one operator, contacts, wallets, favicon hash."""
import re
from urllib.parse import urljoin, urlsplit

from .. import data, net
from ..htmlutil import visible_text
from ..models import Section
from ..utils import base58check_ok, bech32_ok, favicon_hash, registered_domain, sha256_hex
from . import check

_IDS = {
    "Google Analytics (UA)": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "Google Analytics 4": re.compile(r"\bG-[A-Z0-9]{8,12}\b"),
    "Google Tag Manager": re.compile(r"\bGTM-[A-Z0-9]{5,9}\b"),
    "Google Ads": re.compile(r"\bAW-\d{9,11}\b"),
    "AdSense publisher": re.compile(r"\b(?:ca-)?pub-\d{16}\b"),
    "Facebook Pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{15,16})['\"]"),
    "Yandex Metrica": re.compile(r"\bym\(\s*(\d{6,10})\s*,\s*['\"]init"),
    "Hotjar": re.compile(r"\bhjid\s*:\s*(\d{5,9})"),
    "Microsoft Clarity": re.compile(r"clarity\.ms/tag/([a-z0-9]{8,12})"),
}
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_PHONE = re.compile(r"(?<![\w+])\+\d[\d\s().-]{7,18}\d")
_SOCIAL = {"facebook.com": "Facebook", "twitter.com": "X/Twitter", "x.com": "X/Twitter", "instagram.com": "Instagram",
           "linkedin.com": "LinkedIn", "t.me": "Telegram", "wa.me": "WhatsApp", "youtube.com": "YouTube",
           "tiktok.com": "TikTok", "github.com": "GitHub", "discord.gg": "Discord", "discord.com": "Discord"}
_BTC = re.compile(r"\b(bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_TRX = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")


def extract_pivots(html, base_url):
    out = {"tracking_ids": [], "emails": [], "phones": [], "social": [], "wallets": []}
    seen = set()
    for label, rx in _IDS.items():
        for m in rx.finditer(html):
            v = m.group(1) if m.groups() else m.group(0)
            if (label, v) not in seen:
                seen.add((label, v))
                out["tracking_ids"].append({"type": label, "id": v})
    text = visible_text(html)
    emails = set(_EMAIL.findall(html)) | set(_EMAIL.findall(text))
    out["emails"] = sorted(e for e in emails if not re.search(r"\.(png|jpe?g|gif|svg|webp|css|js)$", e, re.I)
                           and "example." not in e and "sentry" not in e.lower())[:25]
    tel = set(re.findall(r"href=['\"]tel:([^'\"]+)", html, re.I)) | set(_PHONE.findall(text))
    out["phones"] = sorted({re.sub(r"\s+", " ", t).strip() for t in tel})[:15]
    for href in set(re.findall(r"href=['\"](https?://[^'\"]+)", html, re.I)):
        host = (urlsplit(href).hostname or "").lower().removeprefix("www.")
        if host in _SOCIAL and urlsplit(href).path.strip("/"):
            out["social"].append({"network": _SOCIAL[host], "url": href[:200]})
    out["social"] = sorted(out["social"], key=lambda x: x["url"])[:20]
    wallets = []
    for m in _BTC.findall(text):
        if (m.startswith("bc1") and bech32_ok(m)) or (not m.startswith("bc1") and base58check_ok(m, {0, 5})):
            wallets.append({"coin": "BTC", "address": m})
    for m in _ETH.findall(text):
        wallets.append({"coin": "ETH/EVM", "address": m})
    for m in _TRX.findall(text):
        if base58check_ok(m, {0x41}):
            wallets.append({"coin": "TRX", "address": m})
    out["wallets"] = list({w["address"]: w for w in wallets}.values())[:20]
    return out


def _favicon_url(soup, base_url):
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel and link.get("href"):
            return urljoin(base_url, link["href"])
    p = urlsplit(base_url)
    return f"{p.scheme}://{p.netloc}/favicon.ico"


@check("osint", "OSINT pivots", stage=2, requires="http")
def run(ctx):
    s = Section()
    html = ctx.html
    pivots = extract_pivots(html, ctx.fetch.final_url) if html else {}
    s.data.update(pivots)

    fav_url = _favicon_url(ctx.soup, ctx.fetch.final_url)
    fav = {"url": fav_url}
    if not fav_url.startswith("data:"):
        try:
            r = net.safe_fetch(fav_url, max_bytes=300_000, timeout=6, max_redirects=3)
            if r.status == 200 and r.body and not r.is_html:
                fav.update(mmh3=favicon_hash(r.body), sha256=sha256_hex(r.body), bytes=len(r.body))
                fav["shodan_query"] = f"http.favicon.hash:{fav['mmh3']}"
        except Exception as e:
            fav["error"] = str(e)[:120]
    s.data["favicon"] = fav

    if "mmh3" in fav:
        page_domain = ctx.final_registered_domain
        owned = data.brand_domains()
        for brand, hashes in data.favicon_hashes().items():
            if fav["mmh3"] in hashes:
                s.data["favicon_brand"] = brand
                if owned.get(page_domain) != brand:
                    s.flag("osint.favicon_brand", f"Uses {brand}'s favicon on an unrelated domain", "high", weight=0.45,
                           evidence=f"favicon hash {fav['mmh3']} on {page_domain}",
                           fix="Phishing kits copy the real site's favicon.")
                break

    if pivots.get("wallets"):
        s.flag("osint.wallets", f"{len(pivots['wallets'])} crypto wallet address(es) on the page", "info",
               evidence=", ".join(w["address"][:14] + "…" for w in pivots["wallets"][:3]))
    if pivots.get("tracking_ids"):
        s.flag("osint.tracking_ids", f"{len(pivots['tracking_ids'])} tracking ID(s) usable for pivoting", "info",
               evidence=", ".join(t["id"] for t in pivots["tracking_ids"][:5]),
               fix="The same analytics/ad IDs on other sites usually means the same operator.")
    if ctx.fetch and registered_domain(ctx.fetch.final_url) != ctx.registered_domain:
        s.data["note"] = "pivots taken from the final page after redirects"
    return s
