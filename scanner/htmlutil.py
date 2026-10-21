"""Small HTML helpers shared by several checks."""
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

_META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)
_JS_REDIRECT = re.compile(
    r"(?:window|document|top|self|parent)?\.?location(?:\.href)?\s*=\s*['\"]([^'\"]{4,300})['\"]"
    r"|location\.(?:replace|assign)\(\s*['\"]([^'\"]{4,300})['\"]", re.I)


def soup_of(html):
    return BeautifulSoup(html or "", "lxml")


def meta_refresh(soup, base_url):
    for m in soup.find_all("meta"):
        if (m.get("http-equiv") or "").lower() == "refresh":
            content = m.get("content") or ""
            mm = _META_REFRESH_URL.search(content)
            delay = content.split(";")[0].strip()
            return {"delay": delay, "url": urljoin(base_url, mm.group(1).strip()) if mm else ""}
    return None


def js_redirects(soup, base_url):
    out = []
    for sc in soup.find_all("script"):
        if sc.get("src"):
            continue
        for m in _JS_REDIRECT.finditer(sc.string or sc.get_text() or ""):
            target = m.group(1) or m.group(2)
            if target and not target.startswith(("#", "javascript:")):
                out.append(urljoin(base_url, target))
    return out[:5]


def visible_text(html, limit=200_000):
    """Text a visitor would see (parses its own soup so shared soups are not mutated)."""
    soup = soup_of(html)
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.extract()
    return soup.get_text(" ", strip=True)[:limit]


def page_signature(html, final_url):
    """Coarse fingerprint used to compare responses (e.g. browser vs crawler user-agent)."""
    soup = soup_of(html)
    title = (soup.title.get_text(strip=True) if soup.title else "")[:120]
    forms = soup.find_all("form")
    return {
        "final_url": final_url,
        "title": title,
        "forms": len(forms),
        "password": bool(soup.find("input", attrs={"type": re.compile("^password$", re.I)})),
        "links": len(soup.find_all("a")),
        "length": len(html or ""),
    }
