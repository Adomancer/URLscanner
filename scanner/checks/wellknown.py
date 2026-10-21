"""security.txt (RFC 9116) and robots.txt: how the site takes vulnerability reports, and what it hides
from crawlers. Two small GETs; paths listed in robots.txt are only reported, never requested."""
import datetime as dt
import re
from urllib.parse import urlsplit

from .. import net
from ..models import Section
from . import check

_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z-]*)\s*:\s*(.+?)\s*$")
_SENSITIVE = re.compile(r"(?:^|[/._-])(admin|administrator|backups?|bak|\.git|\.svn|\.env|config|private|secret|"
                        r"internal|phpmyadmin|cpanel|dump|staging|debug|logs?)(?:$|[/._-])", re.I)


def parse_security_txt(text):
    """Fields of a security.txt file (keys lower-cased, values as lists). Pure function."""
    fields = {}
    for line in text.splitlines():
        if line.startswith(("#", "-----", "Hash:")):  # comments and PGP clear-sign armour
            continue
        m = _FIELD.match(line)
        if m:
            fields.setdefault(m.group(1).lower(), []).append(m.group(2)[:300])
    expires = (fields.get("expires") or [""])[0]
    try:
        expires_dt = dt.datetime.fromisoformat(re.sub(r"[zZ]$", "+00:00", expires)) if expires else None
        if expires_dt and not expires_dt.tzinfo:
            expires_dt = expires_dt.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        expires_dt = None
    return {"contact": fields.get("contact", []), "expires": expires, "expires_dt": expires_dt,
            "policy": fields.get("policy", []), "encryption": fields.get("encryption", []),
            "signed": "-----BEGIN PGP SIGNED MESSAGE-----" in text, "fields": sorted(fields)}


def parse_robots(text):
    """Disallowed paths and sitemaps from robots.txt, plus the paths that look sensitive. Pure function."""
    disallow, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value and value not in disallow:
            disallow.append(value[:200])
        elif key == "sitemap" and value:
            sitemaps.append(value[:200])
    disallow = disallow[:200]
    return {"disallow": disallow, "sitemaps": sitemaps[:20],
            "sensitive": [p for p in disallow if _SENSITIVE.search(p)][:20]}


def _origin(url):
    p = urlsplit(url)
    host = f"[{p.hostname}]" if ":" in (p.hostname or "") else p.hostname
    return f"{p.scheme}://{host}" + (f":{p.port}" if p.port else "")


def _fetch_text(url):
    """Body of a plain-text file, or None when it is missing (error status, or an HTML catch-all page)."""
    try:
        r = net.safe_fetch(url, max_redirects=2, max_bytes=32_768, timeout=6)
    except Exception:
        return None
    if r.status != 200 or not r.body or r.is_html:
        return None
    return r.text


@check("wellknown", "security.txt & robots.txt", stage=2, requires="http")
def run(ctx):
    s = Section()
    origin = _origin(ctx.fetch.final_url)

    sec_url, text = None, None
    for path in ("/.well-known/security.txt", "/security.txt"):
        text = _fetch_text(origin + path)
        if text is not None:
            sec_url = origin + path
            break
    if text is None:
        s.data["security_txt"] = None
        s.flag("wellknown.no_security_txt", "No security.txt (no published way to report vulnerabilities)", "info",
               penalty=2, evidence=f"{origin}/.well-known/security.txt",
               fix="Publish /.well-known/security.txt with Contact and Expires fields (RFC 9116).")
    else:
        info = parse_security_txt(text)
        exp = info.pop("expires_dt")
        s.data["security_txt"] = {"url": sec_url, **info}
        missing = [f for f in ("contact", "expires") if f not in info["fields"]]
        if missing:
            s.flag("wellknown.security_txt_incomplete", f"security.txt lacks required field(s): {', '.join(missing)}",
                   "info", penalty=1, evidence=sec_url, fix="RFC 9116 requires both Contact and Expires.")
        if exp and exp < dt.datetime.now(dt.timezone.utc):
            s.flag("wellknown.security_txt_expired", "security.txt has expired", "low", penalty=2,
                   evidence=f"Expires: {info['expires']}", fix="Update the Expires date (at most a year ahead).")

    robots = _fetch_text(origin + "/robots.txt")
    s.data["robots"] = parse_robots(robots) if robots is not None else None
    if robots is not None and s.data["robots"]["sensitive"]:
        paths = s.data["robots"]["sensitive"]
        s.flag("wellknown.robots_sensitive", f"robots.txt names {len(paths)} sensitive-looking path(s)", "info",
               evidence=", ".join(paths[:6]),
               fix="robots.txt is public: it hides nothing from attackers. Protect these paths with authentication.")
    return s
