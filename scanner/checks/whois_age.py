"""Domain age via the WHOIS protocol (TCP port 43) -- no web API, no key.

Newly registered domains are one of the strongest phishing/malware signals.
"""
import datetime as dt
import ipaddress
import re
import socket

from .. import net, storage
from ..models import Section
from . import check

_KNOWN_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "org": "whois.pir.org",
    "info": "whois.nic.info", "io": "whois.nic.io", "co": "whois.nic.co", "me": "whois.nic.me",
    "xyz": "whois.nic.xyz", "top": "whois.nic.top", "app": "whois.nic.google", "dev": "whois.nic.google",
    "id": "whois.id", "uk": "whois.nic.uk", "de": "whois.denic.de", "nl": "whois.domain-registry.nl",
    "eu": "whois.eu", "ru": "whois.tcinet.ru", "au": "whois.auda.org.au", "ca": "whois.cira.ca",
    "fr": "whois.nic.fr", "it": "whois.nic.it", "us": "whois.nic.us", "biz": "whois.nic.biz",
}

_CREATED = re.compile(r"^\s*(?:creation date|created(?: on)?|registered(?: on)?|registration (?:date|time)|"
                      r"domain registration date|record created|created date|domain record activated|"
                      r"registered date|commencement date)\s*[:.]+\s*(.+)$", re.I | re.M)
_EXPIRES = re.compile(r"^\s*(?:registry expiry date|registrar registration expiration date|expir(?:y|ation) date|"
                      r"expires(?: on)?|paid-till|expiration time|renewal date)\s*[:.]+\s*(.+)$", re.I | re.M)
_UPDATED = re.compile(r"^\s*(?:updated date|last updated|last modified|changed|last-update)\s*[:.]+\s*(.+)$", re.I | re.M)
_REGISTRAR = re.compile(r"^\s*(?:registrar(?: name)?|sponsoring registrar|registrar organization)\s*:\s*(.+)$", re.I | re.M)
_REFER = re.compile(r"^\s*(?:refer|whois):\s*(\S+)", re.I | re.M)
_REG_WHOIS = re.compile(r"^\s*registrar whois server:\s*(\S+)", re.I | re.M)
_PRIVACY = re.compile(r"redacted for privacy|privacy|whoisguard|domains by proxy|withheld|data protected|"
                      r"contact privacy|perfect privacy|not disclosed", re.I)
# privacy wording only counts on contact lines (registry disclaimers mention "privacy" too)
_CONTACT_LINE = re.compile(r"^\s*(?:registrant|admin|administrative|tech|technical|owner|holder)[^:\n]*:.*$",
                           re.I | re.M)
_NOT_FOUND = re.compile(r"no match|not found|no data found|no entries found|status:\s*free|is available", re.I)

_DATE_FORMATS = ("%Y-%m-%d", "%d-%b-%Y", "%d-%m-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d", "%d/%m/%Y",
                 "%Y%m%d", "%b %d %Y", "%d %b %Y", "%B %d %Y")


def whois_raw(server, query, timeout=8):
    sock, _ = net.connect_public(server, 43, timeout=timeout)  # server names can come from WHOIS replies
    with sock:
        sock.sendall((query + "\r\n").encode("idna" if not query.isascii() else "ascii"))
        chunks, total = [], 0
        while total < 256 * 1024:
            try:
                buf = sock.recv(8192)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
    return b"".join(chunks).decode("utf-8", "replace")


def parse_date(text):
    text = text.strip().split(" (")[0].strip()
    iso = text.replace("Z", "+00:00").replace("T", " ")
    for candidate in (iso, iso[:25], iso[:19], iso[:10]):
        try:
            d = dt.datetime.fromisoformat(candidate)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    head = re.sub(r"\s+", " ", text.replace(",", " "))
    for fmt in _DATE_FORMATS:
        for cand in (head, head[:11], head[:10], " ".join(head.split()[:3])):
            try:
                return dt.datetime.strptime(cand, fmt).replace(tzinfo=dt.timezone.utc)
            except ValueError:
                continue
    return None


def parse(text):
    def first(rx):
        m = rx.search(text)
        return m.group(1).strip() if m else ""

    created, expires = first(_CREATED), first(_EXPIRES)
    return {
        "created": created,
        "created_dt": parse_date(created) if created else None,
        "expires": expires,
        "expires_dt": parse_date(expires) if expires else None,
        "updated": first(_UPDATED),
        "registrar": first(_REGISTRAR)[:120],
        "privacy": any(_PRIVACY.search(m.group(0)) for m in _CONTACT_LINE.finditer(text)),
        "not_found": bool(_NOT_FOUND.search(text[:2000])) and not created,
    }


def lookup(domain):
    tld = domain.rsplit(".", 1)[-1]
    server = _KNOWN_SERVERS.get(tld)
    if not server:
        iana = whois_raw("whois.iana.org", tld)
        m = _REFER.search(iana)
        server = m.group(1) if m else None
    if not server:
        return {"error": f"no WHOIS server known for .{tld}"}
    text = whois_raw(server, domain)
    info = parse(text)
    m = _REG_WHOIS.search(text)
    reg_server = m.group(1).strip().lower().removeprefix("whois://") if m else ""
    if reg_server and reg_server != server and (not info["created_dt"] or not info["registrar"]):
        try:
            more = parse(whois_raw(reg_server, domain, timeout=6))
            for k, v in more.items():
                if not info.get(k) and v:
                    info[k] = v
        except (OSError, net.BlockedTarget, net.ResolveError):
            pass
    info["server"] = server
    return info


@check("whois", "Domain registration")
def run(ctx):
    s = Section()
    domain = ctx.registered_domain
    try:
        ipaddress.ip_address(domain.strip("[]"))
        s.data["applicable"] = False
        return s
    except ValueError:
        pass
    if "." not in domain:
        s.data["applicable"] = False
        return s

    cached = storage.whois_cache_get(domain)
    if cached is None:
        try:
            info = lookup(domain)
        except (OSError, net.BlockedTarget, net.ResolveError) as e:
            info = {"error": f"WHOIS unavailable: {e}"}
        cacheable = {k: (v.isoformat() if isinstance(v, dt.datetime) else v) for k, v in info.items()}
        if "error" not in info:
            storage.whois_cache_set(domain, cacheable)
        cached = cacheable

    info = dict(cached)
    for k in ("created_dt", "expires_dt"):
        if isinstance(info.get(k), str):
            try:
                info[k] = dt.datetime.fromisoformat(info[k])
            except ValueError:
                info[k] = None
    now = dt.datetime.now(dt.timezone.utc)
    created = info.get("created_dt")
    expires = info.get("expires_dt")
    age = (now - created).days if created else None
    s.data.update({
        "domain": domain,
        "registrar": info.get("registrar", ""),
        "created": created.date().isoformat() if created else info.get("created", ""),
        "expires": expires.date().isoformat() if expires else info.get("expires", ""),
        "updated": info.get("updated", ""),
        "age_days": age,
        "privacy": info.get("privacy", False),
        "server": info.get("server", ""),
        "error": info.get("error", ""),
    })
    if info.get("not_found"):
        s.flag("whois.unregistered", "Domain does not appear to be registered", "medium", weight=0.2, evidence=domain)
    if age is not None:
        if age < 30:
            s.flag("whois.new_domain", f"Newly registered domain ({age} days old)", "high", weight=0.45,
                   evidence=f"created {s.data['created']} via {s.data['registrar'] or 'unknown registrar'}",
                   fix="Most phishing domains are used within days of registration.")
        elif age < 90:
            s.flag("whois.young_domain", f"Young domain ({age} days old)", "medium", weight=0.2,
                   evidence=f"created {s.data['created']}")
        elif age < 365:
            s.flag("whois.recent_domain", f"Domain registered less than a year ago ({age} days)", "low", weight=0.05)
    if expires and created and (expires - created).days <= 366 and age is not None and age < 365:
        s.data["short_registration"] = True
    return s
