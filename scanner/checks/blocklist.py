"""Offline threat-feed matching against files in scanner/data/blocklists/."""
import glob
import ipaddress
import os
import threading
from urllib.parse import urlsplit

from .. import data
from ..models import Section
from ..utils import registered_domain
from . import check

_lock = threading.Lock()
_cache = {"sig": None, "urls": {}, "hosts": {}, "ips": {}, "files": []}


def _refang(s):
    from ..extract import refang
    return refang(s)


def _norm_url(u):
    p = urlsplit(u.strip())
    host = (p.hostname or "").lower()
    path = p.path.rstrip("/") or ""
    return f"{host}{path}{'?' + p.query if p.query else ''}"


def _load():
    files = sorted(glob.glob(os.path.join(data.BLOCKLIST_DIR, "*.txt")))
    sig = tuple((f, os.path.getmtime(f)) for f in files)
    with _lock:
        if sig == _cache["sig"]:
            return _cache
        urls, hosts, ips = {}, {}, {}
        for f in files:
            name = os.path.basename(f)
            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                        line = parts[1]
                    else:
                        line = parts[0]
                    line = _refang(line).strip(",;\"'")
                    if "://" in line:
                        urls.setdefault(_norm_url(line), name)
                        continue
                    try:
                        ipaddress.ip_address(line)
                        ips.setdefault(line, name)
                    except ValueError:
                        hosts.setdefault(line.lower().strip("."), name)
        _cache.update(sig=sig, urls=urls, hosts=hosts, ips=ips, files=[os.path.basename(f) for f in files])
        return _cache


@check("blocklist", "Offline threat feeds", stage=2, passive=True)
def run(ctx):
    s = Section()
    db = _load()
    s.data["feeds"] = db["files"]
    s.data["entries"] = len(db["urls"]) + len(db["hosts"]) + len(db["ips"])
    hits = []
    u = _norm_url(ctx.url)
    if u in db["urls"]:
        hits.append(("url", ctx.url, db["urls"][u], 0.9))
    if ctx.host in db["hosts"]:
        hits.append(("host", ctx.host, db["hosts"][ctx.host], 0.85))
    elif ctx.registered_domain in db["hosts"] and not ctx.trusted:
        hits.append(("domain", ctx.registered_domain, db["hosts"][ctx.registered_domain], 0.8))
    for ip in ctx.ips:
        if ip in db["ips"]:
            hits.append(("ip", ip, db["ips"][ip], 0.6))
            break
    if ctx.fetch and ctx.fetch.final_url != ctx.url:
        fu = _norm_url(ctx.fetch.final_url)
        fh = (urlsplit(ctx.fetch.final_url).hostname or "").lower()
        if fu in db["urls"] or fh in db["hosts"] or registered_domain(fh) in db["hosts"]:
            hits.append(("final", ctx.fetch.final_url, db["urls"].get(fu) or db["hosts"].get(fh) or "feed", 0.85))
    s.data["hits"] = [{"type": t, "value": v, "feed": f} for t, v, f, _ in hits]
    s.data["feed_hits"] = sorted({f for _, _, f, _ in hits})
    for t, v, f, w in hits:
        s.flag(f"blocklist.{t}", f"Listed in offline threat feed '{f}'", "critical", weight=w, evidence=f"{t}: {v}")
    return s
