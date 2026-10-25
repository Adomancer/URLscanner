"""Loaders for the bundled offline datasets (cached after first use)."""
import json
import os
from functools import lru_cache

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKLIST_DIR = os.path.join(DATA_DIR, "blocklists")
BRAND_REF_DIR = os.path.join(DATA_DIR, "brand_refs")


def _path(name):
    return os.path.join(DATA_DIR, name)


def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


@lru_cache(maxsize=None)
def json_file(name):
    with open(_path(name), encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=None)
def brands():
    return json_file("brands.json")


@lru_cache(maxsize=None)
def brand_domains():
    """registered domain -> brand name"""
    out = {}
    for b in brands():
        for d in b["domains"]:
            out[d.lower()] = b["brand"]
    return out


@lru_cache(maxsize=None)
def brand_sender_domains():
    """registered domain -> brand name, for domains a brand legitimately sends e-mail from."""
    out = dict(brand_domains())
    for b in brands():
        for d in b.get("sender_domains", []):
            out[d.lower()] = b["brand"]
    return out


@lru_cache(maxsize=None)
def confusables():
    return {k: v for k, v in json_file("confusables.json").items() if not k.startswith("_")}


@lru_cache(maxsize=None)
def lists():
    return json_file("lists.json")


@lru_cache(maxsize=None)
def freemail_domains():
    return frozenset(lists().get("freemail_domains", []))


def abused_platform(host):
    """The platform entry if anyone can publish content under this host (Google Forms, OneDrive...)."""
    host = (host or "").lower().rstrip(".")
    return next((p for p in lists().get("abused_platforms", []) if host == p or host.endswith("." + p)), "")


def mail_allowlist():
    """Trusted senders (addresses or registered domains). Re-read on every call so edits apply at once."""
    return frozenset(x.lower() for x in _read_lines(_path("mail_allowlist.txt")))


@lru_cache(maxsize=None)
def trusted_domains():
    """Top sites + brand-owned domains + user allowlist (used to dampen weak signals)."""
    out = set(d.lower() for d in _read_lines(_path("top_domains.txt")))
    out.update(brand_domains())
    out.update(d.lower() for d in _read_lines(_path("allowlist.txt")))
    return frozenset(out)


@lru_cache(maxsize=None)
def tech_signatures():
    return json_file("tech_signatures.json")


@lru_cache(maxsize=None)
def eol_rules():
    return json_file("eol_versions.json")


@lru_cache(maxsize=None)
def takeover_fingerprints():
    return json_file("takeover_fingerprints.json")


def favicon_hashes():
    """brand -> [mmh3 favicon hashes]  (built by tools/build_brand_data.py)"""
    path = _path("favicon_hashes.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def brand_refs():
    """Visual reference hashes captured with `cli.py add-brand-ref`."""
    out = []
    if not os.path.isdir(BRAND_REF_DIR):
        return out
    for name in sorted(os.listdir(BRAND_REF_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(BRAND_REF_DIR, name), encoding="utf-8") as f:
                out.extend(json.load(f))
    return out
