"""Technology fingerprinting from local signatures + end-of-life / known-vulnerable version rules."""
import re

from .. import data
from ..models import Section
from ..utils import version_tuple
from . import check
from .headers import parse_cookie


def _match(rx, value):
    if rx == "":
        return True, ""
    m = re.search(rx, value, re.I)
    if not m:
        return False, ""
    ver = next((g for g in m.groups() if g), "") if m.groups() else ""
    return True, ver


def fingerprint(headers, cookies, html, script_srcs, metas):
    h = {k.lower(): v for k, v in headers.items()}
    found = {}
    for sig in data.tech_signatures():
        hit, version = False, ""
        for name, rx in sig.get("headers", {}).items():
            if name in h:
                ok, v = _match(rx, h[name])
                if ok:
                    hit, version = True, version or v
        for rx in sig.get("cookies", []):
            if any(re.search(rx, c, re.I) for c in cookies):
                hit = True
        for name, rx in sig.get("meta", {}).items():
            if name in metas:
                ok, v = _match(rx, metas[name])
                if ok:
                    hit, version = True, version or v
        for rx in sig.get("scripts", []):
            for src in script_srcs:
                ok, v = _match(rx, src)
                if ok:
                    hit, version = True, version or v
                    break
        for rx in sig.get("html", []):
            m = re.search(rx, html[:1_500_000], re.I)
            if m:
                hit = True
                if m.groups() and m.group(1):
                    version = version or m.group(1)
        if hit:
            found[sig["name"]] = {"name": sig["name"], "category": sig["category"], "version": version.strip(".")}
    return list(found.values())


def eol_findings(techs):
    out = []
    for t in techs:
        if not t["version"]:
            continue
        v = version_tuple(t["version"])
        if not v:
            continue
        for rule in data.eol_rules():
            if rule["tech"] != t["name"]:
                continue
            if v < version_tuple(rule["below"]) and v >= version_tuple(rule.get("min", "0")):
                out.append((t, rule))
                break
    return out


@check("tech", "Technology stack", stage=2, requires="http")
def run(ctx):
    s = Section()
    f = ctx.fetch
    soup = ctx.soup
    cookies = [parse_cookie(c)["name"] for c in f.set_cookies]
    scripts = [sc.get("src") for sc in soup.find_all("script") if sc.get("src")]
    metas = {}
    for m in soup.find_all("meta"):
        name = (m.get("name") or "").lower()
        if name and m.get("content"):
            metas[name] = m["content"]
    techs = fingerprint(f.headers, cookies, ctx.html, scripts, metas)
    s.data["technologies"] = sorted(techs, key=lambda t: (t["category"], t["name"]))
    for t, rule in eol_findings(techs):
        t["eol"] = rule["note"]
        s.flag(f"tech.outdated.{t['name'].lower().replace(' ', '_')}", f"Outdated {t['name']} {t['version']}",
               rule["severity"], penalty=rule["penalty"], evidence=rule["note"],
               fix=f"Upgrade {t['name']} to a supported release.")
    return s
