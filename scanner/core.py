"""Scan orchestrator: normalise the URL, run checks stage by stage in parallel, score, store."""
import datetime as dt
import ipaddress
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlunsplit

import idna

from . import __version__, net, storage
from .checks import ScanContext, load_all
from .extract import refang
from .models import Finding, Section
from .scoring import consensus, correlate, score

MAX_URL_LENGTH = 2048
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


class InvalidURL(ValueError):
    pass


def normalize_url(raw):
    """Refang, add a scheme if missing, IDNA-encode the host, and validate. Raises InvalidURL."""
    url = refang((raw or "").strip())
    if not url:
        raise InvalidURL("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise InvalidURL("URL contains whitespace or control characters.")
    if not _SCHEME.match(url):
        if url.startswith("//"):
            url = url[2:]
        url = "https://" + url
    p = urlsplit(url)
    if p.scheme.lower() not in ("http", "https"):
        raise InvalidURL("Only http:// and https:// URLs can be scanned.")
    try:
        host = p.hostname
        port = p.port
    except ValueError:
        raise InvalidURL("Invalid port in URL.") from None
    if not host:
        raise InvalidURL("URL has no hostname.")
    host = host.rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        ascii_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError:
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise InvalidURL("Hostname is not a valid domain name.") from None
        if "." not in ascii_host:
            raise InvalidURL("Hostname must be a full domain name (e.g. example.com).")
    netloc = ascii_host
    if port:
        netloc += f":{port}"
    if p.username is not None:
        userinfo = p.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def new_scan_id():
    return uuid.uuid4().hex[:12]


def _error_result(scan_id, raw, url, message, options):
    return {"id": scan_id, "input": raw, "url": url or raw, "host": "", "error": message, "options": options,
            "risk_score": None, "verdict": "Error", "grade": "N/A", "posture_score": None, "reasons": [],
            "findings": [], "sections": {}, "checks": {}, "version": __version__,
            "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "duration_ms": 0}


def scan_url(raw_url, *, active=False, browser=False, authorized=False, scan_id=None, progress=None,
             store=True, batch_id=None):
    """Run a full scan and return a JSON-serialisable dict.

    active   -- run active checks (port scan); only honoured together with authorized=True
    browser  -- run the headless-browser sandbox (needs Playwright)
    progress -- optional callback(dict) receiving per-check status updates
    """
    scan_id = scan_id or new_scan_id()
    options = {"active": bool(active and authorized), "browser": bool(browser), "scan_id": scan_id}
    started = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()

    try:
        url = normalize_url(raw_url)
    except InvalidURL as e:
        result = _error_result(scan_id, raw_url, None, str(e), options)
        if store:
            storage.save_result(scan_id, result)
        return result

    ctx = ScanContext(url, options)
    try:
        ctx.ips = net.resolve_public(ctx.host, ctx.port)
    except net.BlockedTarget as e:
        result = _error_result(scan_id, raw_url, url, str(e), options)
        result["host"] = ctx.host
        if store:
            storage.save_result(scan_id, result)
        return result
    except net.ResolveError as e:
        ctx.resolve_error = str(e)

    checks = [c for c in load_all() if (not c.active or options["active"]) and (not c.browser or options["browser"])]
    state = {c.name: {"title": c.title, "status": "queued"} for c in checks}

    def report(name, **kw):
        state[name].update(kw)
        if progress:
            try:
                progress({k: dict(v) for k, v in state.items()})
            except Exception:
                pass

    findings = []
    for stage in (1, 2, 3):
        batch = []
        for c in checks:
            if c.stage != stage:
                continue
            if c.requires == "resolved" and not ctx.ips:
                report(c.name, status="skipped", note="domain does not resolve")
            elif c.requires == "http" and not ctx.fetch:
                report(c.name, status="skipped", note=ctx.fetch_error or ctx.resolve_error or "no HTTP response")
            else:
                batch.append(c)
        if not batch:
            continue
        with ThreadPoolExecutor(max_workers=min(8, len(batch))) as pool:
            futures = {}
            for c in batch:
                report(c.name, status="running")
                futures[pool.submit(_run_check, c, ctx)] = c
            for fut in as_completed(futures):
                c = futures[fut]
                section, err, ms = fut.result()
                if err:
                    report(c.name, status="error", ms=ms, note=err)
                    findings.append(Finding(f"{c.name}.check_error", f"{c.title} check failed", "info",
                                            evidence=err, category=c.name))
                    continue
                ctx.sections[c.name] = section.data
                for f in section.findings:
                    f.category = f.category or c.name
                findings.extend(section.findings)
                report(c.name, status="done", ms=ms, findings=len(section.findings))

    if ctx.resolve_error:
        findings.append(Finding("dns.unresolvable", "Domain does not resolve (offline, parked or taken down)", "low",
                                weight=0.1, evidence=ctx.resolve_error, category="dns"))
    findings.extend(correlate(findings, ctx.sections))
    findings = _dedupe(findings)
    verdict = score(findings, trusted=ctx.trusted, fetched=ctx.fetch is not None)
    detections = consensus(state, findings, ctx.sections)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_rank.get(f.severity, 5), -f.weight, -f.penalty))
    result = {
        "id": scan_id,
        "version": __version__,
        "input": raw_url,
        "url": url,
        "host": ctx.host,
        "host_unicode": ctx.host_unicode,
        "registered_domain": ctx.registered_domain,
        "trusted_domain": ctx.trusted,
        "final_url": ctx.final_url,
        "ips": ctx.ips,
        "status_code": ctx.fetch.status if ctx.fetch else None,
        "resolve_error": ctx.resolve_error,
        "fetch_error": ctx.fetch_error,
        "started_at": started_at,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "options": options,
        **verdict,
        "detections": detections,
        "history": storage.host_stats(ctx.host, exclude=scan_id),
        "findings": [f.to_dict() for f in findings],
        "sections": ctx.sections,
        "checks": state,
        "error": None,
    }
    if store:
        storage.save_result(scan_id, result)
    return result


def _run_check(c, ctx):
    t0 = time.monotonic()
    try:
        section = c.func(ctx)
        if not isinstance(section, Section):
            raise TypeError(f"check returned {type(section).__name__}, expected Section")
        return section, None, int((time.monotonic() - t0) * 1000)
    except Exception as e:  # a broken check must never break the scan
        return None, f"{type(e).__name__}: {str(e)[:200]}", int((time.monotonic() - t0) * 1000)


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f.id, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_many(urls, workers=4, **kwargs):
    """Scan several URLs concurrently (results in input order)."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(lambda u: scan_url(u, **kwargs), urls))
