"""Main HTTP fetch (SSRF-safe). Every later check reuses ctx.fetch instead of re-requesting."""
from urllib.parse import urlsplit

import requests

from .. import net
from ..models import Section
from . import check


def _http_probe_url(ctx):
    """Plain-HTTP twin of an https:// target on port 80, or None when the target uses a custom port
    (a custom HTTPS port says nothing about what port 80 does)."""
    if ctx.parts.port not in (None, 443):
        return None
    host = f"[{ctx.host}]" if ":" in ctx.host else ctx.host
    return f"http://{host}/"


@check("http", "HTTP response", requires="resolved")
def run(ctx):
    s = Section()
    try:
        ctx.fetch = net.safe_fetch(ctx.url)
    except net.BlockedTarget as e:
        ctx.fetch_error = str(e)
        s.flag("http.blocked", "Request blocked (target resolves to an internal address)", "high", weight=0.3,
               evidence=str(e))
        return s
    except requests.exceptions.Timeout:
        ctx.fetch_error = "timed out"
        s.flag("http.timeout", "Server did not respond in time", "info", evidence=ctx.url)
        return s
    except (requests.RequestException, net.ResolveError) as e:
        ctx.fetch_error = str(e)[:300]
        s.flag("http.unreachable", "Site could not be fetched", "info", evidence=str(e)[:300])
        return s

    f = ctx.fetch
    s.data.update({
        "status": f.status,
        "final_url": f.final_url,
        "content_type": f.content_type,
        "bytes": len(f.body),
        "truncated": f.truncated,
        "elapsed_ms": f.elapsed_ms,
        "hops": len(f.chain),
        "cert_error": f.cert_error,
        "stopped_reason": f.stopped_reason,
    })
    if f.stopped_reason:
        s.flag("http.redirect_stopped", "Redirect chain was stopped", "medium", weight=0.15, evidence=f.stopped_reason)

    final = urlsplit(f.final_url)
    if final.scheme == "http":
        s.flag("http.plaintext", "Page is served over plain HTTP (no encryption)", "medium", weight=0.05, penalty=20,
               evidence=f.final_url, fix="Serve the site over HTTPS and redirect HTTP to HTTPS.")
    elif ctx.scheme == "https":
        # Does the plain-HTTP version upgrade visitors to HTTPS?
        http_url = _http_probe_url(ctx)
        s.data["http_upgrade"] = None  # unknown: custom port, or port 80 closed (which is fine)
        if http_url:
            try:
                probe = net.safe_fetch(http_url, max_redirects=0, max_bytes=1024, timeout=6)
                loc = probe.chain[0].location if probe.chain else ""
                s.data["http_upgrade"] = loc.startswith("https://")
                if probe.status and not (300 <= probe.status < 400 and loc.startswith("https://")):
                    s.flag("http.no_upgrade", "Plain HTTP does not redirect to HTTPS", "low", penalty=5,
                           evidence=f"{http_url} -> {probe.status} {loc}".strip(),
                           fix="Answer port 80 with a 301 redirect to https://.")
            except Exception:
                pass
    if f.status >= 400:
        s.flag("http.error_status", f"Server answered with HTTP {f.status}", "info", evidence=f.final_url)
    return s
