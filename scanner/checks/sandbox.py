"""Optional headless-browser sandbox (Playwright + Chromium).

Renders the page like a real visitor would: follows JavaScript redirects, records every domain contacted,
captures a screenshot and the rendered DOM (fed back into the content check), and compares the screenshot
against visual references of genuine brand login pages. Every request the page makes is SSRF-checked.
"""
import importlib.util
import os
from urllib.parse import urlsplit

import config

from .. import data, net
from ..models import Section
from ..utils import registered_domain
from . import check


def available():
    return importlib.util.find_spec("playwright") is not None


def dhash(image_bytes, size=8):
    """64-bit difference hash of an image (perceptual: survives resizing / small changes)."""
    from io import BytesIO

    from PIL import Image
    img = Image.open(BytesIO(image_bytes)).convert("L").resize((size + 1, size), Image.LANCZOS)
    px = list(img.getdata())
    bits = 0
    for row in range(size):
        for col in range(size):
            left, right = px[row * (size + 1) + col], px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (left > right)
    return f"{bits:016x}"


def hamming(a, b):
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def render(url, timeout=None, screenshot_path=None):
    """Render a URL in headless Chromium. Returns a dict (raises if Playwright is unusable)."""
    from playwright.sync_api import Error as PWError
    from playwright.sync_api import sync_playwright

    timeout_ms = int((timeout or config.SANDBOX_TIMEOUT) * 1000)
    requests_log, blocked, downloads, dialogs, navigations = [], [], [], [], []

    def guard(route):
        req_url = route.request.url
        p = urlsplit(req_url)
        if p.scheme in ("data", "blob", "about"):
            return route.continue_()
        if p.scheme not in ("http", "https"):
            blocked.append(req_url[:200])
            return route.abort()
        try:
            net.resolve_public(p.hostname, p.port or (443 if p.scheme == "https" else 80))
        except (net.BlockedTarget, net.ResolveError) as e:
            if isinstance(e, net.BlockedTarget):
                blocked.append(req_url[:200])
            return route.abort()
        requests_log.append({"url": req_url[:300], "type": route.request.resource_type})
        return route.continue_()

    def ws_guard(ws):
        # context.route() never sees WebSockets, so without this a page could reach ws://192.168.x.x
        p = urlsplit(ws.url)
        try:
            net.resolve_public(p.hostname, p.port or (443 if p.scheme == "wss" else 80))
        except (net.BlockedTarget, net.ResolveError, ValueError) as e:
            if not isinstance(e, net.ResolveError):
                blocked.append(ws.url[:200])
            # Never connected to a server, so nothing reaches the network. (ws.close() here deadlocks
            # Playwright's sync API.)
            return
        requests_log.append({"url": ws.url[:300], "type": "websocket"})
        ws.connect_to_server()  # no message handlers set, so frames are forwarded as-is

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--no-first-run"])
        try:
            context = browser.new_context(user_agent=config.USER_AGENT, viewport={"width": 1366, "height": 768},
                                          ignore_https_errors=True, accept_downloads=False,
                                          service_workers="block", locale="en-US")
            context.route("**/*", guard)
            context.route_web_socket("**/*", ws_guard)
            page = context.new_page()
            page.on("download", lambda d: downloads.append({"url": d.url[:300], "filename": d.suggested_filename}))
            page.on("dialog", lambda d: (dialogs.append({"type": d.type, "message": d.message[:200]}), d.dismiss()))
            page.on("framenavigated", lambda fr: navigations.append(fr.url[:300]) if fr == page.main_frame else None)
            error = ""
            try:
                page.goto(url, wait_until="load", timeout=timeout_ms)
            except PWError as e:
                error = str(e).splitlines()[0][:200]
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PWError:
                pass
            shot = b""
            try:
                shot = page.screenshot(type="jpeg", quality=70, timeout=8000)
            except PWError:
                pass
            html = ""
            try:
                html = page.content()[:3_000_000]
            except PWError:
                pass
            cookies = [{"name": c["name"], "domain": c["domain"], "secure": c["secure"], "httpOnly": c["httpOnly"],
                        "sameSite": c.get("sameSite", "")} for c in context.cookies()]
            final_url = page.url
            title = ""
            try:
                title = page.title()[:200]
            except PWError:
                pass
        finally:
            browser.close()

    if shot and screenshot_path:
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
        with open(screenshot_path, "wb") as f:
            f.write(shot)
    return {"final_url": final_url, "title": title, "html": html, "screenshot": shot, "requests": requests_log,
            "blocked": blocked, "downloads": downloads, "dialogs": dialogs, "navigations": navigations,
            "cookies": cookies, "error": error}


@check("sandbox", "Browser sandbox", stage=2, requires="http", browser=True)
def run(ctx):
    s = Section()
    if not available():
        s.data["skipped"] = "Playwright is not installed (pip install -r requirements-browser.txt)"
        s.flag("sandbox.unavailable", "Browser sandbox not installed", "info", evidence=s.data["skipped"])
        return s
    shot_path = os.path.join(config.SCREENSHOT_DIR, f"{ctx.options.get('scan_id', 'scan')}.jpg")
    try:
        r = render(ctx.url, screenshot_path=shot_path)
    except Exception as e:
        msg = str(e).splitlines()[0][:200]
        if "Executable doesn't exist" in str(e):
            msg = "Chromium is missing: run 'python -m playwright install chromium'"
        s.data["skipped"] = msg
        s.flag("sandbox.failed", "Browser sandbox could not run", "info", evidence=msg)
        return s

    ctx.rendered_html = r["html"]
    page_domain = registered_domain(r["final_url"])
    domains = {}
    for req in r["requests"]:
        d = registered_domain(req["url"])
        if d:
            domains[d] = domains.get(d, 0) + 1
    trackers = sorted(d for d in domains if any(d == t or d.endswith("." + t) or t.endswith(d)
                                                for t in data.lists()["trackers"]))
    s.data.update({
        "final_url": r["final_url"], "title": r["title"], "error": r["error"],
        "screenshot": os.path.basename(shot_path) if r["screenshot"] else "",
        "requests": len(r["requests"]), "domains": sorted(domains.items(), key=lambda kv: -kv[1])[:40],
        "third_party": sorted(d for d in domains if d != page_domain), "trackers": trackers,
        "blocked": r["blocked"][:20], "downloads": r["downloads"], "dialogs": r["dialogs"],
        "navigations": list(dict.fromkeys(r["navigations"]))[:10], "cookies": r["cookies"][:40],
    })

    http_final = ctx.final_registered_domain
    if page_domain and page_domain != http_final:
        s.flag("sandbox.js_redirect", f"JavaScript sends visitors to {page_domain}", "medium", weight=0.2,
               evidence=f"HTTP ended on {http_final}, browser ended on {r['final_url'][:150]}")
    if r["downloads"]:
        s.flag("sandbox.drive_by", "Page started a file download on its own", "high", weight=0.4,
               evidence=r["downloads"][0]["filename"])
    if r["blocked"]:
        s.flag("sandbox.internal_requests", "Page tried to reach internal network addresses", "high", weight=0.3,
               evidence=r["blocked"][0], fix="Seen in router-attack and DNS-rebinding pages; requests were blocked.")
    if r["dialogs"]:
        s.flag("sandbox.dialogs", f"Page pops up {len(r['dialogs'])} dialog(s) on load", "low", weight=0.08,
               evidence=r["dialogs"][0]["message"])

    if r["screenshot"]:
        try:
            h = dhash(r["screenshot"])
            s.data["dhash"] = h
            owned = data.brand_domains()
            best = None
            for ref in data.brand_refs():
                dist = hamming(h, ref["dhash"])
                if dist <= 10 and (best is None or dist < best[0]):
                    best = (dist, ref)
            if best and owned.get(page_domain) != best[1]["brand"]:
                s.flag("sandbox.visual_clone", f"Looks visually like the {best[1]['brand']} login page", "critical",
                       weight=0.5, evidence=f"perceptual-hash distance {best[0]}/64 to {best[1]['url']}")
                s.data["visual_match"] = {"brand": best[1]["brand"], "distance": best[0]}
        except Exception as e:
            s.data["dhash_error"] = str(e)[:120]
    return s
