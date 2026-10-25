"""Runtime settings, read from the environment (or a local .env file).

No API keys are needed: every check runs locally against the target itself.
"""
import os
import secrets

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.getenv("SCANNER_OUTPUT_DIR", os.path.join(BASE_DIR, "outputs"))
DB_PATH = os.getenv("SCANNER_DB", os.path.join(OUTPUT_DIR, "scans.db"))
SCREENSHOT_DIR = os.path.join(OUTPUT_DIR, "screenshots")

def _persistent_secret():
    """Use SECRET_KEY if set; otherwise generate one and keep it (so sessions/CSRF survive
    restarts and are shared across gunicorn workers on the same machine)."""
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    path = os.path.join(OUTPUT_DIR, ".secret_key")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        if os.path.exists(path):
            return open(path, encoding="utf-8").read().strip()
        key = secrets.token_hex(32)
        with open(path, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        return secrets.token_hex(32)


# Flask session signing key.
SECRET_KEY = _persistent_secret()
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

# Web UI access control. When set, every page and API call needs this token (login form or
# "Authorization: Bearer <token>"). Set it whenever the UI is reachable by anyone but you (e.g. Docker).
ACCESS_TOKEN = os.getenv("SCANNER_ACCESS_TOKEN", "")
# Allow port scans from the web UI. Off by default: the CLI (--active --i-am-authorized) is the safer path.
WEB_ACTIVE = os.getenv("SCANNER_WEB_ACTIVE", "0") == "1"
# Trust X-Forwarded-For for rate limiting. Only enable behind a reverse proxy that sets it.
TRUST_PROXY = os.getenv("SCANNER_TRUST_PROXY", "0") == "1"

# Only for local testing: lets the scanner reach private/loopback addresses (disables SSRF protection).
ALLOW_PRIVATE_TARGETS = os.getenv("SCANNER_ALLOW_PRIVATE", "0") == "1"

HTTP_TIMEOUT = float(os.getenv("SCANNER_HTTP_TIMEOUT", "10"))
MAX_BODY_BYTES = int(os.getenv("SCANNER_MAX_BODY_BYTES", str(16 * 1024 * 1024)))
MAX_REDIRECTS = int(os.getenv("SCANNER_MAX_REDIRECTS", "10"))
SANDBOX_TIMEOUT = float(os.getenv("SCANNER_SANDBOX_TIMEOUT", "20"))

# --- Gmail scanner (scanner.mail) ---
# A Google *App Password* (Google account -> Security -> 2-Step Verification -> App passwords).
# It grants full mailbox access over IMAP: keep it only in .env and revoke it when unused.
GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
GMAIL_IMAP_HOST = os.getenv("GMAIL_IMAP_HOST", "imap.gmail.com")
# What link analysis of e-mail may touch: "dns" = DNS + WHOIS lookups of the domain (never the site
# itself); "none" = no network connection at all during analysis.
MAIL_NETWORK = "none" if os.getenv("SCANNER_MAIL_NETWORK", "dns").lower() == "none" else "dns"
try:  # bytes downloaded per Gmail run at most (Gmail rate-limits IMAP downloads)
    MAIL_MAX_RUN_BYTES = int(os.getenv("SCANNER_MAIL_MAX_RUN_BYTES", str(200 * 1024 * 1024)))
except ValueError:
    MAIL_MAX_RUN_BYTES = 200 * 1024 * 1024
# Host names the /mail pages answer to besides localhost (comma-separated). Pages that show your mail
# check the Host header so a DNS-rebinding web page cannot read them through your browser.
ALLOWED_HOSTS = {h.strip().lower() for h in os.getenv("SCANNER_ALLOWED_HOSTS", "").split(",") if h.strip()}

USER_AGENT = os.getenv(
    "SCANNER_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36",
)
