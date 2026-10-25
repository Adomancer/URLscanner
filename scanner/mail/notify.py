"""Desktop notification (Windows toast) for dangerous mail found by `gmail watch`.

The sender and subject are written by an attacker. They are therefore never put into the command
line: the PowerShell script below is a fixed string, the text travels in environment variables, and
the script XML-escapes it before building the toast. Elsewhere this is a no-op.
"""
import logging
import os
import re
import subprocess

log = logging.getLogger(__name__)

TITLE_VAR, BODY_VAR = "URLSCANNER_TOAST_TITLE", "URLSCANNER_TOAST_BODY"
_POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
SCRIPT = (
    "$ErrorActionPreference = 'Stop';"
    "[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime];"
    "[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime];"
    f"$t = [Security.SecurityElement]::Escape($env:{TITLE_VAR});"
    f"$b = [Security.SecurityElement]::Escape($env:{BODY_VAR});"
    "$x = New-Object Windows.Data.Xml.Dom.XmlDocument;"
    "$x.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>' + $t + '</text><text>' + $b +"
    " '</text></binding></visual></toast>');"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    f"'{_POWERSHELL_APP_ID}').Show([Windows.UI.Notifications.ToastNotification]::new($x))"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def clean(text, limit):
    """Printable text only (no control or bidi-override characters), at most `limit` characters."""
    text = _CONTROL.sub("", str(text or "")).replace("\r", " ")
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def toast(title, body, runner=subprocess.run):
    """Show a toast on Windows. Returns True if one was shown."""
    if os.name != "nt":
        return False
    env = dict(os.environ)
    env[TITLE_VAR] = clean(title, 80)
    env[BODY_VAR] = clean(body, 200)
    try:
        proc = runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SCRIPT], env=env,
                      shell=False, capture_output=True, timeout=20,
                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("toast failed: %s", type(e).__name__)
        return False
