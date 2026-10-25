"""Resource limits for analysing one message, so a hostile e-mail cannot stall the scanner."""
import os


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


MAX_MESSAGE_BYTES = _int("SCANNER_MAIL_MAX_MESSAGE_BYTES", 25 * 1024 * 1024)
MAX_ATTACHMENTS = 20                       # attachments + inline images analysed per message
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024    # larger attachments are listed but not analysed
MAX_TOTAL_ATTACHMENT_BYTES = 30 * 1024 * 1024
MAX_URLS = 30                              # distinct URLs analysed per message
MAX_UNWRAP_DEPTH = 3
TIME_BUDGET_SECONDS = _int("SCANNER_MAIL_TIME_BUDGET", 60)
LINK_WORKERS = 4
