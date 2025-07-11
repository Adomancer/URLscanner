import requests
import socket
import validators
from urllib.parse import urlparse
from .utils import get_ip_from_url
from .shodan import shodan_lookup
from .virustotal import virustotal_check_domain
from .utils import get_ip_from_url


SECURITY_HEADERS = [
    "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "Referrer-Policy"
]

def scan_url(url):
    result = {
        "url": url,
        "headers": {},
        "missing_headers": [],
        "redirects": [],
        "status_code": None,
        "ip": None,
        "shodan_info": None,
        "virustotal": None
    }

    if not validators.url(url):
        result["error"] = "❌ URL tidak valid. Harus dimulai dengan http:// atau https://"
        return result

    if len(url) > 2048:
        result["error"] = "❌ URL terlalu panjang. Maksimal 2048 karakter."
        return result

    try:
        ip = get_ip_from_url(url)
        result["ip"] = ip
        if ip and (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254.")):
            result["error"] = "❌ Diblokir: Target berada di jaringan internal (kemungkinan SSRF)"
            return result

    except Exception as e:
        result["error"] = f"Gagal resolve IP: {str(e)}"
        return result

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["redirects"] = [r.url for r in response.history]

        for header in SECURITY_HEADERS:
            if header not in response.headers:
                result["missing_headers"].append(header)

    except requests.exceptions.Timeout:
        result["error"] = "❌ Timeout! Server tidak merespons dalam 10 detik."
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"❌ Permintaan gagal: {str(e)}"
        return result

    if ip:
        result["shodan_info"] = shodan_lookup(ip)

    domain = urlparse(url).netloc
    result["virustotal"] = virustotal_check_domain(domain)

    return result
