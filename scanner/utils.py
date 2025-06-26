import requests
import socket
import shodan
import socket
from config import SHODAN_API_KEY
from config import VIRUSTOTAL_API_KEY
from urllib.parse import urlparse


def get_ip_from_url(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            return None
        return socket.gethostbyname(domain)
    except Exception:
        return None

def shodan_lookup(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports"),
            "last_update": host.get("last_update")
        }
    except Exception as e:
        return {"error": str(e)}
    
def virustotal_check_domain(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers)
        data = response.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)

        return {
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "reputation": reputation,
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}"
        }
    except Exception as e:
        return {"error": str(e)}
