import os
from shodan import Shodan
from dotenv import load_dotenv
load_dotenv()

def shodan_lookup(ip):
    try:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {"error": "API key Shodan tidak ditemukan"}

        api = Shodan(api_key)
        host = api.host(ip)

        return {
            "Org": host.get("org"),
            "OS": host.get("os", "Unknown"),
            "Open Ports": host.get("ports", []),
            "Last Update": host.get("last_update"),
        }

    except Exception as e:
        return {"error": f"Data tidak tersedia / dibatasi oleh Shodan. ({str(e)})"}
