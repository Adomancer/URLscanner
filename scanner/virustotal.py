import requests
import os
from dotenv import load_dotenv
load_dotenv()

def virustotal_check_domain(domain):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "API key VirusTotal tidak ditemukan."}

    headers = {"x-apikey": api_key}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        data = response.json()

        attributes = data["data"]["attributes"]
        last_analysis = attributes["last_analysis_stats"]

        return {
            "harmless": last_analysis.get("harmless"),
            "suspicious": last_analysis.get("suspicious"),
            "malicious": last_analysis.get("malicious"),
            "reputation": attributes.get("reputation"),
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}"
        }

    except Exception as e:
        return {"error": str(e)}
