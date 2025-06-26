from dotenv import load_dotenv
import os

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")