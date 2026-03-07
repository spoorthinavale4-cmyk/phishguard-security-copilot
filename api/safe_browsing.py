import os
import requests
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat types to check against
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",   # Phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_url_safe_browsing(url: str) -> dict:
    """
    Check a single URL against Google Safe Browsing API.

    Returns:
        {
            "is_threat": bool,
            "threat_type": str or None,   # e.g. "SOCIAL_ENGINEERING"
            "available": bool             # False if API key missing or request failed
        }
    """
    if not SAFE_BROWSING_API_KEY:
        return {"is_threat": False, "threat_type": None, "available": False}

    payload = {
        "client": {
            "clientId": "phishguard-security-copilot",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=5
        )

        if response.status_code != 200:
            return {"is_threat": False, "threat_type": None, "available": False}

        data = response.json()

        # If "matches" key exists and is non-empty → URL is a known threat
        matches = data.get("matches", [])
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN_THREAT")
            return {"is_threat": True, "threat_type": threat_type, "available": True}

        # No matches → Google has no record of this URL being malicious
        return {"is_threat": False, "threat_type": None, "available": True}

    except Exception as e:
        print("Safe Browsing API error:", str(e))
        return {"is_threat": False, "threat_type": None, "available": False}


def threat_type_to_label(threat_type: str) -> str:
    """Convert Google's threat type string to a human-readable signal label."""
    mapping = {
        "SOCIAL_ENGINEERING": "google_confirmed_phishing",
        "MALWARE": "google_confirmed_malware",
        "UNWANTED_SOFTWARE": "google_confirmed_unwanted_software",
        "POTENTIALLY_HARMFUL_APPLICATION": "google_confirmed_harmful_app",
    }
    return mapping.get(threat_type, "google_confirmed_threat")
