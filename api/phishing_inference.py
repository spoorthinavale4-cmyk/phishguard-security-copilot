import os
import joblib
import pandas as pd
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_classifier.pkl")

model = joblib.load(MODEL_PATH)

# Training feature order
FEATURE_ORDER = [
    "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
    "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
    "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
    "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
    "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
    "Statistical_report"
]

THRESHOLD = 0.60


# Security intelligence lists
TRUSTED_DOMAINS = [
    "google.com","amazon.com","amazon.in","paypal.com",
    "microsoft.com","apple.com","icicibank.com"
]

KNOWN_BRANDS = [
    "google","amazon","paypal","microsoft","apple","facebook","netflix"
]

SUSPICIOUS_TLDS = [
    ".xyz",".top",".ru",".tk",".gq",".ml",".click",".link"
]

# Domains on these TLDs are almost always legitimate institutions
SAFE_TLDS = [
    ".ac.in", ".edu.in", ".gov.in", ".nic.in", ".res.in",
    ".edu", ".gov", ".mil", ".ac.uk", ".gov.uk"
]


def is_trusted(domain):
    return any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)


def is_safe_tld(domain):
    return any(domain.endswith(tld) for tld in SAFE_TLDS)


def predict_phishing(url, features_dict):

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    signals = []

    # 1️⃣ Trusted domain override
    if is_trusted(domain):
        return {
            "prediction": "legitimate",
            "confidence": 0.95,
            "risk_level": "low",
            "signals": ["trusted_domain"]
        }

    # 2️⃣ Safe TLD override (educational, government domains)
    if is_safe_tld(domain):
        return {
            "prediction": "legitimate",
            "confidence": 0.85,
            "risk_level": "low",
            "signals": ["safe_institutional_tld"]
        }

    # 3️⃣ Brand impersonation detection
    if any(brand in domain for brand in KNOWN_BRANDS) and not is_trusted(domain):
        signals.append("brand_impersonation")

    # 4️⃣ Suspicious TLD detection
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        signals.append("risky_tld")

    # 5️⃣ Non-secure protocol signal
    if parsed.scheme == "http":
        signals.append("non_secure_protocol")

    # Ensure feature order matches training
    ordered_features = {k: features_dict[k] for k in FEATURE_ORDER}

    df = pd.DataFrame([ordered_features])

    probs = model.predict_proba(df)[0]

    # model.classes_ == [-1, 1]  →  index 1 is the phishing class
    phishing_prob = probs[1]

    prediction = "phishing" if phishing_prob >= THRESHOLD else "legitimate"

    risk = "high" if phishing_prob > 0.75 else "medium" if phishing_prob > 0.60 else "low"

    return {
        "prediction": prediction,
        "confidence": float(phishing_prob),
        "risk_level": risk,
        "signals": signals
    }