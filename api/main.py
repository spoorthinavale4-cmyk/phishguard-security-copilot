from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

from url_feature_extractor import extract_features_from_url
from siem_checker import check_siem_for_clicks
from email_parser import extract_urls
from phishing_inference import predict_phishing
from llm_explainer import generate_llm_explanation

# ⭐ THIS MUST COME BEFORE ANY ROUTES
app = FastAPI(title="PhishGuard Security Copilot API")


class EmailRequest(BaseModel):
    email_text: str


@app.post("/analyze-email")
def analyze_email(request: EmailRequest):

    urls = extract_urls(request.email_text)
    results = []

    TRUSTED_DOMAINS = ["google.com", "microsoft.com", "paypal.com", "amazon.com"]
    KNOWN_BRANDS = ["google", "microsoft", "paypal", "amazon", "apple", "facebook"]

    def is_trusted(d):
        return any(d == td or d.endswith("." + td) for td in TRUSTED_DOMAINS)

    def has_brand(d):
        return any(b in d for b in KNOWN_BRANDS)

    for url in urls:
        try:
            print("DEBUG URL:", url)

            features = extract_features_from_url(url)
            print("DEBUG FEATURES:", features)

            pred, prob = predict_phishing(features)
            print("DEBUG MODEL OUTPUT:", pred, prob)
            domain = urlparse(url).netloc.lower()
            domain = domain.split(":")[0]

# ⭐ Legitimate-domain safeguard
            SAFE_TOP_LEVEL_DOMAINS = [
            "github.com",
            "openai.com",
            "google.com",
            "microsoft.com",
            "microsoftonline.com",
            "amazon.com",
            "paypal.com"
]

            if any(domain == d or domain.endswith("." + d) for d in SAFE_TOP_LEVEL_DOMAINS):
                prob = min(prob, 0.40)  # lower risk score

            # ⭐ Risk-tier labeling (safer than hard phishing/legit)
            if prob >= 0.70:
                label = "phishing"
            elif prob >= 0.45:
                label = "suspicious"
            else:
                label = "legitimate"

            

            # ⭐ SECURITY OVERRIDE RULE (brand impersonation)
            domain = urlparse(url).netloc.lower()
            domain = domain.split(":")[0]
            # ⭐ Phase-2: Security Signals
            signals = []
            # Signal 1️⃣ : Non-secure protocol
            if url.startswith("http://"):
                signals.append("non_secure_protocol")

            # Signal 2️⃣ : Brand impersonation pattern
            if has_brand(domain) and not is_trusted(domain):
                signals.append("brand_impersonation") 

            # Signal 3️⃣ : Risky top-level domain
            RISKY_TLDS = [".ru", ".tk", ".xyz", ".top", ".click"]

            if any(domain.endswith(tld) for tld in RISKY_TLDS):
                signals.append("risky_tld")   

            if has_brand(domain) and not is_trusted(domain) and prob >= 0.55:
                    label = "phishing"
                    prob = max(prob, 0.75)
             # ⭐ Risk-level scoring (Phase 1 upgrade)
            if prob >= 0.75:
                risk_level = "high"
            elif prob >= 0.45:
                risk_level = "medium"
            else:
                risk_level = "low"       
            
            # ⭐ Phase-3: Decision Summary (rule-based reasoning)
            if label == "phishing":
                if "brand_impersonation" in signals:
                    decision_summary = "High-risk phishing due to brand impersonation"
                elif "non_secure_protocol" in signals:
                    decision_summary = "Phishing risk due to insecure protocol"
                else:
                    decision_summary = "Phishing detected by model indicators"
            elif label == "suspicious":
                    decision_summary = "Suspicious indicators detected"
            else:
                decision_summary = "No strong phishing indicators"

            explanation = generate_llm_explanation(url, label, prob)
            print("DEBUG LLM DONE")

            siem_data = {}

            if label == "phishing":
                impacted_users = check_siem_for_clicks(url)

                if impacted_users:
                    siem_data = {
                        "clicked_users": impacted_users,
                        "recommended_action": "Force password reset and investigate accounts"
                    }

            results.append({
                "url": url,
                "prediction": label,
                "confidence": float(prob),
                "risk_level": risk_level,
                "signals": signals,
                "decision_summary": decision_summary,
                "explanation": explanation,
                "siem_alert": siem_data
            })

        except Exception as e:
            print("🔥 REAL ERROR OCCURRED:", str(e))
            raise

    return {
        "extracted_urls": urls,
        "analysis": results
    }