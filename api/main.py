from fastapi import Request, FastAPI
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from urllib.parse import urlparse

from api.url_feature_extractor import extract_features_from_url
from api.siem_checker import check_siem_for_clicks
from api.email_parser import extract_urls
from api.phishing_inference import predict_phishing
from api.safe_browsing import check_url_safe_browsing, threat_type_to_label
from api.llm_explainer import generate_llm_explanation


app = FastAPI(title="PhishGuard Security Copilot API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded. Try again later."},
    )


class EmailRequest(BaseModel):
    email_text: str


@app.post("/analyze-email")
@limiter.limit("10/minute")
def analyze_email(request: Request, body: EmailRequest):

    urls = extract_urls(body.email_text)
    results = []

    for url in urls:

        try:
            print("DEBUG URL:", url)

            features = extract_features_from_url(url)
            print("DEBUG FEATURES:", features)

            # FIXED LINE
            result = predict_phishing(url, features)

            label = result["prediction"]
            prob = result["confidence"]
            risk_level = result["risk_level"]
            signals = result["signals"]

            # ── Google Safe Browsing hard override ──────────────────────────
            sb = check_url_safe_browsing(url)
            if sb["available"] and sb["is_threat"]:
                # Google has confirmed this URL is malicious — trust it fully
                threat_signal = threat_type_to_label(sb["threat_type"])
                label = "phishing"
                prob = 0.99
                risk_level = "high"
                if threat_signal not in signals:
                    signals = [threat_signal] + signals
            # ────────────────────────────────────────────────────────────────

            domain = urlparse(url).netloc.lower().split(":")[0]

            SAFE_TOP_LEVEL_DOMAINS = [
                "github.com",
                "openai.com",
                "google.com",
                "microsoft.com",
                "microsoftonline.com",
                "amazon.com",
                "paypal.com",
                "stackoverflow.com",
                "wikipedia.org",
            ]

            SAFE_TLDS = [
                ".ac.in", ".edu.in", ".gov.in", ".nic.in", ".res.in",
                ".edu", ".gov", ".mil", ".ac.uk", ".gov.uk",
            ]

            safe_tld_match = any(domain.endswith(t) for t in SAFE_TLDS)

            # Only cap phishing confidence — never overwrite a legitimate verdict
            if label == "phishing":
                if any(domain == d or domain.endswith("." + d) for d in SAFE_TOP_LEVEL_DOMAINS) or safe_tld_match:
                    prob = min(prob, 0.40)
                    # Recalculate label and risk consistently with the new capped probability
                    label = "phishing" if prob >= 0.60 else "legitimate"
                    risk_level = "high" if prob > 0.75 else "medium" if prob > 0.60 else "low"

            # Decision summary
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

            # LLM explanation temporarily disabled to preserve API quota.
            # Re-enable by uncommenting the line below and removing the placeholder.
            # explanation = generate_llm_explanation(url, label, prob)
            explanation = "AI explanation is temporarily disabled."

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
            print("REAL ERROR OCCURRED:", str(e))
            raise

    return {
        "extracted_urls": urls,
        "analysis": results
    }