from email_parser import extract_urls
from phishing_inference import predict_phishing

# ===== Sample Email =====
email_text = """
Dear employee,

We detected unusual activity.
Verify your account immediately:

http://secure-login-paypal.xyz
"""

# ===== Extract URLs =====
urls = extract_urls(email_text)

print("\nExtracted URLs:", urls)

# ===== Simulate Features (temporary) =====
dummy_features = {
    "having_IP_Address": -1,
    "URL_Length": 1,
    "Shortining_Service": -1,
    "having_At_Symbol": -1,
    "double_slash_redirecting": -1,
    "Prefix_Suffix": -1,
    "having_Sub_Domain": 1,
    "SSLfinal_State": -1,
    "Domain_registeration_length": -1,
    "Favicon": 1,
    "port": 1,
    "HTTPS_token": -1,
    "Request_URL": 1,
    "URL_of_Anchor": -1,
    "Links_in_tags": 1,
    "SFH": -1,
    "Submitting_to_email": -1,
    "Abnormal_URL": -1,
    "Redirect": 0,
    "on_mouseover": 1,
    "RightClick": 1,
    "popUpWidnow": 1,
    "Iframe": -1,
    "age_of_domain": -1,
    "DNSRecord": -1,
    "web_traffic": 1,
    "Page_Rank": -1,
    "Google_Index": 1,
    "Links_pointing_to_page": 1,
    "Statistical_report": -1
}

# ===== Run Prediction =====
for url in urls:
    pred, prob = predict_phishing(dummy_features)

    print("\nURL:", url)
    print("Prediction:", "Phishing" if pred == -1 else "Legitimate")
    print("Confidence:", prob)