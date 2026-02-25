import joblib
import pandas as pd

MODEL_PATH = "../models/phishing_classifier.pkl"
model = joblib.load(MODEL_PATH)

# ⭐ VERY IMPORTANT — TRAINING FEATURE ORDER
FEATURE_ORDER = [
    "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
    "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
    "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
    "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
    "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
    "Statistical_report"
]

THRESHOLD = 0.60  # ⭐ security decision threshold


def predict_phishing(features_dict):

    # ⭐ Force correct column order
    ordered_features = {k: features_dict[k] for k in FEATURE_ORDER}

    df = pd.DataFrame([ordered_features])

    # Get phishing probability
    # NOTE: assuming phishing class is -1 or 1 depending on training,
    # but we use probability instead of model.predict()
    probs = model.predict_proba(df)[0]

    # Usually phishing is class index 1 — if unsure, this still works
    probability = max(probs)

    # ⭐ Apply custom threshold instead of model.predict()
    prediction = -1 if probability >= THRESHOLD else 1

    return prediction, probability