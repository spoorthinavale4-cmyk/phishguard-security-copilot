import os
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import numpy as np

# ── Paths (always relative to this file, not the working directory) ──────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH   = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_PATH  = os.path.join(BASE_DIR, "models", "phishing_classifier.pkl")

# ── Feature order must EXACTLY match phishing_inference.py ───────────────────
FEATURE_ORDER = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report"
]

print("=" * 55)
print("  PhishGuard Model Training")
print("=" * 55)

# ── 1. Load dataset ───────────────────────────────────────────────────────────
df = pd.read_csv(DATA_PATH)
print(f"\n[1] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

# ── 2. Validate columns ───────────────────────────────────────────────────────
missing = [f for f in FEATURE_ORDER if f not in df.columns]
if missing:
    raise ValueError(f"Dataset is missing expected features: {missing}")
print(f"[2] All {len(FEATURE_ORDER)} expected features found ✓")

# ── 3. Class distribution ─────────────────────────────────────────────────────
counts = df["Result"].value_counts()
print(f"\n[3] Class distribution:")
print(f"    Phishing   (+1): {counts.get(1, 0):,}")
print(f"    Legitimate (-1): {counts.get(-1, 0):,}")
imbalance_ratio = counts.get(1, 0) / counts.get(-1, 1)
print(f"    Imbalance ratio: {imbalance_ratio:.2f}:1")

# ── 4. Prepare features and labels ───────────────────────────────────────────
# Explicitly select features in the exact order inference code expects
X = df[FEATURE_ORDER]
y = df["Result"]

# ── 5. Stratified train/test split ───────────────────────────────────────────
# stratify=y preserves the class ratio in both train and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y          # <-- preserves 56/44 ratio in both splits
)
print(f"\n[4] Train size: {len(X_train):,} | Test size: {len(X_test):,} (stratified)")

# ── 6. Train model ────────────────────────────────────────────────────────────
# class_weight='balanced' corrects for the phishing/legitimate imbalance.
# This was the primary cause of false positives on legitimate sites.
print("\n[5] Training RandomForest...")
model = RandomForestClassifier(
    n_estimators=200,           # more trees = more stable & accurate
    class_weight="balanced",    # corrects for 56/44 class imbalance
    random_state=42,
    n_jobs=-1                   # use all CPU cores for faster training
)
model.fit(X_train, y_train)
print("    Training complete ✓")

# ── 7. Cross-validation ───────────────────────────────────────────────────────
print("\n[6] Cross-validation (5-fold)...")
cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1_weighted', n_jobs=-1)
print(f"    F1 scores: {cv_scores.round(4)}")
print(f"    Mean F1:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ── 8. Evaluate on held-out test set ─────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n[7] Test Set Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate(-1)", "Phishing(+1)"]))

cm = confusion_matrix(y_test, y_pred)
print("[8] Confusion Matrix:")
print(f"    True Negatives  (legit  → legit ): {cm[0][0]:,}")
print(f"    False Positives (legit  → phish ): {cm[0][1]:,}  ← want this LOW")
print(f"    False Negatives (phish  → legit ): {cm[1][0]:,}  ← want this LOW")
print(f"    True Positives  (phish  → phish ): {cm[1][1]:,}")

# ── 9. Top feature importances ────────────────────────────────────────────────
importances = pd.Series(model.feature_importances_, index=FEATURE_ORDER)
top10 = importances.nlargest(10)
print("\n[9] Top 10 most important features:")
for feat, imp in top10.items():
    bar = "█" * int(imp * 200)
    print(f"    {feat:<35} {imp:.4f} {bar}")

# ── 10. Validate model classes ────────────────────────────────────────────────
print(f"\n[10] model.classes_ = {model.classes_}  (index 1 = phishing probability)")

# ── 11. Save model ────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump(model, MODEL_PATH)
print(f"\n[11] Model saved → {MODEL_PATH}")
print("=" * 55)
print("  Done! Retrain complete.")
print("=" * 55)