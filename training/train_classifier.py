print("SCRIPT STARTED")
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

# ===== 1. Load Dataset =====
data_path = "../data/dataset.csv"
df = pd.read_csv(data_path)

# ===== 2. Prepare Features =====
X = df.drop(columns=["id", "Result"])
y = df["Result"]

# ===== 3. Train/Test Split =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ===== 4. Train Model =====
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ===== 5. Evaluate =====
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# ===== 6. Save Model =====
os.makedirs("../models", exist_ok=True)
joblib.dump(model, "../models/phishing_classifier.pkl")

print("Model saved inside models/phishing_classifier.pkl")