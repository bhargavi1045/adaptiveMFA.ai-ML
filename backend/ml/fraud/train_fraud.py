import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load dataset
df = pd.read_csv(os.path.join(BASE_DIR, 'datasets', 'fraud', 'fraud_cases.csv'))

# Features and target
features = ['risk_score', 'failed_attempts', 'session_duration_s']
target = 'is_fraud'

X = df[features]
y = df[target]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_pred_proba = model.predict_proba(X_test)[:, 1]

print(classification_report(y_test, y_pred))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_pred_proba):.2f}")

model_path = os.path.join(BASE_DIR, 'ml', 'fraud', 'fraud_model.pkl')
joblib.dump(model, model_path)
print(f"Fraud model trained and saved at {model_path}")
