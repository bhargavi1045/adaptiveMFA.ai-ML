import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

# Get the correct path relative to this script
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, '../../datasets/context/login_events.csv')

print(f"Looking for CSV at: {csv_path}")
print(f"File exists: {os.path.exists(csv_path)}")

# Load dataset
df = pd.read_csv(csv_path)
print(f"Loaded {len(df)} rows of context data")

# Features and target
X = df[['new_device', 'ip_change', 'login_hour']]
y = (df['context_risk'] > 0.5).astype(int)  # Binary: high risk or not

print(f"\nDataset Overview:")
print(f"   Total logins: {len(df)}")
print(f"   High risk logins: {y.sum()} ({(y.sum()/len(y))*100:.2f}%)")
print(f"   Low risk logins: {(~y).sum()} ({((~y).sum()/len(y))*100:.2f}%)")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nData Split:")
print(f"   Training samples: {len(X_train)}")
print(f"   Testing samples: {len(X_test)}")

# Train model
print("\nTraining Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=100, 
    max_depth=10,
    random_state=42,
    class_weight='balanced'
)
model.fit(X_train, y_train)

# Evaluate
train_accuracy = model.score(X_train, y_train)
test_accuracy = model.score(X_test, y_test)
print(f"\nContext Model Performance:")
print(f"   Training accuracy: {train_accuracy:.2%}")
print(f"   Testing accuracy: {test_accuracy:.2%}")

# Detailed metrics
y_pred = model.predict(X_test)
print(f"\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Low Risk', 'High Risk']))

print(f"\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"   True Negatives: {cm[0][0]}, False Positives: {cm[0][1]}")
print(f"   False Negatives: {cm[1][0]}, True Positives: {cm[1][1]}")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(f"\nFeature Importance:")
for _, row in feature_importance.iterrows():
    print(f"   {row['feature']}: {row['importance']:.4f}")

# Save model in the same directory as this script
model_path = os.path.join(script_dir, 'context_model.pkl')
joblib.dump(model, model_path)
print(f"\nContext model trained and saved to {model_path}")

# Test prediction with sample data
print("\nSample predictions (first 5 rows):")
sample_df = X_test.head()
sample_predictions = model.predict(sample_df)
sample_proba = model.predict_proba(sample_df)

for i in range(len(sample_df)):
    risk_level = "HIGH RISK" if sample_predictions[i] == 1 else "LOW RISK"
    confidence = sample_proba[i][sample_predictions[i]] * 100
    print(f"   Sample {i+1}: {risk_level} (confidence: {confidence:.1f}%)")
    print(f"      New device: {sample_df.iloc[i]['new_device']}, "
          f"IP change: {sample_df.iloc[i]['ip_change']}, "
          f"Login hour: {sample_df.iloc[i]['login_hour']}")