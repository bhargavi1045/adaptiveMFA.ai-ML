import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Get the correct path relative to this script
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, '../../datasets/behavior/behavior_sessions.csv')

print(f"Looking for CSV at: {csv_path}")
print(f"File exists: {os.path.exists(csv_path)}")

# Load dataset
df = pd.read_csv(csv_path)
print(f"Loaded {len(df)} rows of behavior data")

# Features
X = df[['keystroke_interval_ms', 'mouse_speed_px_s', 'session_duration_s', 'click_rate']]

# Train Isolation Forest for anomaly detection
print("Training Isolation Forest model...")
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

# Save model in the same directory as this script
model_path = os.path.join(script_dir, 'behavior_model.pkl')
joblib.dump(model, model_path)
print(f"Behavior model trained and saved to {model_path}")

# Test prediction
predictions = model.predict(X)
anomalies = np.sum(predictions == -1)
normal = np.sum(predictions == 1)
print(f"\nModel Performance:")
print(f"   Total sessions: {len(X)}")
print(f"   Normal behavior: {normal}")
print(f"   Anomalies detected: {anomalies}")
print(f"   Anomaly rate: {(anomalies/len(X))*100:.2f}%")

# Show sample predictions
print("\nSample predictions (first 5 rows):")
sample_df = df.head()
sample_predictions = model.predict(sample_df[['keystroke_interval_ms', 'mouse_speed_px_s', 'session_duration_s', 'click_rate']])
for i, pred in enumerate(sample_predictions):
    label = "ANOMALY" if pred == -1 else "NORMAL"
    print(f"   Row {i+1}: {label}")