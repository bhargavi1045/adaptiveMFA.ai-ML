import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor
import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

df = pd.read_csv(os.path.join(BASE_DIR, 'datasets', 'risk', 'risk_training.csv'))

features = ['behavior_risk', 'context_risk', 'velocity_risk']
target = 'risk_score'

X = df[features]
y = df[target]


model = GradientBoostingRegressor()
model.fit(X, y)

model_path = os.path.join(BASE_DIR, 'ml', 'risk', 'risk_model.pkl')
joblib.dump(model, model_path)

print(f"Risk model trained and saved at {model_path}")
