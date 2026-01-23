import pandas as pd
import numpy as np

rows = 6000
np.random.seed(42)

data = {
    "risk_score": np.random.uniform(0, 1, rows),
    "failed_attempts": np.random.poisson(1.2, rows),
    "session_duration_s": np.random.normal(500, 180, rows),
}

df = pd.DataFrame(data)

# Fraud label
df["is_fraud"] = (
    (df["risk_score"] > 0.75) |
    (df["failed_attempts"] > 4)
).astype(int)

df.to_csv("fraud_cases.csv", index=False)
print("Fraud dataset generated")
