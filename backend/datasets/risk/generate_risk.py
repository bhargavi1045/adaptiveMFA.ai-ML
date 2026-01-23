import pandas as pd
import numpy as np

rows = 8000
np.random.seed(42)

data = {
    "behavior_risk": np.random.uniform(0, 1, rows),
    "context_risk": np.random.uniform(0, 1, rows),
    "velocity_risk": np.random.uniform(0, 1, rows),
}

df = pd.DataFrame(data)

df["risk_score"] = (
    df["behavior_risk"] * 0.4 +
    df["context_risk"] * 0.4 +
    df["velocity_risk"] * 0.2
)

df.to_csv("risk_training.csv", index=False)
print("Risk dataset generated")
