import pandas as pd
import numpy as np

rows = 10000
np.random.seed(42)

data = {
    "new_device": np.random.choice([0, 1], rows, p=[0.8, 0.2]),
    "ip_change": np.random.choice([0, 1], rows, p=[0.85, 0.15]),
    "login_hour": np.random.randint(0, 24, rows),
}

df = pd.DataFrame(data)

# Context risk score (0–1)
df["context_risk"] = (
    df["new_device"] * 0.5 +
    df["ip_change"] * 0.3 +
    ((df["login_hour"] < 6) | (df["login_hour"] > 22)).astype(int) * 0.2
)

df.to_csv("login_events.csv", index=False)
print("Context dataset generated")