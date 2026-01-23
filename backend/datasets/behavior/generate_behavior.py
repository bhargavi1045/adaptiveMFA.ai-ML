import pandas as pd
import numpy as np

np.random.seed(42)

rows = 12000

data = {
    "keystroke_interval_ms": np.random.normal(180, 40, rows),
    "mouse_speed_px_s": np.random.normal(900, 250, rows),
    "session_duration_s": np.random.normal(600, 200, rows),
    "click_rate": np.random.normal(3, 1, rows)
}

df = pd.DataFrame(data)

# Inject anomalies (bots / attackers)
anomaly_idx = np.random.choice(df.index, size=int(0.1 * rows))
df.loc[anomaly_idx, "mouse_speed_px_s"] *= 3
df.loc[anomaly_idx, "keystroke_interval_ms"] *= 0.3

df.to_csv("behavior_sessions.csv", index=False)
print("Behavior dataset generated")