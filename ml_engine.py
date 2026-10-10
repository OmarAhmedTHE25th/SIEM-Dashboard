import sqlite3
import pandas as pd
import numpy as np
import os
from sklearn.ensemble import IsolationForest
import joblib

DB_NAME = os.path.expanduser("~/siem.db")
MODEL_FILE = "/home/omar-25th/siem_isoforest.joblib"

FEATURE_COLS = ["total_attempts", "failure_rate", "unique_users", "mean_interval", "std_interval"]


def transform_features(df: pd.DataFrame) -> pd.DataFrame:
    """Log-transforms heavy-tailed features so orders of magnitude stand out."""
    df_transformed = df.copy()
    df_transformed["total_attempts"] = np.log1p(df_transformed["total_attempts"])
    df_transformed["unique_users"] = np.log1p(df_transformed["unique_users"])
    df_transformed["mean_interval"] = np.log1p(df_transformed["mean_interval"])
    df_transformed["std_interval"] = np.log1p(df_transformed["std_interval"])
    return df_transformed[FEATURE_COLS]


def extract_features_from_db() -> pd.DataFrame:
    conn = sqlite3.connect(DB_NAME, timeout=15.0)
    conn.execute("PRAGMA mmap_size = 0;")
    df = pd.read_sql_query("SELECT timestamp, source_ip, user, status FROM events", conn)
    conn.close()

    if df.empty:
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", utc=True)
    df = df.sort_values(by=["source_ip", "timestamp"])

    feature_rows = []
    for ip, group in df.groupby("source_ip"):
        total_attempts = len(group)
        failures = (group["status"] == "failed").sum()
        failure_rate = failures / total_attempts if total_attempts > 0 else 0.0
        unique_users = group["user"].nunique()

        if total_attempts > 1:
            time_deltas = group["timestamp"].diff().dt.total_seconds().dropna()
            mean_interval = float(time_deltas.mean())
            std_interval = float(time_deltas.std(ddof=0))
        else:
            mean_interval = 3600.0
            std_interval = 0.0

        feature_rows.append({
            "source_ip": ip,
            "total_attempts": total_attempts,
            "failure_rate": failure_rate,
            "unique_users": unique_users,
            "mean_interval": mean_interval,
            "std_interval": std_interval
        })

    return pd.DataFrame(feature_rows)


def train_model():
    df_features = extract_features_from_db()
    if len(df_features) < 5:
        print("[!] Not enough profiles to train.")
        return None

    X = transform_features(df_features)

    # Set contamination to 0.35 to match the dirty historical set
    model = IsolationForest(n_estimators=150, contamination=0.35, random_state=42)
    model.fit(X)

    joblib.dump(model, MODEL_FILE)
    print(f"[+] Model retrained with log-scaling on {len(df_features)} profiles.")
    return model


class AnomalyScorer:
    def __init__(self, score_threshold=0.05):
        self.threshold = score_threshold
        try:
            self.model = joblib.load(MODEL_FILE)
            self.is_ready = True
        except Exception:
            self.model = None
            self.is_ready = False

    def score_ip_behavior(self, features: dict) -> tuple[bool, float]:
        if not self.is_ready:
            return False, 0.0

        raw_df = pd.DataFrame([features])
        X = transform_features(raw_df)

        score = float(self.model.decision_function(X)[0])

        # An anomaly is either predict == -1 or score is below our sensitivity threshold
        is_anomaly = score < self.threshold
        return is_anomaly, score


if __name__ == "__main__":
    train_model()