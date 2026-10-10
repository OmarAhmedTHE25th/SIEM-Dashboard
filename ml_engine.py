import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib

DB_NAME = "siem.db"
MODEL_FILE = "siem_isoforest.joblib"

def extract_features_from_db() -> pd.DataFrame:
    """Queries raw events from SQLite and aggregates them into behavioral feature vectors per IP."""
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT timestamp, source_ip, user, status FROM events", conn)
    conn.close()

    if df.empty:
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)
    df = df.sort_values(by=["source_ip", "timestamp"])

    feature_rows = []

    for ip, group in df.groupby("source_ip"):
        total_attempts = len(group)
        failures = (group["status"] == "failed").sum()
        failure_rate = failures / total_attempts if total_attempts > 0 else 0.0
        unique_users = group["user"].nunique()

        # Inter-arrival time between attempts
        if total_attempts > 1:
            time_deltas = group["timestamp"].diff().dt.total_seconds().dropna()
            mean_interval = float(time_deltas.mean())
            std_interval = float(time_deltas.std(ddof=0))
        else:
            # Single event defaults
            mean_interval = 3600.0  # arbitrary large baseline interval
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


FEATURE_COLS = ["total_attempts", "failure_rate", "unique_users", "mean_interval", "std_interval"]


def train_model():
    """Trains an Isolation Forest on current events and saves the weights to disk."""
    df_features = extract_features_from_db()

    if len(df_features) < 3:
        print("[!] Not enough distinct IP profiles to train yet (need at least 3 distinct IPs).")
        return None

    X = df_features[FEATURE_COLS]

    # contamination: expected proportion of outliers in the data (e.g., 5-10%)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)

    joblib.dump(model, MODEL_FILE)
    print(f"[+] Model trained successfully on {len(df_features)} IP profiles and saved to {MODEL_FILE}")
    return model


class AnomalyScorer:
    """Loads the trained model and scores behavioral feature vectors."""

    def __init__(self):
        try:
            self.model = joblib.load(MODEL_FILE)
            self.is_ready = True
        except Exception:
            self.model = None
            self.is_ready = False

    def score_ip_behavior(self, features: dict) -> tuple[bool, float]:
        """
        Returns (is_anomaly, anomaly_score).
        IsolationForest:
          - predict: -1 for outlier/anomaly, 1 for inlier/normal
          - decision_function: lower/negative values indicate anomalous behavior
        """
        if not self.is_ready:
            return False, 0.0

        X = pd.DataFrame([[
            features["total_attempts"],
            features["failure_rate"],
            features["unique_users"],
            features["mean_interval"],
            features["std_interval"]
        ]], columns=FEATURE_COLS)

        prediction = self.model.predict(X)[0]
        score = self.model.decision_function(X)[0]

        is_anomaly = (prediction == -1)
        return is_anomaly, float(score)


if __name__ == "__main__":
    train_model()
