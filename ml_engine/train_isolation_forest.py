"""
Unsupervised Isolation Forest Trainer & Baseline Profiler.
Trains on verified benign traffic to establish behavioral boundaries and calculates
statistical baseline metrics (mean, std-dev, IQR) for dynamic anomaly detection.
"""

import json
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from feature_pipeline import NetworkFeaturePipeline, FEATURE_NAMES

def train_isolation_forest(data_path: str = "artifacts/training_dataset.csv"):
    os.makedirs("artifacts", exist_ok=True)
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)

    # Filter for benign traffic only to establish normal behavioral baseline
    benign_df = df[df["attack_class"] == "Benign"].copy()
    print(f"Training Isolation Forest on {len(benign_df)} benign baseline flows...")

    pipeline = NetworkFeaturePipeline()
    pipeline.fit_scaler(benign_df)
    pipeline.save_scaler("artifacts/scaler.joblib")

    X_scaled = pipeline.transform(benign_df)

    # Train Isolation Forest
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.03,  # Expected minor anomaly contamination rate
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_scaled)

    # Calculate baseline anomaly scores
    scores = iso_forest.decision_function(X_scaled)
    score_p1 = float(np.percentile(scores, 1.0))
    score_p5 = float(np.percentile(scores, 5.0))
    score_mean = float(np.mean(scores))
    score_std = float(np.std(scores))

    # Calculate feature baseline profiles (mean, std, median, IQR) for each feature
    feature_profiles = {}
    for feat in FEATURE_NAMES:
        vals = benign_df[feat].to_numpy()
        q75, q25 = np.percentile(vals, [75, 25])
        iqr = float(q75 - q25)
        feature_profiles[feat] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals)) if np.std(vals) > 0 else 1.0,
            "median": float(np.median(vals)),
            "iqr": iqr if iqr > 0 else 1.0,
            "min": float(np.min(vals)),
            "max": float(np.max(vals))
        }

    baseline_profile = {
        "score_threshold_p1": score_p1,
        "score_threshold_p5": score_p5,
        "score_mean": score_mean,
        "score_std": score_std,
        "default_threshold": score_p5,
        "features": feature_profiles
    }

    # Save model and baseline profile
    joblib.dump(iso_forest, "artifacts/isolation_forest.joblib")
    with open("artifacts/baseline_profile.json", "w") as f:
        json.dump(baseline_profile, f, indent=2)

    print("Isolation Forest trained successfully.")
    print(f"Baseline Score Mean: {score_mean:.4f}, Std: {score_std:.4f}, P5 Threshold: {score_p5:.4f}")
    print("Saved -> artifacts/isolation_forest.joblib & artifacts/baseline_profile.json")

if __name__ == "__main__":
    train_isolation_forest()
