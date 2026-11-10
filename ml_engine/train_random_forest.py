"""
Supervised Random Forest Attack Classifier Trainer.
Trains a balanced multi-class classifier capable of distinguishing
Benign, DoS/DDoS, PortScan, BruteForce, WebAttack, and Infiltration attacks.
"""

import json
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from feature_pipeline import NetworkFeaturePipeline, ATTACK_CLASSES, FEATURE_NAMES

def train_random_forest(data_path: str = "artifacts/training_dataset.csv"):
    os.makedirs("artifacts", exist_ok=True)
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)

    pipeline = NetworkFeaturePipeline(scaler_path="artifacts/scaler.joblib")
    X = pipeline.transform(df)

    # Encode targets
    class_to_idx = {cls_name: i for i, cls_name in enumerate(ATTACK_CLASSES)}
    y = df["attack_class"].map(class_to_idx).to_numpy()

    # Train/Val split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training Random Forest on {len(X_train)} samples across {len(ATTACK_CLASSES)} classes...")
    rf_clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_clf.fit(X_train, y_train)

    val_acc = rf_clf.score(X_val, y_val)
    print(f"Validation Accuracy: {val_acc * 100:.2f}%")

    # Feature importances
    importances = rf_clf.feature_importances_
    feat_rankings = [
        {"feature": feat, "importance": float(imp)}
        for feat, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    ]

    joblib.dump(rf_clf, "artifacts/random_forest.joblib")
    with open("artifacts/feature_importance.json", "w") as f:
        json.dump(feat_rankings, f, indent=2)
    with open("artifacts/classes.json", "w") as f:
        json.dump(ATTACK_CLASSES, f, indent=2)

    print("Random Forest classifier saved -> artifacts/random_forest.joblib")
    print(f"Top 5 most predictive features:")
    for item in feat_rankings[:5]:
        print(f" - {item['feature']}: {item['importance']:.4f}")

if __name__ == "__main__":
    train_random_forest()
