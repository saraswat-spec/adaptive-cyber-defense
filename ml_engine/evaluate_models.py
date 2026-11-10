"""
Model Performance Evaluator.
Computes comprehensive diagnostics strictly from held-out validation samples (2,000 flows):
Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix, and Isolation Forest Anomaly Detection efficacy.
"""

import json
import os
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
    precision_recall_fscore_support
)
import joblib
from feature_pipeline import NetworkFeaturePipeline, ATTACK_CLASSES, FEATURE_NAMES

def evaluate(val_data_path: str = "artifacts/val_split.csv"):
    if not os.path.exists(val_data_path):
        val_data_path = os.path.join(os.path.dirname(__file__), "artifacts", "val_split.csv")

    df = pd.read_csv(val_data_path)
    scaler_path = os.path.join(os.path.dirname(val_data_path), "scaler.joblib")
    pipeline = NetworkFeaturePipeline(scaler_path=scaler_path)
    X = pipeline.transform(df)

    class_to_idx = {cls_name: i for i, cls_name in enumerate(ATTACK_CLASSES)}
    y_true = df["attack_class"].map(class_to_idx).to_numpy()

    artifacts_dir = os.path.dirname(val_data_path)
    rf_clf = joblib.load(os.path.join(artifacts_dir, "random_forest.joblib"))
    iso_forest = joblib.load(os.path.join(artifacts_dir, "isolation_forest.joblib"))
    with open(os.path.join(artifacts_dir, "baseline_profile.json"), "r") as f:
        baseline = json.load(f)

    threshold = baseline.get("default_threshold", 0.0138)

    # 1. Evaluate Random Forest Classifier on Validation Set
    y_pred = rf_clf.predict(X)
    y_proba = rf_clf.predict_proba(X)

    acc = float(accuracy_score(y_true, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted")
    roc_auc = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="weighted"))

    cm = confusion_matrix(y_true, y_pred)
    cm_formatted = []
    for i, actual_cls in enumerate(ATTACK_CLASSES):
        for j, pred_cls in enumerate(ATTACK_CLASSES):
            cm_formatted.append({
                "actual": actual_cls,
                "predicted": pred_cls,
                "count": int(cm[i][j])
            })

    class_metrics = {}
    report = classification_report(y_true, y_pred, target_names=ATTACK_CLASSES, output_dict=True)
    for cls_name in ATTACK_CLASSES:
        class_metrics[cls_name] = {
            "precision": float(report[cls_name]["precision"]),
            "recall": float(report[cls_name]["recall"]),
            "f1_score": float(report[cls_name]["f1-score"]),
            "support": int(report[cls_name]["support"])
        }

    # 2. Evaluate Isolation Forest on Validation Set
    iso_scores = iso_forest.decision_function(X)
    is_anomaly_pred = iso_scores < threshold
    is_attack_true = (df["attack_class"] != "Benign").to_numpy()

    true_positives = int(np.sum(is_anomaly_pred & is_attack_true))
    false_positives = int(np.sum(is_anomaly_pred & (~is_attack_true)))
    false_negatives = int(np.sum((~is_anomaly_pred) & is_attack_true))
    true_negatives = int(np.sum((~is_anomaly_pred) & (~is_attack_true)))

    anomaly_detection_rate = float(true_positives / max(1, true_positives + false_negatives))
    false_alarm_rate = float(false_positives / max(1, false_positives + true_negatives))

    metrics_payload = {
        "overall": {
            "accuracy": acc,
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": roc_auc
        },
        "anomaly_detection": {
            "detection_rate": anomaly_detection_rate,
            "false_alarm_rate": false_alarm_rate,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        },
        "dataset_provenance": {
            "total_dataset_samples": 10000,
            "train_samples": 8000,
            "validation_samples": len(df),
            "val_benign_samples": int(np.sum(~is_attack_true)),
            "val_attack_samples": int(np.sum(is_attack_true)),
            "evaluation_partition": "HELD_OUT_VALIDATION_SET_ONLY"
        },
        "confusion_matrix_grid": cm.tolist(),
        "confusion_matrix_records": cm_formatted,
        "class_metrics": class_metrics,
        "classes": ATTACK_CLASSES
    }

    out_file = os.path.join(artifacts_dir, "evaluation_metrics.json")
    with open(out_file, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"Evaluation Complete on Held-Out Validation Set ({len(df)} samples)!")
    print(f"Accuracy: {acc*100:.2f}%, F1: {f1:.4f}, ROC-AUC: {roc_auc:.4f}")
    print(f"IsoForest Recall: {anomaly_detection_rate*100:.2f}%, False Alarm Rate: {false_alarm_rate*100:.2f}%")

if __name__ == "__main__":
    evaluate()
