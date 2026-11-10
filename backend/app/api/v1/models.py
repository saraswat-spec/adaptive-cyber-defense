"""
Machine Learning Performance & Diagnostics Endpoints.
Surfaces model evaluation metrics, confusion matrix grids, and feature importance rankings.
Provides direct HTTP REST inference endpoint for the Java Spring Boot backend.
"""

import json
import os
import sys
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException

from app.config import settings
from app.schemas.telemetry import FlowIngestPayload
from app.services.hybrid_detector import detector
from app.services.rule_engine import RuleEngine

# Add ml_engine to sys.path
ML_DIR = os.path.join(settings.BASE_DIR, "ml_engine")
if ML_DIR not in sys.path:
    sys.path.append(ML_DIR)

from feature_pipeline import ATTACK_CLASSES

router = APIRouter(tags=["Model Analytics & ML Inference"])

@router.post("/ml/predict")
def predict_flow_inference(payload: FlowIngestPayload) -> Dict[str, Any]:
    """
    Direct HTTP REST ML inference endpoint invoked by the Java Spring Boot backend.
    Evaluates Isolation Forest & Random Forest models and returns raw predictions
    and XAI feature explanations.
    """
    flow_dict = payload.model_dump()
    if payload.raw_features:
        for k, v in payload.raw_features.items():
            flow_dict[k] = v

    # 1. Rule Evaluation
    rule_triggered, rule_name, rule_conf = RuleEngine.evaluate(flow_dict)

    # 2. ML Transformations
    raw_vec, scaled_vec = detector.pipeline.transform_single_flow(flow_dict)

    # Isolation Forest Anomaly Score
    if detector.iso_forest is not None:
        iso_score = float(detector.iso_forest.decision_function(scaled_vec)[0])
    else:
        iso_score = 0.05

    # Random Forest Classification
    if detector.rf_classifier is not None:
        pred_idx = int(detector.rf_classifier.predict(scaled_vec)[0])
        probas = detector.rf_classifier.predict_proba(scaled_vec)[0]
        predicted_class = ATTACK_CLASSES[pred_idx]
        class_prob = float(probas[pred_idx])
    else:
        predicted_class = "Benign"
        class_prob = 0.50

    # 3. Explainability
    xai = detector.xai_engine.explain_flow(
        flow=flow_dict,
        predicted_class=predicted_class if predicted_class != "Benign" else (rule_name or "Anomalous Behavior"),
        risk_score=75.0 if (predicted_class != "Benign" or rule_triggered) else 15.0,
        anomaly_score=iso_score
    )

    return {
        "anomaly_score": round(iso_score, 4),
        "predicted_class": predicted_class,
        "class_probability": round(class_prob, 4),
        "rule_triggered": rule_triggered,
        "rule_name": rule_name,
        "rule_confidence": round(rule_conf, 4),
        "explanation_narrative": xai.get("narrative", ""),
        "top_features": xai.get("top_features", [])
    }

@router.get("/models/analytics")
def get_model_analytics() -> Dict[str, Any]:
    """Retrieves full evaluation report including Confusion Matrix, Accuracy, and ROC-AUC."""
    eval_file = os.path.join(settings.ML_ARTIFACTS_DIR, "evaluation_metrics.json")
    if not os.path.exists(eval_file):
        raise HTTPException(status_code=404, detail="Model evaluation metrics not yet generated.")

    with open(eval_file, "r") as f:
        metrics = json.load(f)
    return metrics

@router.get("/models/features")
def get_feature_importances() -> List[Dict[str, Any]]:
    """Retrieves the global feature importance rankings from the Random Forest classifier."""
    feat_file = os.path.join(settings.ML_ARTIFACTS_DIR, "feature_importance.json")
    if not os.path.exists(feat_file):
        raise HTTPException(status_code=404, detail="Feature importance records not found.")

    with open(feat_file, "r") as f:
        features = json.load(f)
    return features
