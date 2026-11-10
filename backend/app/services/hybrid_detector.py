"""
Hybrid Cyberattack Detection Engine.
Fuses deterministic rules, unsupervised Isolation Forest anomaly scoring,
and supervised Random Forest multi-class classification into unified SOC alerts.
"""

import json
import os
import sys
from typing import Dict, Any, Tuple, Optional
import numpy as np
import joblib

from app.config import settings
from app.db.storage import db_store
from app.services.rule_engine import RuleEngine
from app.services.risk_scorer import RiskScorer
from app.services.mitigation_service import MitigationService

# Add ml_engine to sys.path to access feature pipeline & explainability
ML_DIR = os.path.join(settings.BASE_DIR, "ml_engine")
if ML_DIR not in sys.path:
    sys.path.append(ML_DIR)

from feature_pipeline import NetworkFeaturePipeline, ATTACK_CLASSES
from explainability import ExplainabilityEngine

class HybridDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(HybridDetector, cls).__new__(cls)
            cls._instance._load_models()
        return cls._instance

    def _load_models(self):
        artifacts_dir = settings.ML_ARTIFACTS_DIR
        scaler_file = os.path.join(artifacts_dir, "scaler.joblib")
        iso_file = os.path.join(artifacts_dir, "isolation_forest.joblib")
        rf_file = os.path.join(artifacts_dir, "random_forest.joblib")
        baseline_file = os.path.join(artifacts_dir, "baseline_profile.json")

        self.pipeline = NetworkFeaturePipeline(scaler_path=scaler_file)
        self.iso_forest = joblib.load(iso_file) if os.path.exists(iso_file) else None
        self.rf_classifier = joblib.load(rf_file) if os.path.exists(rf_file) else None
        self.xai_engine = ExplainabilityEngine(baseline_path=baseline_file)

        # Load baseline threshold
        self.baseline_threshold = 0.0126
        if os.path.exists(baseline_file):
            with open(baseline_file, "r") as f:
                b_data = json.load(f)
                self.baseline_threshold = b_data.get("default_threshold", 0.0126)

    def process_flow(self, flow: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Processes single flow record:
        1. Checks Rule Engine
        2. Evaluates ML models
        3. Computes Risk Score
        4. If anomalous or classified attack -> generates Alert with XAI & Mitigations
        """
        # Save flow to DB store
        stored_flow = db_store.insert_flow(flow)

        # 1. Rule Engine Evaluation
        rule_triggered, rule_name, rule_conf = RuleEngine.evaluate(flow)

        # 2. ML Transformations
        raw_vec, scaled_vec = self.pipeline.transform_single_flow(flow)

        # Isolation Forest Anomaly Score
        # decision_function: lower score = more anomalous
        if self.iso_forest is not None:
            iso_score = float(self.iso_forest.decision_function(scaled_vec)[0])
        else:
            iso_score = 0.05

        # Get active dynamic threshold
        threshold_record = db_store.adaptive_thresholds.get("anomaly_score", {})
        active_threshold = threshold_record.get("current_threshold", self.baseline_threshold)
        ml_anomaly_triggered = iso_score < active_threshold

        # Random Forest Classification
        if self.rf_classifier is not None:
            pred_idx = int(self.rf_classifier.predict(scaled_vec)[0])
            probas = self.rf_classifier.predict_proba(scaled_vec)[0]
            predicted_class = ATTACK_CLASSES[pred_idx]
            class_prob = float(probas[pred_idx])
        else:
            predicted_class = "Benign"
            class_prob = 0.50

        # Class attack check
        ml_class_triggered = (predicted_class != "Benign") and (class_prob >= 0.45)

        # 3. Dynamic Threat Risk Scoring
        risk_score, risk_level = RiskScorer.calculate_risk(
            anomaly_score=iso_score,
            anomaly_threshold=active_threshold,
            predicted_class=predicted_class,
            class_probability=class_prob,
            rule_triggered=rule_triggered,
            rule_confidence=rule_conf,
            target_ip=flow.get("dst_ip", "10.0.0.5")
        )

        stored_flow["risk_score"] = risk_score
        stored_flow["classified_attack"] = predicted_class

        # Determine if an alert should be triggered
        should_alert = (
            rule_triggered or
            ml_anomaly_triggered or
            ml_class_triggered or
            risk_score >= 35.0
        )

        alert = None
        if should_alert:
            # Generate Explainable AI breakdown
            explanation = self.xai_engine.explain_flow(
                flow=flow,
                predicted_class=predicted_class if predicted_class != "Benign" else (rule_name or "Anomalous Behavior"),
                risk_score=risk_score,
                anomaly_score=iso_score
            )

            # Generate Recommended Mitigations
            mitigations = MitigationService.generate_recommendations(
                src_ip=flow.get("src_ip", "0.0.0.0"),
                dst_port=int(flow.get("dst_port", 80)),
                attack_type=predicted_class,
                risk_level=risk_level
            )

            attack_label = predicted_class if predicted_class != "Benign" else (rule_name or "Behavioral Anomaly")

            alert_data = {
                "flow_id": stored_flow["id"],
                "data_source": flow.get("data_source", "OBSERVED"),
                "timestamp": stored_flow["timestamp"],
                "risk_score": risk_score,
                "risk_level": risk_level,
                "attack_type": attack_label,
                "confidence": round(max(class_prob, rule_conf, 0.65), 2),
                "status": "NEW",
                "src_ip": flow.get("src_ip", "0.0.0.0"),
                "dst_ip": flow.get("dst_ip", "10.0.0.5"),
                "src_port": int(flow.get("src_port", 0)),
                "dst_port": int(flow.get("dst_port", 0)),
                "protocol": flow.get("protocol", "TCP"),
                "rule_triggered": rule_triggered,
                "ml_triggered": (ml_anomaly_triggered or ml_class_triggered),
                "explanation": explanation,
                "mitigations": mitigations
            }

            alert = db_store.insert_alert(alert_data)

        return stored_flow, alert

detector = HybridDetector()
