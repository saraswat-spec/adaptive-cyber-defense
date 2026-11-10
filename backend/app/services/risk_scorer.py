"""
Dynamic Threat Risk Scoring Engine.
Computes a scientifically weighted 0-100 risk score factoring anomaly magnitude,
classification confidence, attack family severity, and target asset criticality.
"""

from typing import Dict, Any, Tuple
from app.schemas.alert import RiskLevel

# Threat severity index per attack family
ATTACK_SEVERITY_WEIGHTS = {
    "Benign": 0.0,
    "PortScan": 45.0,
    "BruteForce": 75.0,
    "WebAttack": 80.0,
    "DoS_DDoS": 90.0,
    "Infiltration": 95.0,
}

# Asset criticality factor (can be expanded via CMDB/Inventory)
ASSET_CRITICALITY_MAP = {
    "10.0.0.5": 1.15,   # Core Production Server
    "10.0.0.10": 1.10,  # Application Gateway
    "172.16.0.4": 1.05, # Internal DMZ
}

class RiskScorer:
    @staticmethod
    def calculate_risk(
        anomaly_score: float,
        anomaly_threshold: float,
        predicted_class: str,
        class_probability: float,
        rule_triggered: bool,
        rule_confidence: float,
        target_ip: str
    ) -> Tuple[float, RiskLevel]:
        """
        Calculates dynamic risk score (0 - 100) and severity level.
        """
        # 1. Anomaly component (0 - 35 points)
        # Lower anomaly score = further outside the normal boundary
        anomaly_delta = max(0.0, anomaly_threshold - anomaly_score)
        anomaly_component = min(35.0, (anomaly_delta / 0.05) * 35.0)

        # 2. Classification component (0 - 45 points)
        base_severity = ATTACK_SEVERITY_WEIGHTS.get(predicted_class, 50.0)
        classification_component = (base_severity * class_probability) * 0.45

        # 3. Rule heuristic component (0 - 20 points)
        rule_component = (rule_confidence * 20.0) if rule_triggered else 0.0

        # Raw combined score
        raw_score = anomaly_component + classification_component + rule_component

        # 4. Asset criticality multiplier
        asset_multiplier = ASSET_CRITICALITY_MAP.get(target_ip, 1.0)
        final_score = min(100.0, max(0.0, raw_score * asset_multiplier))

        # Categorize
        if final_score >= 80.0:
            level: RiskLevel = "CRITICAL"
        elif final_score >= 60.0:
            level: RiskLevel = "HIGH"
        elif final_score >= 35.0:
            level: RiskLevel = "MEDIUM"
        else:
            level: RiskLevel = "LOW"

        return round(final_score, 1), level
