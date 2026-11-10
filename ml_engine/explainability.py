"""
Explainable AI (XAI) Feature Attribution Engine.
Translates complex ML anomaly and classification decisions into human-readable,
actionable causality explanations and quantitative contribution weights.
"""

import json
import os
from typing import Dict, List, Any

# Descriptive label and unit mapping for high-signal features
FEATURE_LABELS = {
    "flow_packets_per_sec": ("Packet Generation Rate", "pkts/s"),
    "flow_bytes_per_sec": ("Flow Bandwidth Velocity", "B/s"),
    "syn_flag_cnt": ("SYN Handshake Flag Count", "flags"),
    "ack_flag_cnt": ("ACK Acknowledgment Count", "flags"),
    "fin_flag_cnt": ("FIN Termination Count", "flags"),
    "rst_flag_cnt": ("RST Connection Reset Count", "flags"),
    "port_entropy": ("Port Dispersion Entropy", "index (0-1)"),
    "tot_fwd_pkts": ("Forward Transmitted Packets", "pkts"),
    "tot_bwd_pkts": ("Backward Received Packets", "pkts"),
    "fwd_pkt_len_max": ("Max Forward Packet Length", "bytes"),
    "pkt_len_mean": ("Mean Packet Length", "bytes"),
    "flow_duration": ("Flow Session Duration", "seconds"),
    "tot_len_fwd_pkts": ("Forward Transmitted Bytes", "bytes"),
    "tot_len_bwd_pkts": ("Backward Received Bytes", "bytes"),
    "down_up_ratio": ("Download / Upload Ratio", "ratio"),
    "subflow_fwd_bytes": ("Subflow Forward Bytes", "bytes"),
}

class ExplainabilityEngine:
    def __init__(self, baseline_path: str = "artifacts/baseline_profile.json"):
        self.baseline = {}
        if os.path.exists(baseline_path):
            with open(baseline_path, "r") as f:
                self.baseline = json.load(f)

    def explain_flow(
        self,
        flow: Dict[str, Any],
        predicted_class: str,
        risk_score: float,
        anomaly_score: float,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Calculates feature attributions by measuring normalized deviations (Z-score & IQR distance)
        against the benign behavioral baseline.
        """
        features_baseline = self.baseline.get("features", {})
        attributions = []

        for feat_name, base_stats in features_baseline.items():
            observed_val = float(flow.get(feat_name, 0.0))
            mean_val = float(base_stats.get("mean", 0.0))
            std_val = float(base_stats.get("std", 1.0))
            if std_val <= 1e-6:
                std_val = 1.0

            # Normalized deviation score (z-score)
            z_score = abs(observed_val - mean_val) / std_val

            # Directional indicator
            direction = "ABOVE_NORMAL" if observed_val > mean_val else "BELOW_NORMAL"

            friendly_name, unit = FEATURE_LABELS.get(feat_name, (feat_name.replace("_", " ").title(), ""))

            attributions.append({
                "feature": feat_name,
                "label": friendly_name,
                "observed_value": round(observed_val, 2),
                "baseline_mean": round(mean_val, 2),
                "baseline_std": round(std_val, 2),
                "z_score": round(z_score, 2),
                "direction": direction,
                "unit": unit
            })

        # Sort by z-score deviation descending
        attributions.sort(key=lambda x: x["z_score"], reverse=True)
        top_features = attributions[:top_k]

        # Generate narrative explanation based on top features and predicted attack class
        narrative = self._generate_narrative(top_features, predicted_class, risk_score, anomaly_score)

        return {
            "top_features": top_features,
            "narrative": narrative,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": round(risk_score, 1)
        }

    def _generate_narrative(
        self,
        top_features: List[Dict[str, Any]],
        predicted_class: str,
        risk_score: float,
        anomaly_score: float
    ) -> str:
        """Synthesizes human-readable sentence for SOC incident reporting."""
        if predicted_class == "Benign" and risk_score < 30.0:
            return "Flow behavior adheres closely to historical benign baselines. No significant anomaly detected."

        reasons = []
        for feat in top_features[:3]:
            if feat["z_score"] >= 2.0:
                ratio = feat["observed_value"] / max(0.01, feat["baseline_mean"])
                if feat["direction"] == "ABOVE_NORMAL" and ratio > 1.5:
                    reasons.append(f"{feat['label']} is {ratio:.1f}x higher than baseline ({feat['observed_value']} {feat['unit']} vs mean {feat['baseline_mean']})")
                elif feat["direction"] == "BELOW_NORMAL":
                    reasons.append(f"{feat['label']} is significantly depressed ({feat['observed_value']} vs mean {feat['baseline_mean']})")
                else:
                    reasons.append(f"{feat['label']} deviated by {feat['z_score']}σ from baseline")

        reason_str = "; ".join(reasons) if reasons else "Multiple composite flow timing and volume indicators deviated from baseline."

        if predicted_class == "DoS_DDoS":
            prefix = "Volumetric Denial of Service (DoS/DDoS) pattern identified."
        elif predicted_class == "PortScan":
            prefix = "Active reconnaissance or port sweep pattern identified."
        elif predicted_class == "BruteForce":
            prefix = "Rapid authentication cycling / brute-force signature detected."
        elif predicted_class == "WebAttack":
            prefix = "Abnormal web application payload size or parameter structure detected."
        elif predicted_class == "Infiltration":
            prefix = "Stealthy periodic beaconing or C2 staging activity flagged."
        else:
            prefix = f"Unusual behavioral deviation flagged (Risk: {risk_score:.0f}/100)."

        return f"{prefix} Primary indicators: {reason_str}"
