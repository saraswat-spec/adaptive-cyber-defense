"""
Adaptive Baseline & False-Positive Learning Service.
Dynamically calibrates anomaly detection thresholds and baseline parameters
based on historical feedback and administrator triage decisions.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.db.storage import db_store

class AdaptiveService:
    @staticmethod
    def process_feedback(
        alert_id: str,
        feedback_type: str,
        analyst_notes: Optional[str] = None,
        adjust_threshold: bool = True
    ) -> Dict[str, Any]:
        """
        Processes SOC analyst review of an alert.
        If marked as FALSE_POSITIVE, adaptively tunes anomaly detection sensitivity.
        """
        alert = db_store.get_alert(alert_id)
        if not alert:
            return {"success": False, "message": "Alert not found."}

        # Update alert status
        new_status = "FALSE_POSITIVE" if feedback_type == "FALSE_POSITIVE" else "RESOLVED"
        db_store.update_alert_status(alert_id, new_status)

        adjustments = {}
        if feedback_type == "FALSE_POSITIVE" and adjust_threshold:
            # 1. Adapt Anomaly Score Threshold
            current_anomaly_item = db_store.adaptive_thresholds.get("anomaly_score", {})
            curr_val = current_anomaly_item.get("current_threshold", 0.0126)
            # Make the threshold slightly stricter/lower to reduce future false alarms
            # (lower decision_function cutoff means fewer samples flagged as outliers)
            new_val = round(curr_val * 0.92, 4)
            db_store.update_adaptive_threshold(
                metric_name="anomaly_score",
                new_val=new_val,
                reason=f"Recalibrated from false positive alert {alert_id} ({alert.get('attack_type')})"
            )
            adjustments["anomaly_score"] = {"previous": curr_val, "updated": new_val}

            # 2. If the alert was rule-based SYN flood, slightly adapt syn_flood_ratio
            if alert.get("attack_type") == "RULE_SYN_FLOOD_VOLUMETRIC" or "SYN" in alert.get("attack_type", ""):
                syn_item = db_store.adaptive_thresholds.get("syn_flood_ratio", {})
                curr_syn = syn_item.get("current_threshold", 0.85)
                new_syn = min(0.95, round(curr_syn + 0.02, 2))
                db_store.update_adaptive_threshold(
                    metric_name="syn_flood_ratio",
                    new_val=new_syn,
                    reason=f"False positive on SYN ratio; raised tolerance threshold."
                )
                adjustments["syn_flood_ratio"] = {"previous": curr_syn, "updated": new_syn}

        # Record audit feedback
        feedback_record = {
            "alert_id": alert_id,
            "feedback_type": feedback_type,
            "analyst_notes": analyst_notes,
            "parameter_adjustments": adjustments,
            "recorded_at": datetime.now(timezone.utc)
        }
        db_store.insert_feedback(feedback_record)

        return {
            "success": True,
            "alert_id": alert_id,
            "status": new_status,
            "adjustments": adjustments
        }

    @staticmethod
    def calibrate_thresholds(
        anomaly_sensitivity_factor: float,
        confidence_floor: float,
        syn_flood_ratio: Optional[float] = None,
        port_entropy: Optional[float] = None
    ) -> Dict[str, Any]:
        """Manually tunes detection sensitivity parameters from SOC configuration UI."""
        # Baseline threshold multiplied by sensitivity factor
        base_threshold = 0.0126
        tuned_threshold = round(base_threshold * anomaly_sensitivity_factor, 4)
        db_store.update_adaptive_threshold(
            metric_name="anomaly_score",
            new_val=tuned_threshold,
            reason=f"Manual SOC sensitivity calibration factor ({anomaly_sensitivity_factor}x)"
        )

        if syn_flood_ratio is not None:
            db_store.update_adaptive_threshold(
                metric_name="syn_flood_ratio",
                new_val=syn_flood_ratio,
                reason="Manual calibration"
            )

        if port_entropy is not None:
            db_store.update_adaptive_threshold(
                metric_name="port_scan_entropy",
                new_val=port_entropy,
                reason="Manual calibration"
            )

        return {
            "success": True,
            "current_thresholds": db_store.get_adaptive_thresholds()
        }
