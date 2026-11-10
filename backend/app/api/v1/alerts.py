"""
Alerts, Incident Triage, Explainability & Mitigation Endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Query, HTTPException, Path

from app.schemas.alert import (
    AlertResponse,
    AlertStatusUpdate,
    AlertFeedbackRequest,
    MitigationExecutionRequest
)
from app.db.storage import db_store
from app.services.adaptive_service import AdaptiveService
from app.services.mitigation_service import MitigationService

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = Query(None, description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    source: Optional[str] = Query("ALL", description="ALL, OBSERVED, SIMULATED"),
    limit: int = Query(50, ge=1, le=100)
):
    """Retrieves security incidents and flagged alerts."""
    return db_store.list_alerts(status=status, severity=severity, source=source, limit=limit)

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: str = Path(..., description="Alert UUID")):
    """Retrieves full incident forensics including XAI narrative and feature attributions."""
    alert = db_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    payload: AlertStatusUpdate,
    alert_id: str = Path(..., description="Alert UUID")
):
    """Updates the triage status of an incident."""
    updated = db_store.update_alert_status(alert_id, payload.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return updated

@router.post("/{alert_id}/feedback")
def submit_analyst_feedback(
    payload: AlertFeedbackRequest,
    alert_id: str = Path(..., description="Alert UUID")
):
    """
    Submits SOC analyst feedback (e.g. marking FALSE_POSITIVE) to trigger
    adaptive threshold recalibration and update detection baseline tolerances.
    """
    result = AdaptiveService.process_feedback(
        alert_id=alert_id,
        feedback_type=payload.feedback_type,
        analyst_notes=payload.analyst_notes,
        adjust_threshold=payload.adjust_threshold
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result

@router.post("/{alert_id}/mitigate")
def execute_mitigation(
    payload: MitigationExecutionRequest,
    alert_id: str = Path(..., description="Alert UUID")
):
    """
    Executes or simulates recommended containment actions (e.g. firewall IP block).
    Defaults to SIMULATED mode for non-destructive operation.
    """
    alert = db_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    target_action = None
    for action in alert.get("mitigations", []):
        if action.get("action_type") == payload.action_type:
            target_action = action
            break

    if not target_action:
        # Generate default action if not found
        target_action = {
            "action_type": payload.action_type,
            "target_ip": alert.get("src_ip", "192.168.1.100"),
            "status": "RECOMMENDED"
        }

    outcome = MitigationService.execute_action(target_action, mode=payload.execution_mode)
    return outcome
