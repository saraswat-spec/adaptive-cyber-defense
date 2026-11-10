"""
Alerts, Incidents, XAI Explanations & Mitigation Schemas.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AlertStatus = Literal["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
FeedbackType = Literal["CONFIRMED_THREAT", "FALSE_POSITIVE", "BENIGN_ANOMALY"]
MitigationActionType = Literal["BLOCK_IP", "RATE_LIMIT", "ISOLATE_HOST", "NOTIFY_WEBHOOK"]
MitigationStatus = Literal["RECOMMENDED", "SIMULATED_APPLIED", "APPLIED", "DISMISSED"]

class FeatureAttribution(BaseModel):
    feature: str
    label: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    direction: str
    unit: str

class AlertExplanationResponse(BaseModel):
    top_features: List[FeatureAttribution]
    narrative_summary: str
    anomaly_score: float
    risk_score: float

class MitigationActionResponse(BaseModel):
    action_type: MitigationActionType
    target_ip: str
    generated_script: str
    status: MitigationStatus
    created_at: datetime

class AlertResponse(BaseModel):
    id: str
    flow_id: Optional[str] = None
    data_source: Literal["OBSERVED", "SIMULATED"]
    timestamp: datetime
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: RiskLevel
    attack_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    status: AlertStatus
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    rule_triggered: bool
    ml_triggered: bool
    explanation: Optional[AlertExplanationResponse] = None
    mitigations: Optional[List[MitigationActionResponse]] = Field(default_factory=list)

class AlertStatusUpdate(BaseModel):
    status: AlertStatus

class AlertFeedbackRequest(BaseModel):
    feedback_type: FeedbackType
    analyst_notes: Optional[str] = None
    adjust_threshold: bool = True

class MitigationExecutionRequest(BaseModel):
    action_type: MitigationActionType
    execution_mode: Literal["SIMULATED", "ACTIVE"] = "SIMULATED"
