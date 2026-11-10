"""
Adaptive Threshold & Baseline Configuration Schemas.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class AdaptiveThresholdItem(BaseModel):
    metric_name: str
    current_threshold: float
    previous_threshold: float
    baseline_mean: float
    baseline_std: float
    false_positive_rate_window: float
    reason: Optional[str] = None
    updated_at: datetime

class ThresholdCalibrationUpdate(BaseModel):
    anomaly_sensitivity_factor: float = Field(default=1.0, ge=0.2, le=3.0)
    confidence_floor: float = Field(default=0.5, ge=0.1, le=0.95)
    syn_flood_ratio_threshold: Optional[float] = Field(default=0.85, ge=0.3, le=0.99)
    port_entropy_threshold: Optional[float] = Field(default=0.75, ge=0.3, le=0.99)

class BaselineProfileResponse(BaseModel):
    score_threshold_p1: float
    score_threshold_p5: float
    score_mean: float
    score_std: float
    default_threshold: float
    features: Dict[str, Any]
    current_thresholds: List[AdaptiveThresholdItem]
