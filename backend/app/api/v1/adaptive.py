"""
Adaptive Baseline & Threshold Configuration Endpoints.
"""

import json
import os
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException

from app.config import settings
from app.schemas.adaptive import (
    AdaptiveThresholdItem,
    ThresholdCalibrationUpdate,
    BaselineProfileResponse
)
from app.db.storage import db_store
from app.services.adaptive_service import AdaptiveService

router = APIRouter(prefix="/adaptive", tags=["Adaptive Baseline"])

@router.get("/baseline")
def get_baseline_profile() -> Dict[str, Any]:
    """Retrieves the baseline statistical distribution metrics and threshold percentiles."""
    base_file = os.path.join(settings.ML_ARTIFACTS_DIR, "baseline_profile.json")
    if not os.path.exists(base_file):
        raise HTTPException(status_code=404, detail="Baseline profile not found.")

    with open(base_file, "r") as f:
        profile = json.load(f)

    profile["current_thresholds"] = db_store.get_adaptive_thresholds()
    return profile

@router.get("/thresholds", response_model=List[AdaptiveThresholdItem])
def get_current_thresholds():
    """Returns all active dynamic thresholds and their recalibration origins."""
    return db_store.get_adaptive_thresholds()

@router.patch("/thresholds")
def calibrate_thresholds(payload: ThresholdCalibrationUpdate):
    """Calibrates sensitivity multipliers and thresholds dynamically."""
    result = AdaptiveService.calibrate_thresholds(
        anomaly_sensitivity_factor=payload.anomaly_sensitivity_factor,
        confidence_floor=payload.confidence_floor,
        syn_flood_ratio=payload.syn_flood_ratio_threshold,
        port_entropy=payload.port_entropy_threshold
    )
    return result
