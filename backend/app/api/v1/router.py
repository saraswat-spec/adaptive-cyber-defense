"""
Master V1 API Router.
Aggregates all modular sub-routers for the Mini-SOC platform.
"""

from fastapi import APIRouter
from app.api.v1.telemetry import router as telemetry_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.simulation import router as simulation_router
from app.api.v1.models import router as models_router
from app.api.v1.adaptive import router as adaptive_router

api_router = APIRouter()
api_router.include_router(telemetry_router)
api_router.include_router(alerts_router)
api_router.include_router(simulation_router)
api_router.include_router(models_router)
api_router.include_router(adaptive_router)
