"""
Attack Simulation Laboratory Schemas.
"""

from datetime import datetime
from typing import Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

ScenarioType = Literal[
    "SYN_FLOOD",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "WEB_ATTACK",
    "INFILTRATION_BEACON"
]

class SimulationLaunchRequest(BaseModel):
    scenario: ScenarioType
    target_ip: str = "10.0.0.5"
    target_port: Optional[int] = None
    packet_rate_pps: int = Field(default=1000, ge=10, le=10000)
    duration_seconds: float = Field(default=5.0, ge=1.0, le=60.0)
    custom_params: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SimulationRunResponse(BaseModel):
    id: str
    scenario_name: str
    target_ip: str
    target_port: Optional[int]
    total_packets_injected: int
    duration_seconds: float
    status: Literal["RUNNING", "COMPLETED", "FAILED"]
    started_at: datetime
    ended_at: Optional[datetime] = None
    detected_alerts_count: int = 0
