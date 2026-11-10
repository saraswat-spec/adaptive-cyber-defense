"""
Attack Simulation Laboratory Endpoints.
Enables controlled generation of synthetic cyberattacks for red-team testing
and SOC detection validation, with guaranteed SIMULATED origin attribution.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException

from app.schemas.simulation import (
    SimulationLaunchRequest,
    SimulationRunResponse,
    ScenarioType
)
from app.db.storage import db_store
from app.services.simulation_service import SimulationService

router = APIRouter(prefix="/simulation", tags=["Simulation Laboratory"])

SCENARIO_TEMPLATES = [
    {
        "id": "SYN_FLOOD",
        "name": "Volumetric SYN Flood (DDoS)",
        "description": "Exhausts server connection buffers by generating a torrential burst of TCP SYN packets without ACKs.",
        "category": "Denial of Service",
        "default_rate_pps": 2500,
        "default_duration_sec": 5.0,
        "targeted_ports": [80, 443]
    },
    {
        "id": "PORT_SCAN",
        "name": "Reconnaissance / TCP Port Scan",
        "description": "Rapid port sweeps across hundreds of destination endpoints to identify open attack surfaces and running daemons.",
        "category": "Reconnaissance",
        "default_rate_pps": 300,
        "default_duration_sec": 3.0,
        "targeted_ports": [21, 22, 23, 25, 80, 443, 3306, 8080]
    },
    {
        "id": "BRUTE_FORCE",
        "name": "Authentication Brute Force",
        "description": "High-density dictionary credential cycling targeting SSH, FTP, or remote desktop protocols.",
        "category": "Initial Access",
        "default_rate_pps": 150,
        "default_duration_sec": 6.0,
        "targeted_ports": [22, 21, 3389]
    },
    {
        "id": "WEB_ATTACK",
        "name": "Web Application Exploit (SQLi / XSS)",
        "description": "Transmits anomalous, oversized payload buffers containing SQL injection syntax and directory traversal sequences.",
        "category": "Web Exploitation",
        "default_rate_pps": 80,
        "default_duration_sec": 4.0,
        "targeted_ports": [80, 443, 8080]
    },
    {
        "id": "INFILTRATION_BEACON",
        "name": "Stealthy C2 Infiltration Beacon",
        "description": "Low-frequency, highly periodic heartbeats mimicking malware command-and-control communication channels.",
        "category": "Command & Control",
        "default_rate_pps": 10,
        "default_duration_sec": 10.0,
        "targeted_ports": [443, 8443, 53]
    }
]

@router.get("/scenarios")
def get_scenario_templates() -> List[Dict[str, Any]]:
    """Returns available attack scenario presets."""
    return SCENARIO_TEMPLATES

@router.post("/execute", response_model=SimulationRunResponse, status_code=202)
async def execute_simulation(payload: SimulationLaunchRequest):
    """
    Launches an attack simulation scenario in the background.
    All flows generated are strictly tagged with data_source='SIMULATED'.
    """
    run_record = SimulationService.launch(
        scenario=payload.scenario,
        target_ip=payload.target_ip,
        target_port=payload.target_port,
        duration=payload.duration_seconds,
        packet_rate=payload.packet_rate_pps
    )
    return run_record

@router.get("/runs", response_model=List[SimulationRunResponse])
def get_simulation_runs():
    """Retrieves execution logs of past and active attack simulation runs."""
    return db_store.list_simulation_runs()
