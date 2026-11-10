"""
Telemetry & Flow Ingestion Endpoints.
Supports high-frequency flow ingestion, summary statistics, and SSE live streams.
"""

import asyncio
from datetime import datetime
import json
from typing import List, Optional
from fastapi import APIRouter, Query, BackgroundTasks, Request
from sse_starlette.sse import EventSourceResponse

from app.schemas.telemetry import FlowIngestPayload, FlowRecordResponse
from app.db.storage import db_store
from app.services.hybrid_detector import detector

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])

@router.get("/flows", response_model=List[FlowRecordResponse])
def get_flows(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query("ALL", description="Filter by ALL, OBSERVED, or SIMULATED")
):
    """Retrieves paginated network flows with explicit provenance tags."""
    return db_store.list_flows(limit=limit, offset=offset, source=source)

@router.post("/ingest", response_model=FlowRecordResponse, status_code=201)
def ingest_flow(payload: FlowIngestPayload):
    """
    Ingests an incoming flow record, processes it through the Hybrid Detection Engine,
    and returns detection metrics with explicit origin provenance.
    """
    flow_data = payload.model_dump()
    stored_flow, _ = detector.process_flow(flow_data)
    return stored_flow

@router.get("/stats")
def get_telemetry_stats():
    """Computes summary rates, total packet volume, and data source distribution."""
    total_flows = len(db_store.flows)
    observed_count = sum(1 for f in db_store.flows if f.get("data_source") == "OBSERVED")
    simulated_count = sum(1 for f in db_store.flows if f.get("data_source") == "SIMULATED")

    # Calculate aggregate PPS and BPS from recent flows
    recent = db_store.flows[:20]
    avg_pps = sum(f.get("flow_packets_per_sec", 0.0) for f in recent) / max(1, len(recent))
    avg_bps = sum(f.get("flow_bytes_per_sec", 0.0) for f in recent) / max(1, len(recent))

    # Protocol breakdown
    protocols = {}
    for f in db_store.flows[:100]:
        proto = f.get("protocol", "TCP")
        protocols[proto] = protocols.get(proto, 0) + 1

    return {
        "total_flows_captured": total_flows,
        "observed_flows_count": observed_count,
        "simulated_flows_count": simulated_count,
        "current_packet_rate_pps": round(avg_pps, 1),
        "current_bandwidth_bps": round(avg_bps, 1),
        "protocol_distribution": protocols
    }

@router.get("/stream")
async def stream_telemetry(
    request: Request,
    filter_source: Optional[str] = Query("ALL")
):
    """
    Server-Sent Events (SSE) endpoint providing live real-time network flow telemetry
    and incident notifications to connected SOC analyst clients.
    """
    async def event_generator():
        last_flow_id = None
        while True:
            if await request.is_disconnected():
                break

            # Poll for new flows from DB store
            flows = db_store.list_flows(limit=5, source=filter_source)
            if flows and flows[0]["id"] != last_flow_id:
                last_flow_id = flows[0]["id"]
                yield {
                    "event": "flow_batch",
                    "data": json.dumps(flows[:3], default=str)
                }

            # Also push latest alert if present
            recent_alerts = db_store.list_alerts(limit=1, source=filter_source)
            if recent_alerts:
                yield {
                    "event": "alert_heartbeat",
                    "data": json.dumps(recent_alerts[0], default=str)
                }

            await asyncio.sleep(1.5)

    return EventSourceResponse(event_generator())
