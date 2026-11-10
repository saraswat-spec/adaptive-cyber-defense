"""
Telemetry & Network Flow Data Schemas.
Ensures strict type validation and explicit data origin provenance tagging.
"""

from datetime import datetime
from typing import Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict

DataSource = Literal["OBSERVED", "SIMULATED", "DATASET"]
ProtocolType = Literal["TCP", "UDP", "ICMP", "OTHER"]

class FlowIngestPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    data_source: DataSource = Field(
        ...,
        description="Explicit provenance flag: OBSERVED (live/pcap), SIMULATED (attack lab), or DATASET (benchmark)"
    )
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: ProtocolType = "TCP"
    flow_duration: float = 0.0
    tot_fwd_pkts: int = 1
    tot_bwd_pkts: int = 0
    tot_len_fwd_pkts: float = 64.0
    tot_len_bwd_pkts: float = 0.0
    flow_bytes_per_sec: float = 0.0
    flow_packets_per_sec: float = 0.0
    syn_flag_cnt: int = 0
    ack_flag_cnt: int = 0
    fin_flag_cnt: int = 0
    rst_flag_cnt: int = 0
    port_entropy: float = 0.0
    raw_features: Optional[Dict[str, Any]] = Field(default_factory=dict)
    simulation_run_id: Optional[str] = None

class FlowRecordResponse(BaseModel):
    id: str
    data_source: DataSource
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    flow_duration: float
    flow_bytes_per_sec: float
    flow_packets_per_sec: float
    tot_fwd_pkts: int
    tot_bwd_pkts: int
    syn_ratio: float = 0.0
    risk_score: Optional[float] = None
    classified_attack: Optional[str] = None
    simulation_run_id: Optional[str] = None
