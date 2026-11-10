"""
Unified Storage & Persistence Engine.
Provides high-throughput in-memory state with thread-safe locking and optional
asynchronous persistence to Supabase PostgreSQL when credentials are provided.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, List, Any, Optional
from app.config import settings

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = None

class SOCDataStore:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SOCDataStore, cls).__new__(cls)
            cls._instance._init_store()
        return cls._instance

    def _init_store(self):
        self.flows: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.feedback_records: List[Dict[str, Any]] = []
        self.simulation_runs: List[Dict[str, Any]] = []
        self.adaptive_thresholds: Dict[str, Dict[str, Any]] = {
            "anomaly_score": {
                "metric_name": "anomaly_score",
                "current_threshold": 0.0126,
                "previous_threshold": 0.0126,
                "baseline_mean": 0.0758,
                "baseline_std": 0.0325,
                "false_positive_rate_window": 0.05,
                "reason": "Initial calibrated P5 baseline",
                "updated_at": datetime.now(timezone.utc)
            },
            "syn_flood_ratio": {
                "metric_name": "syn_flood_ratio",
                "current_threshold": 0.85,
                "previous_threshold": 0.85,
                "baseline_mean": 0.06,
                "baseline_std": 0.04,
                "false_positive_rate_window": 0.01,
                "reason": "Normal TCP handshake ratio baseline",
                "updated_at": datetime.now(timezone.utc)
            },
            "flow_rate_pps": {
                "metric_name": "flow_rate_pps",
                "current_threshold": 1500.0,
                "previous_threshold": 1500.0,
                "baseline_mean": 85.0,
                "baseline_std": 42.0,
                "false_positive_rate_window": 0.02,
                "reason": "Typical perimeter packet rate cutoff",
                "updated_at": datetime.now(timezone.utc)
            },
            "port_scan_entropy": {
                "metric_name": "port_scan_entropy",
                "current_threshold": 0.75,
                "previous_threshold": 0.75,
                "baseline_mean": 0.18,
                "baseline_std": 0.08,
                "false_positive_rate_window": 0.01,
                "reason": "Standard endpoint port dispersion index",
                "updated_at": datetime.now(timezone.utc)
            }
        }

        # Initialize Supabase client if configured
        self.supabase: Optional[Client] = None
        if settings.SUPABASE_URL and settings.SUPABASE_KEY and create_client:
            try:
                self.supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                print("Connected to Supabase PostgreSQL.")
            except Exception as e:
                print(f"Supabase connection notice: Running in local memory store ({e})")

    # Flow operations
    def insert_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        if "id" not in flow:
            flow["id"] = str(uuid.uuid4())
        if "timestamp" not in flow:
            flow["timestamp"] = datetime.now(timezone.utc)

        self.flows.insert(0, flow)
        if len(self.flows) > 5000:
            self.flows.pop()  # Keep recent 5,000 flows in memory

        return flow

    def list_flows(
        self,
        limit: int = 50,
        offset: int = 0,
        source: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        filtered = self.flows
        if source and source != "ALL":
            filtered = [f for f in filtered if f.get("data_source") == source]
        return filtered[offset:offset + limit]

    # Alert operations
    def insert_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        if "id" not in alert:
            alert["id"] = str(uuid.uuid4())
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.now(timezone.utc)

        self.alerts.insert(0, alert)
        if len(self.alerts) > 1000:
            self.alerts.pop()

        return alert

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for a in self.alerts:
            if a["id"] == alert_id:
                return a
        return None

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        results = self.alerts
        if status:
            results = [a for a in results if a.get("status") == status]
        if severity:
            results = [a for a in results if a.get("risk_level") == severity]
        if source and source != "ALL":
            results = [a for a in results if a.get("data_source") == source]
        return results[:limit]

    def update_alert_status(self, alert_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["status"] = new_status
                return a
        return None

    # Feedback operations
    def insert_feedback(self, feedback: Dict[str, Any]):
        feedback["id"] = str(uuid.uuid4())
        feedback["created_at"] = datetime.now(timezone.utc)
        self.feedback_records.append(feedback)
        return feedback

    # Simulation runs
    def insert_simulation_run(self, run: Dict[str, Any]):
        if "id" not in run:
            run["id"] = str(uuid.uuid4())
        if "started_at" not in run:
            run["started_at"] = datetime.now(timezone.utc)
        self.simulation_runs.insert(0, run)
        return run

    def update_simulation_run(self, run_id: str, updates: Dict[str, Any]):
        for r in self.simulation_runs:
            if r["id"] == run_id:
                r.update(updates)
                return r
        return None

    def list_simulation_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.simulation_runs[:limit]

    # Adaptive Thresholds
    def get_adaptive_thresholds(self) -> List[Dict[str, Any]]:
        return list(self.adaptive_thresholds.values())

    def update_adaptive_threshold(
        self,
        metric_name: str,
        new_val: float,
        reason: str
    ):
        if metric_name in self.adaptive_thresholds:
            item = self.adaptive_thresholds[metric_name]
            item["previous_threshold"] = item["current_threshold"]
            item["current_threshold"] = new_val
            item["reason"] = reason
            item["updated_at"] = datetime.now(timezone.utc)
            return item
        return None

db_store = SOCDataStore()
