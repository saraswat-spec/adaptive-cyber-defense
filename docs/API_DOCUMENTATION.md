# Complete REST API Reference (API_DOCUMENTATION.md)

This specification defines the 20+ production REST API endpoints provided by the **Adaptive Cyberattack Detection and Prevention System (Mini-SOC)**.

- **Base URL (Local):** `http://localhost:9090`
- **Base URL (Production):** Configured via `VITE_API_BASE_URL` (e.g., `https://soc-java-backend.onrender.com`)
- **API Prefix:** `/api/v1`
- **Content-Type:** `application/json`

---

## Table of Endpoints

| Category | HTTP Method | Endpoint | Description |
|---|---|---|---|
| **Health** | `GET` | `/health` / `/api/v1/health` | Service health and model readiness probe |
| **Telemetry** | `POST` | `/api/v1/telemetry/ingest` | Ingests a raw network flow and executes detection pipeline |
| | `GET` | `/api/v1/telemetry/flows` | Paginated flow query with provenance filtering |
| | `GET` | `/api/v1/telemetry/stats` | Aggregated traffic throughput, PPS, and flow counts |
| **Alerts** | `GET` | `/api/v1/alerts` | Filterable list of generated threat alerts |
| | `GET` | `/api/v1/alerts/{id}` | Detailed alert forensics, XAI explanation, actions |
| | `PATCH` | `/api/v1/alerts/{id}/status` | Update alert triage status |
| | `POST` | `/api/v1/alerts/{id}/mitigate` | Execute containment action (BLOCK_IP, etc.) |
| | `POST` | `/api/v1/alerts/{id}/feedback` | Submit analyst feedback on alert |
| **Incidents** | `GET` | `/api/v1/incidents` | List multi-alert security incidents |
| | `GET` | `/api/v1/incidents/{id}` | Incident details with aggregated alerts |
| | `PATCH` | `/api/v1/incidents/{id}/status` | Transition incident lifecycle status |
| **Simulation** | `GET` | `/api/v1/simulation/scenarios` | Retrieve executable attack scenario blueprints |
| | `POST` | `/api/v1/simulation/execute` | Asynchronously launch synthetic attack simulation |
| | `GET` | `/api/v1/simulation/runs` | List simulation run history and real-time statuses |
| **Adaptive** | `GET` | `/api/v1/adaptive/thresholds` | Query all active dynamic detection thresholds |
| | `PATCH` | `/api/v1/adaptive/thresholds` | Manually recalibrate specific threshold |
| | `GET` | `/api/v1/adaptive/baseline` | Retrieve statistical normal baseline profile |
| | `GET` | `/api/v1/feedback` | Audit log of all analyst feedback records |
| **Analytics** | `GET` | `/api/v1/models/analytics` | Dual-model performance metrics (accuracy, F1, ROC) |
| | `GET` | `/api/v1/models/features` | Global feature importance rankings for ML models |

---

## Detailed Endpoint Specifications

### 1. Health Probe
#### `GET /api/v1/health`
Returns the operational status of the service.
- **Status:** `200 OK`
- **Response:**
```json
{
  "status": "UP",
  "service": "soc-java-backend",
  "version": "1.0.0",
  "timestamp": "2026-11-10T22:30:00.000Z"
}
```

---

### 2. Telemetry Ingestion
#### `POST /api/v1/telemetry/ingest`
Ingests a single network flow event, persists it, and evaluates it through the hybrid detection pipeline.
- **Request Body:**
```json
{
  "source_ip": "10.0.0.5",
  "source_port": 49152,
  "destination_ip": "192.168.1.10",
  "destination_port": 21,
  "protocol": "TCP",
  "flow_duration": 120.5,
  "total_forward_packets": 14,
  "total_backward_packets": 18,
  "flow_bytes_per_second": 8244.9,
  "flow_packets_per_second": 13.06,
  "syn_flag_count": 1,
  "ack_flag_count": 0,
  "data_source": "SIMULATED"
}
```
- **Status:** `200 OK`
- **Response:**
```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "alert_generated": true,
  "risk_score": 88.5,
  "risk_level": "CRITICAL",
  "attack_type": "PORT_SCAN",
  "confidence": 0.94
}
```

---

### 3. Telemetry Flows Query
#### `GET /api/v1/telemetry/flows`
Retrieves paginated network flows.
- **Query Parameters:**
  - `limit` (optional, default 50): Page size.
  - `offset` (optional, default 0): Record offset.
  - `source` (optional, default `ALL`): `ALL`, `OBSERVED`, `SIMULATED`, or `DATASET`.
- **Status:** `200 OK`
- **Response:** Array of network flow objects.

---

### 4. Telemetry Statistics
#### `GET /api/v1/telemetry/stats`
Provides real-time aggregate statistics across all captured flows.
- **Status:** `200 OK`
- **Response:**
```json
{
  "total_flows": 1250,
  "total_packets": 85400,
  "total_bytes": 104857600,
  "average_flow_duration_ms": 340.2,
  "average_bandwidth_kbps": 128.5
}
```

---

### 5. Threat Alerts
#### `GET /api/v1/alerts`
Retrieves security alerts filtered by triage status, severity, or data provenance.
- **Query Parameters:**
  - `status` (optional): `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, `CONFIRMED_THREAT`
  - `severity` (optional): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - `source` (optional): `ALL`, `OBSERVED`, `SIMULATED`, `DATASET`
- **Status:** `200 OK`

#### `GET /api/v1/alerts/{id}`
Returns full alert forensics including local feature explanations (XAI) and mitigation history.
- **Status:** `200 OK` or `404 Not Found`

#### `PATCH /api/v1/alerts/{id}/status`
Transitions the triage status of an alert.
- **Request Body:**
```json
{
  "status": "INVESTIGATING"
}
```
- **Status:** `200 OK`

#### `POST /api/v1/alerts/{id}/mitigate`
Applies or simulates a containment action against the attacking entity.
- **Request Body:**
```json
{
  "action_type": "BLOCK_IP",
  "target_ip": "10.0.0.5",
  "analyst_notes": "Automated host block applied by analyst"
}
```
- **Status:** `200 OK`

#### `POST /api/v1/alerts/{id}/feedback`
Records human analyst feedback.
- **Request Body:**
```json
{
  "feedback_type": "FALSE_POSITIVE",
  "analyst_notes": "Scheduled internal vulnerability scan",
  "adjust_threshold": true
}
```
- **Status:** `200 OK`
- **Response:**
```json
{
  "status": "success",
  "feedback_id": "42fbb1c7-74be-419b-a083-d34a41eb6034",
  "threshold_adjusted": true,
  "message": "Feedback recorded. Adaptive threshold recalibrated."
}
```

---

### 6. Incident Management
#### `GET /api/v1/incidents`
Lists high-level incidents aggregating multiple correlated alerts.
- **Status:** `200 OK`

#### `GET /api/v1/incidents/{id}`
Returns an incident and its nested array of associated alerts.
- **Status:** `200 OK`

#### `PATCH /api/v1/incidents/{id}/status`
Updates incident status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`).
- **Status:** `200 OK`

---

### 7. Attack Simulation Laboratory
#### `GET /api/v1/simulation/scenarios`
Returns the catalog of executable attack scenarios (`PORT_SCAN`, `DDOS_SYN_FLOOD`, `BRUTE_FORCE`, `BOTNET_C2`).
- **Status:** `200 OK`

#### `POST /api/v1/simulation/execute`
Launches an asynchronous attack simulation. Synthetic events are generated in-memory with `data_source = SIMULATED`.
- **Request Body:**
```json
{
  "scenario": "PORT_SCAN",
  "target_ip": "10.0.0.5",
  "target_port": 21,
  "duration_seconds": 3.0
}
```
- **Status:** `200 OK`
- **Response:**
```json
{
  "run_id": "a268271b-67b2-43a3-9a8a-5e20546b7021",
  "status": "RUNNING",
  "message": "Simulation launched successfully"
}
```

#### `GET /api/v1/simulation/runs`
Lists all historical and running simulations with packet and alert metrics.
- **Status:** `200 OK`

---

### 8. Adaptive Thresholds
#### `GET /api/v1/adaptive/thresholds`
Lists all active adaptive thresholds (`anomaly_score`, `syn_flood_ratio`, `flow_rate_pps`, `port_scan_entropy`).
- **Status:** `200 OK`

#### `PATCH /api/v1/adaptive/thresholds`
Manually updates a threshold.
- **Request Body:**
```json
{
  "metric_name": "syn_flood_ratio",
  "threshold": 0.88,
  "reason": "Adjusted for higher baseline SYN volume"
}
```
- **Status:** `200 OK`

#### `GET /api/v1/adaptive/baseline`
Returns the normal traffic baseline statistics profile.
- **Status:** `200 OK`

#### `GET /api/v1/feedback`
Returns the historical audit trail of all analyst feedback records.
- **Status:** `200 OK`

---

### 9. Model Analytics & Explainability
#### `GET /api/v1/models/analytics`
Returns cross-validation and evaluation metrics for Random Forest and Isolation Forest (Accuracy, Precision, Recall, F1, ROC-AUC).
- **Status:** `200 OK`

#### `GET /api/v1/models/features`
Returns global feature importance rankings across all 40 flow attributes.
- **Status:** `200 OK`
