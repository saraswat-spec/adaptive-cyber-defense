# System Architecture & Technical Specifications (ARCHITECTURE.md)

This document details the architectural topology, component interactions, and data flow pipelines of the **Adaptive Cyberattack Detection and Prevention System Using Behavioural Analysis and Dynamic Threat Intelligence (Mini-SOC)**.

---

## High-Level System Architecture

```
+-----------------------------------------------------------------------------------------+
|                                    PRESENTATION TIER                                    |
|                      React 18 + Vite + TypeScript + Tailwind CSS                        |
|                                                                                         |
|  [Traffic Monitor]   [Alerts Triage]   [Attack Simulation Lab]   [Adaptive Thresholds]   |
+-----------------------------------------------------------------------------------------+
                                         |
                                         | REST / JSON (CORS Enabled)
                                         v
+-----------------------------------------------------------------------------------------+
|                                APPLICATION SERVICES TIER                                |
|                        Java 21 + Spring Boot 3.2.5 (Port 9090)                          |
|                                                                                         |
|  Controllers:                                                                           |
|   - DetectionController     - AlertController           - IncidentController            |
|   - SimulationController    - FeedbackController        - ModelAnalyticsController      |
|                                                                                         |
|  Core Services:                                                                         |
|   - DetectionServiceImpl    - SimulationServiceImpl     - AdaptiveThresholdServiceImpl  |
|   - MitigationServiceImpl   - ThreatIntelligenceService                                 |
+-----------------------------------------------------------------------------------------+
                   |                                           |
                   | REST Prediction / XAI                     | Spring Data JPA / JDBC
                   v                                           v
+------------------------------------+     +----------------------------------------------+
|       MACHINE LEARNING TIER        |     |              PERSISTENCE TIER                |
|      Python 3.11 + FastAPI         |     |        H2 (Dev) / Supabase Postgres (Prod)   |
|           (Port 8000)              |     |                                              |
|                                    |     |  - network_events     - threat_alerts        |
|  - Isolation Forest (Anomaly)      |     |  - incidents          - analyst_feedback     |
|  - Random Forest (Classification)  |     |  - adaptive_thresholds - simulation_runs     |
|  - StandardScaler (Normalization)  |     |  - prevention_actions                        |
|  - Local Feature XAI Engine        |     +----------------------------------------------+
+------------------------------------+
```

---

## Component Breakdown

### 1. Presentation Tier (Frontend)
- **Framework:** React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, Recharts.
- **Role:** Provides a reactive, unified Security Operations Center (SOC) dashboard.
- **Key Modules:**
  - `TrafficMonitor`: Real-time telemetry inspector displaying forward/backward packets, instantaneous bandwidth in KB/s, flow rate in PPS, and protocol distributions.
  - `AlertsTriage`: Interactive security alert feed with severity color-coding, rule/ML triggers, local feature attributions, and one-click containment execution.
  - `SimulationLab`: Interactive control console to launch synthetic attacks (Port Scan, SYN Flood, Brute Force, Botnet C2) and track real-time packet generation and alert rates.
  - `AdaptiveConfig`: Visualizer for dynamic anomaly thresholds, baseline statistics distributions, and historical analyst feedback audit logs.
- **Hosting Target:** Netlify (configured with `dist` publish directory and SPA fallback redirects).

### 2. Application Services Tier (Java Backend)
- **Framework:** Java 21, Spring Boot 3.2.5, Spring Data JPA, Hibernate, Jakarta Bean Validation.
- **Role:** Central orchestrator for the SOC. Ingests network flows, triggers asynchronous simulations, coordinates ML inference calls, manages transactional database state, and records human-in-the-loop analyst feedback.
- **Hosting Target:** Render (containerized via multi-stage Alpine Dockerfile).

### 3. Machine Learning Inference Tier (Python ML Engine)
- **Framework:** Python 3.11, FastAPI, Uvicorn, Scikit-learn, NumPy, Pandas.
- **Role:** High-performance inference microservice evaluating 40 network flow features across two complementary machine learning models:
  - **Unsupervised Anomaly Detection:** Isolation Forest (150 trees) flagging statistical anomalies.
  - **Supervised Threat Classification:** Random Forest (150 trees) classifying specific attack families.
  - **Explainability (XAI):** Natural language explanation and local feature importance calculation comparing flow attributes against baseline enterprise traffic distributions.
- **Hosting Target:** Render (containerized via Python 3.11-slim Dockerfile).

### 4. Persistence Tier (Relational Storage)
- **Engines:**
  - **Local Development:** In-memory H2 Database (`jdbc:h2:mem:socdb`) or persistent file-based H2 (`jdbc:h2:file:./data/socdb`).
  - **Production:** Supabase / PostgreSQL (`application-postgres.properties` profile).
- **Core Entities:**
  1. `NetworkEvent`: Raw bidirectional network conversation metrics, tagged with `data_source` provenance (`OBSERVED`, `SIMULATED`, `DATASET`).
  2. `ThreatAlert`: High-risk security alerts generated when hybrid risk score $\ge 60.0$.
  3. `Incident`: Aggregation entity grouping multiple correlated alerts for forensic investigation.
  4. `AnalystFeedback`: Record of SOC operator triage (`CONFIRMED_THREAT`, `FALSE_POSITIVE`, `BENIGN_ANOMALY`).
  5. `AdaptiveThreshold`: Calibrated threshold records with baseline mean, standard deviation, and historical justification.
  6. `SimulationRun`: Execution metadata and telemetry counts for synthetic attack simulations.
  7. `PreventionAction`: Automated containment scripts (`BLOCK_IP`, `RATE_LIMIT`, `ISOLATE_HOST`).

---

## End-to-End Data Pipelines

### Pipeline 1: Telemetry Ingestion & Detection Flow
```
Flow Ingested (POST /api/v1/telemetry/ingest)
       |
       v
Persist NetworkEvent (JPA)
       |
       v
Invoke ML Inference (POST http://python-ml:8000/api/v1/ml/predict)
       |
       +---> Isolation Forest (Anomaly Score)
       +---> Random Forest (Attack Class + Confidence)
       +---> XAI Engine (Feature Attributions)
       |
       v
Evaluate Heuristic Detection Rules
       |
       v
Compute Composite Hybrid Risk Score (w_rule=0.35, w_rf=0.45, w_iso=0.20)
       |
       v
Score >= 60.0 ?
      /        \
   YES          NO
    /            \
Persist Alert     Log Telemetry Only
Recommend Action  Return 200 OK
Return Alert DTO
```

### Pipeline 2: Attack Simulation Laboratory Flow
```
Analyst launches simulation (POST /api/v1/simulation/execute)
       |
       v
Persist SimulationRun (status = "RUNNING")
       |
       v
Launch Asynchronous Worker (@Async CompletableFuture)
       |
       v  (Loop for duration: injects packets every 50ms)
Generate Synthetic Event (data_source = SIMULATED)
       |
Pass through DetectionService -> ML Engine -> Rule Engine
       |
Count Injected Packets & Triggered Alerts
       |
       v
Mark SimulationRun (status = "COMPLETED", ended_at = now())
```

### Pipeline 3: Analyst Feedback & Adaptive Recalibration Flow
```
Analyst submits feedback (POST /api/v1/alerts/{id}/feedback)
       |
       v
Type == CONFIRMED_THREAT ?
     /                   \
   YES                    NO (FALSE_POSITIVE)
    /                      \
Update Alert Status         Check Validated Feedback Quorum (N >= 2)
Preserve Thresholds         Quorum Met ?
threshold_adjusted = false     /          \
                             YES           NO
                              /             \
                   Bounded Recalibration   Log Feedback
                   Clamped to safety floor  threshold_adjusted = false
                   threshold_adjusted = true
```
