# Adaptive Cyberattack Detection & Prevention System (Mini-SOC)

[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-teal.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.0-purple.svg)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-cyan.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](LICENSE)

An enterprise-grade, interactive **Security Operations Center (SOC)** web application featuring hybrid machine learning threat detection, explainable AI (XAI), human-in-the-loop adaptive feedback, simulated attack red-teaming, and dynamic containment response.

---

## Architecture Topology

The platform is engineered using a decoupled, production-ready microservices architecture:

```
Cyber attack detection system/
├── frontend/               # React 18 + Vite + TypeScript + Tailwind CSS (Netlify)
├── java-backend/           # Java 21 + Spring Boot 3.2.5 + Spring Data JPA (Render)
├── backend/                # Python 3.11 + FastAPI + Uvicorn ML Microservice (Render)
├── ml_engine/              # Scikit-learn Pipelines, Trained Estimators & Baseline Profiles
├── docs/                   # Comprehensive Technical & Architectural Specifications
│   ├── ARCHITECTURE.md     # System architecture, microservices, and data flow pipelines
│   ├── JAVA_CONCEPTS.md    # In-depth guide of Java OOP, Spring Boot, JPA & Concurrency
│   ├── METHODOLOGY.md      # Mathematical models, CICIDS2017 features, and XAI algorithms
│   ├── DEPLOYMENT.md       # Step-by-step production deployment for Netlify, Render & Supabase
│   ├── API_DOCUMENTATION.md# Complete REST API reference for all 20+ endpoints
│   └── supabase_setup.sql  # Production PostgreSQL DDL schema and initial seed data
├── run_all.bat             # One-click Windows launcher for all three tiers
├── Dockerfile              # Containerization specs for Java and Python services
└── .env.example            # Master environment variable template
```

---

## Key Features

1. **Hybrid Threat Detection Engine:**
   - **Unsupervised Anomaly Detection:** 150-tree Isolation Forest detects novel zero-day behavioral deviations.
   - **Supervised Classification:** 150-tree Random Forest classifies known attack vectors (`PORT_SCAN`, `DDOS_SYN_FLOOD`, `SSH_BRUTE_FORCE`, `BOTNET_C2`).
   - **Heuristic Rule Engine:** Validates RFC protocol compliance, TCP handshake flags, and entropy metrics.
   - **Composite Risk Scoring:** Dynamic $0.0 - 100.0$ scoring synthesizing supervised probabilities, anomaly distance, and signature alerts.

2. **Explainable AI (XAI):**
   - Standardized variance feature attribution against enterprise baselines.
   - Automated natural language threat briefings explaining why an alert was triggered.

3. **Human-in-the-Loop Adaptive Learning:**
   - Analyst triage feedback (`CONFIRMED_THREAT`, `FALSE_POSITIVE`, `BENIGN_ANOMALY`).
   - Controlled false positive reduction with sample quorum ($N \ge 2$) and safety boundary clamping.
   - Baseline preservation: Confirmed threats reinforce intelligence without weakening thresholds.

4. **Attack Simulation Laboratory:**
   - Asynchronous red-team simulation engine generating synthetic network traffic entirely in-memory.
   - Strict data provenance tagging (`data_source = SIMULATED`).

5. **Active Containment & Mitigation:**
   - One-click and automated containment script generation (`BLOCK_IP`, `RATE_LIMIT`, `ISOLATE_HOST`).
   - Dry-run execution mode with IP whitelist safeguards to prevent self-lockout.

---

## Production Deployment Arrangement

| Layer | Recommended Host | Artifact / Build | Configuration |
|---|---|---|---|
| **Frontend** | **Netlify** | `npm run build` -> `dist` | `frontend/netlify.toml`, `_redirects`, `VITE_API_BASE_URL` |
| **Java Backend** | **Render** | Dockerfile (`maven` -> `eclipse-temurin-21`) | `java-backend/Dockerfile`, `$PORT`, `$SOC_PYTHON_ML_URL` |
| **Python ML Engine**| **Render** | Dockerfile (`python:3.11-slim`) | `backend/Dockerfile`, `$PORT`, `$ML_ARTIFACTS_DIR` |
| **Database** | **Supabase** | PostgreSQL 15 | `docs/supabase_setup.sql` |

Detailed deployment guides are available in [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md).

---

## Quick Start (Local Development)

### Prerequisites
- **Java:** JDK 21+ and Maven 3.9+
- **Python:** Python 3.10+
- **Node.js:** Node.js 18+ and npm

### Automated One-Click Start (Windows)
```cmd
run_all.bat
```

### Manual Individual Commands

**1. Launch Python ML Microservice (Port 8000):**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**2. Launch Java Spring Boot Backend (Port 9090):**
```bash
cd java-backend
mvn spring-boot:run
```

**3. Launch React Frontend (Port 5173):**
```bash
cd frontend
npm install
npm run dev
```

Open your browser to: **`http://localhost:5173`**

---

## Automated Test Verification

### Java Spring Boot Test Suite
The backend contains comprehensive automated integration and unit tests covering feedback loops, JPA cascades, simulation runs, and detection pipelines:
```bash
cd java-backend
mvn test
```
*Result: 10 tests across 4 test classes pass with 0 failures.*

### Python ML Engine Verification
```bash
python -c "from app.services.hybrid_detector import detector; res = detector.process_flow({'tot_fwd_pkts': 14, 'tot_bwd_pkts': 18, 'flow_bytes_per_sec': 8244.9, 'flow_packets_per_sec': 13.06}); print('Status:', res.get('status'))"
```

### Frontend TypeScript & Production Build
```bash
cd frontend
npm run build
```
*Result: 0 TypeScript errors; bundle compiled to `frontend/dist`.*

---

## Documentation Links

- **[System Architecture (ARCHITECTURE.md)](./docs/ARCHITECTURE.md)**
- **[Java & Spring Concepts Guide (JAVA_CONCEPTS.md)](./docs/JAVA_CONCEPTS.md)**
- **[Detection & ML Methodology (METHODOLOGY.md)](./docs/METHODOLOGY.md)**
- **[Production Deployment Guide (DEPLOYMENT.md)](./docs/DEPLOYMENT.md)**
- **[REST API Documentation (API_DOCUMENTATION.md)](./docs/API_DOCUMENTATION.md)**
- **[Supabase PostgreSQL Schema (supabase_setup.sql)](./docs/supabase_setup.sql)**
