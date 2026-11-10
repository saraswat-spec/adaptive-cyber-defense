# Production Deployment Guide (DEPLOYMENT.md)

This comprehensive guide details step-by-step instructions for deploying the **Adaptive Cyberattack Detection and Prevention System (Mini-SOC)** into production across **Netlify** (Frontend), **Render** (Java & Python Microservices), and **Supabase** (PostgreSQL Database), while preserving full local development capabilities.

---

## Architecture Topology

```
+-------------------------------------------------------------+
|                 CLIENT BROWSER (SOC ANALYST)                |
+-------------------------------------------------------------+
                              |
                              | HTTPS (CORS Enabled)
                              v
+-------------------------------------------------------------+
|              FRONTEND: React 18 + Vite (Netlify)            |
|  - Host: https://your-soc-app.netlify.app                   |
|  - SPA Routing: /* -> /index.html 200                       |
|  - Env: VITE_API_BASE_URL=https://soc-java.onrender.com     |
+-------------------------------------------------------------+
                              |
                              | REST JSON API (/api/v1/*)
                              v
+-------------------------------------------------------------+
|         BACKEND: Java Spring Boot 3.2.5 (Render / Docker)   |
|  - Host: https://soc-java.onrender.com                      |
|  - Port: Dynamically assigned via $PORT                     |
|  - Health: /health or /api/v1/health                        |
|  - Database: Supabase PostgreSQL (or in-memory H2 default)  |
+-------------------------------------------------------------+
                              |
                              | Private HTTP / Internal REST
                              v
+-------------------------------------------------------------+
|         ML ENGINE: Python FastAPI (Render / Docker)         |
|  - Host: https://soc-ml.onrender.com (or private network)   |
|  - Port: Dynamically assigned via $PORT (default 8000)      |
|  - Inference: POST /api/v1/ml/predict                       |
|  - Health: /health or /api/v1/health                        |
+-------------------------------------------------------------+
                              |
                              | SSL Connection Pool (JDBC)
                              v
+-------------------------------------------------------------+
|               DATABASE: Supabase (PostgreSQL 15)            |
|  - Host: db.<PROJECT_REF>.supabase.co:5432                  |
|  - Schema: Initialized via docs/supabase_setup.sql          |
+-------------------------------------------------------------+
```

---

## 1. Database Setup: Supabase (PostgreSQL)

If persistent production storage is desired instead of the default local H2 database:

1. Create a free account at [Supabase](https://supabase.com) and create a new project (e.g. `soc-production-db`).
2. Navigate to the **SQL Editor** tab in the Supabase Dashboard.
3. Open [`docs/supabase_setup.sql`](./supabase_setup.sql), copy its complete contents, paste into the SQL Editor, and click **Run**.
4. This provisions all 7 core tables (`simulation_runs`, `network_events`, `threat_alerts`, `incidents`, `analyst_feedback`, `prevention_actions`, `adaptive_thresholds`), performance indices, and default baseline threshold seeds.
5. In **Project Settings** -> **Database**, note down the **Connection String (JDBC format)**:
   ```
   jdbc:postgresql://db.<PROJECT_REF>.supabase.co:5432/postgres?sslmode=require
   ```

---

## 2. Python ML Microservice: Render Deployment

The Python ML engine serves Isolation Forest and Random Forest inferences with feature explanations.

### Option A: Deploy via Docker (Recommended)
1. In [Render](https://render.com), click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Select **Docker** as the Environment.
4. Set the **Dockerfile Path** to:
   ```
   backend/Dockerfile
   ```
5. Set the **Docker Context** to the repository root (`.`):
6. Configure the Environment Variables:
   | Variable | Value | Description |
   |---|---|---|
   | `PORT` | `8000` | Port automatically routed by Render |
   | `DEBUG` | `false` | Disable debug reloader in production |
   | `CORS_ORIGINS` | `["https://*.netlify.app","http://localhost:5173"]` | Allowed origins |

7. Set Health Check Path to:
   ```
   /health
   ```
8. Click **Deploy Web Service**. Once deployed, copy your service URL (e.g., `https://soc-ml-service.onrender.com`).

---

## 3. Java Spring Boot Backend: Render Deployment

The Java backend handles enterprise business logic, detection coordination, and persistence.

### Deploy via Docker
1. In [Render](https://render.com), click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Select **Docker** as the Environment.
4. Set the **Dockerfile Path** to:
   ```
   java-backend/Dockerfile
   ```
5. Set the **Docker Context** to:
   ```
   java-backend
   ```
6. Configure the Environment Variables:
   | Variable | Value | Description |
   |---|---|---|
   | `PORT` | `9090` | Internal listen port (assigned by Render) |
   | `SOC_PYTHON_ML_URL` | `https://soc-ml-service.onrender.com/api/v1` | URL of the deployed Python ML service |
   | `SOC_CORS_ALLOWED_ORIGINS` | `https://your-soc-app.netlify.app,https://*.netlify.app` | Allowed frontend domains |
   | `H2_CONSOLE_ENABLED` | `false` | Disable web console in production |
   | `SPRING_PROFILES_ACTIVE` | `postgres` (optional) | Set if connecting to Supabase |
   | `SPRING_DATASOURCE_URL` | `jdbc:postgresql://db.<REF>.supabase.co:5432/postgres?sslmode=require` | Supabase JDBC URL |
   | `SPRING_DATASOURCE_USERNAME` | `postgres` | Database username |
   | `SPRING_DATASOURCE_PASSWORD` | `<YOUR_DB_PASSWORD>` | Database password |

7. Set Health Check Path to:
   ```
   /health
   ```
8. Click **Deploy Web Service**. Once deployed, copy your Java backend URL (e.g., `https://soc-java-backend.onrender.com`).

---

## 4. React Frontend: Netlify Deployment

The React 18 / Vite frontend provides the interactive Security Operations Center dashboard.

1. In [Netlify](https://www.netlify.com), click **Add new site** -> **Import an existing project**.
2. Connect your GitHub repository.
3. Configure the Build & Deploy settings:
   - **Base directory:** `frontend`
   - **Build command:** `npm run build`
   - **Publish directory:** `frontend/dist`
4. In **Site Configuration** -> **Environment variables**, add:
   | Key | Value |
   |---|---|
   | `VITE_API_BASE_URL` | `https://soc-java-backend.onrender.com` |

5. Click **Deploy Site**.
6. The `frontend/netlify.toml` and `frontend/public/_redirects` files ensure that Single-Page Application (SPA) routing routes all paths (`/dashboard`, `/alerts`, `/simulation`, `/config`) correctly to `/index.html` without 404 errors on page reload.

---

## 5. Local Development Execution

To run the complete system locally without cloud infrastructure:

### Prerequisites
- Java JDK 21+ and Maven 3.9+
- Python 3.10+
- Node.js 18+ and npm

### Quick Start via Automated Script (Windows)
Run the root batch file:
```cmd
run_all.bat
```

### Manual Individual Commands

**1. Start Python ML Microservice (Port 8000):**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**2. Start Java Spring Boot Backend (Port 9090):**
```bash
cd java-backend
mvn spring-boot:run
```

**3. Start React Frontend (Port 5173):**
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173` to access the SOC Dashboard.

---

## 6. Production Troubleshooting & Verification

| Symptom | Diagnostic Step | Resolution |
|---|---|---|
| **CORS Policy Error** in browser console | Check `SOC_CORS_ALLOWED_ORIGINS` in Java backend | Ensure exact Netlify URL (e.g. `https://my-app.netlify.app`) is included in the comma-separated origin list. |
| **503 ML Service Unavailable** | Verify Python service status at `/health` | Confirm `SOC_PYTHON_ML_URL` environment variable in Java points to the reachable Python host. |
| **404 on Page Refresh on Netlify** | Inspect publish directory and `_redirects` | Ensure `frontend/public/_redirects` containing `/* /index.html 200` is copied into `dist`. |
| **Database Connection Refused** | Verify Supabase SSL and IP whitelist | Ensure JDBC connection string includes `?sslmode=require`. |
