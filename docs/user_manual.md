# Mini-SOC User Manual & Operator Guide

## Adaptive Cyberattack Detection and Prevention System Using Behavioural Analysis and Dynamic Threat Intelligence

---

### 1. Overview & System Capabilities

The **Adaptive Cyberattack Detection and Prevention System (Mini-SOC)** is an engineering testbed and operational dashboard designed for security analysts and engineers.

#### Operational Modules:
1. **Executive SOC Dashboard:** Live threat risk gauge (0–100), real-time traffic volume stream, attack distribution breakdown, and priority alert ticker.
2. **Traffic Flow Monitor:** In-depth packet flow inspector with provenance filter buttons (`ALL`, `OBSERVED`, `SIMULATED`).
3. **Incident Triage & Management:** Deep forensics modal with **Explainable AI (XAI)** feature attributions, recommended firewall containment scripts (with dry-run simulation mode), and false-positive active learning buttons.
4. **Attack Simulation Laboratory:** Red-team simulation testbed for executing synthetic **SYN Floods**, **Port Scans**, **Brute Force**, **Web Attacks**, and **C2 Infiltration Beacons**.
5. **Adaptive Baseline & Threshold Config:** Live threshold cards, sensitivity calibration sliders, and historical audit trail showing how analyst feedback auto-tunes detection tolerance.
6. **Machine Learning Analytics:** 6x6 Multi-Class Confusion Matrix, ROC-AUC curves, Accuracy, F1-scores, and Top 15 Feature Importances.

---

### 2. Launching the System Locally

#### One-Click Launch (Windows):
Double-click `run_all.bat` in the root folder, which will:
1. Launch the FastAPI backend on `http://localhost:8000` (API documentation at `/docs`).
2. Launch the React Vite frontend on `http://localhost:5173`.

#### Manual Terminal Launch:
- **Backend:**
  ```powershell
  cd "C:\Users\kalpa\OneDrive\Desktop\Cyber attack detection system\backend"
  ..\.venv\Scripts\activate
  python -m uvicorn main:app --reload --port 8000
  ```
- **Frontend:**
  ```powershell
  cd "C:\Users\kalpa\OneDrive\Desktop\Cyber attack detection system\frontend"
  npm run dev
  ```

---

### 3. Step-by-Step Operator Workflows

#### A. Running an Attack in the Simulation Lab
1. Navigate to the **Attack Lab** tab on the left sidebar.
2. Select any scenario preset:
   - **Volumetric SYN Flood (DDoS)**
   - **Reconnaissance / TCP Port Scan**
   - **Authentication Brute Force**
   - **Web Application Exploit (SQLi / XSS)**
   - **Stealthy C2 Infiltration Beacon**
3. Adjust the **Packet Generation Velocity** slider (e.g., 2,500 pkts/s) and **Duration** (e.g., 5 seconds).
4. Click **Launch Attack Simulation**.
5. Switch to the **Executive SOC** or **Traffic Monitor** tab:
   - Observe the live packet velocity spike in the dual-area graph (violet line denotes `SIMULATED` traffic).
   - Watch the **Dynamic Threat Risk Gauge** rise into the `HIGH` or `CRITICAL` zone.
   - The new alert appears in the Incident Feed with the badge `SIMULATED`.

#### B. Triaging an Incident with Explainable AI
1. Go to the **Incident Triage** tab or click any alert in the Dashboard feed.
2. Click **XAI Forensics** on the alert.
3. The forensic modal opens:
   - **Explainable AI Narrative:** Explains the plain-English cause (e.g., *SYN flag count is 11.2x higher than baseline with 4,200 pkts/s generation rate*).
   - **Feature Attributions Table:** Highlights the top 5 deviating flow metrics (Z-score, observed vs. baseline mean).
   - **Recommended Mitigation:** Provides the exact `iptables` and `nftables` containment commands with a 1-click **Copy Script** button.
   - **Simulate Containment:** Tests the firewall action safely in non-destructive dry-run mode.

#### C. Testing the Adaptive Feedback Loop (False Positive Reduction)
1. In the Incident Forensics modal, click **False Positive**.
2. Notice the instant confirmation banner: *Baseline anomaly threshold adaptively tuned*.
3. Navigate to the **Adaptive Config** tab:
   - See the updated `anomaly_score` threshold.
   - The historical recalibration audit record is saved with the exact timestamp and rationale.
   - Future flows with similar distributions will have their anomaly distance relaxed to prevent alert fatigue.

---

### 4. Database Setup (Supabase)

To connect the application to a cloud Supabase PostgreSQL database:
1. Open [Supabase Dashboard](https://supabase.com).
2. Create a new project.
3. Navigate to the **SQL Editor** and paste the contents of:
   `docs/supabase_setup.sql`
4. Click **Run** to provision all 9 indexed tables, constraints, and initial thresholds.
5. In `backend/.env` and `frontend/.env`, set:
   ```env
   SUPABASE_URL="https://your-project-id.supabase.co"
   SUPABASE_KEY="your-anon-or-service-role-key"
   ```

*(Note: The system includes a high-throughput in-memory fallback store and runs self-contained without requiring internet access or live credentials).*

---

### 5. Deployment Guide

#### Frontend Deployment (Netlify):
1. Connect your repository to Netlify.
2. Build Settings:
   - **Base directory:** `frontend`
   - **Build command:** `npm run build`
   - **Publish directory:** `frontend/dist`
3. In `frontend/netlify.toml`, update the proxy redirect to point to your live backend URL:
   ```toml
   [[redirects]]
     from = "/api/*"
     to = "https://your-backend-service.onrender.com/api/:splat"
     status = 200
     force = true
   ```

#### Backend Deployment (Render / Railway / Fly.io):
1. Deploy `backend/` as a Python web service using Python 3.11+.
2. Start Command:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
3. Copy `ml_engine/artifacts/` into the deployment directory or package them with the service.
