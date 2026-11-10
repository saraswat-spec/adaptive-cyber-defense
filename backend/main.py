"""
FastAPI Master Entrypoint for the Adaptive Cyberattack Detection & Prevention System.
"""

import asyncio
from contextlib import asynccontextmanager
import random
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from app.config import settings
from app.api.v1.router import api_router
from app.services.hybrid_detector import detector
from synthetic_data_generator import generate_benign_flow

# Background worker to generate realistic baseline background telemetry
async def background_traffic_monitor():
    """Generates continuous benign background telemetry with data_source='SIMULATED' (never claiming live packet capture)."""
    while True:
        try:
            flow = generate_benign_flow(source_label="SIMULATED")
            # 2% chance of subtle benign deviation (e.g. large file transfer)
            if random.random() < 0.02:
                flow["tot_len_fwd_pkts"] = 250000.0
                flow["flow_bytes_per_sec"] = 450000.0
            detector.process_flow(flow)
        except Exception as e:
            print(f"Error in background flow generator: {e}")
        await asyncio.sleep(2.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background traffic monitor
    task = asyncio.create_task(background_traffic_monitor())
    print("Mini-SOC Backend initialized with synthetic background telemetry generator (data_source=SIMULATED).")
    yield
    # Shutdown
    task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Adaptive Cyberattack Detection and Prevention System (Mini-SOC) REST & SSE API.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health")
@app.get("/api/v1/health")
def healthcheck():
    """System health & readiness check."""
    return {
        "status": "healthy",
        "service": "Mini-SOC Cyberattack Detection Engine",
        "models_loaded": {
            "isolation_forest": detector.iso_forest is not None,
            "random_forest": detector.rf_classifier is not None,
            "explainability_engine": detector.xai_engine is not None
        }
    }

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", settings.BACKEND_PORT))
    uvicorn.run("main:app", host=settings.BACKEND_HOST, port=port, reload=settings.DEBUG)
