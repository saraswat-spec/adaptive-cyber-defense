# Python FastAPI ML Microservice Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application and ML model artifacts
COPY backend /app/backend
COPY ml_engine /app/ml_engine

# Set python path and environment
ENV PYTHONPATH="/app/backend:/app:/app/ml_engine"
ENV ML_ARTIFACTS_DIR="/app/ml_engine/artifacts"
ENV PORT=8000
EXPOSE 8000

WORKDIR /app/backend

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
