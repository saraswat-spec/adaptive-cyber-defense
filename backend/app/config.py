"""
Application Configuration Settings.
Loads environment variables and sets defaults for the Mini-SOC FastAPI backend.
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Adaptive Cyberattack Detection and Prevention System"
    API_V1_STR: str = "/api/v1"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    DEBUG: bool = True

    # Supabase Configuration
    SUPABASE_URL: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None
    SUPABASE_JWT_SECRET: Optional[str] = None

    # Paths to ML artifacts (relative to backend or absolute)
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ML_ARTIFACTS_DIR: str = os.environ.get("ML_ARTIFACTS_DIR", os.path.join(BASE_DIR, "ml_engine", "artifacts"))

    # Allowed CORS Origins for Frontend Integration
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*"
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
