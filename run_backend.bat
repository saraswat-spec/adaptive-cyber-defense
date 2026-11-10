@echo off
title Mini-SOC Backend Service
cd /d "%~dp0backend"
echo ===================================================
echo Starting Adaptive Mini-SOC FastAPI Backend Service
echo Port: 8000 | Host: 0.0.0.0
echo ===================================================
call "..\.venv\Scripts\activate.bat"
python -m uvicorn main:app --reload --port 8000 --host 0.0.0.0
pause
