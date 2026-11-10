@echo off
title Launch Mini-SOC System
echo ==========================================================
echo Launching Adaptive Cyberattack Detection & Prevention SOC
echo ==========================================================

echo [1/3] Starting Python ML Inference Backend (Port 8000)...
start "Mini-SOC Python ML Service" cmd /c "%~dp0run_backend.bat"

timeout /t 4 /nobreak >nul

echo [2/3] Starting Java Spring Boot Application Backend (Port 9090)...
start "Mini-SOC Java Spring Boot" cmd /c "%~dp0run_java_backend.bat"

timeout /t 5 /nobreak >nul

echo [3/3] Starting React SOC Dashboard Frontend (Port 5173)...
start "Mini-SOC React Frontend" cmd /c "%~dp0run_frontend.bat"

echo.
echo ==========================================================
echo All services launched!
echo - Frontend SOC Dashboard:  http://localhost:5173
echo - Java Spring Boot Backend: http://localhost:9090
echo - H2 Database Console:     http://localhost:9090/h2-console
echo - Python ML Service:       http://localhost:8000
echo - Python Swagger Docs:     http://localhost:8000/docs
echo ==========================================================
