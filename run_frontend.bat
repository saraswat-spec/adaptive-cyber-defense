@echo off
title Mini-SOC React Frontend
cd /d "%~dp0frontend"
echo ===================================================
echo Starting Adaptive Mini-SOC React + Vite Frontend
echo Local: http://localhost:5173
echo ===================================================
set "PATH=C:\Program Files\nodejs;%PATH%"
npm run dev
pause
