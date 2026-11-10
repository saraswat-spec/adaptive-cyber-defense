@echo off
title Mini-SOC Java Spring Boot Backend (Port 9090)
set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.13.9-hotspot"
set "MAVEN_HOME=C:\Users\kalpa\AppData\Local\Programs\apache-maven-3.9.6"
set "PATH=%MAVEN_HOME%\bin;%JAVA_HOME%\bin;%PATH%"

cd /d "%~dp0java-backend"

echo ==========================================================
echo Starting Adaptive Cyberattack Detection Java Spring Boot
echo Server Port: 9090
echo Database: H2 In-Memory (Console: http://localhost:9090/h2-console)
echo ML Delegation: http://localhost:8000/api/v1 (Python ML Service)
echo ==========================================================

if exist "target\soc-java-backend-1.0.0.jar" (
    echo Launching packaged Spring Boot executable JAR...
    java -jar "target\soc-java-backend-1.0.0.jar"
) else (
    echo Target JAR not found. Running with Maven spring-boot:run...
    mvn spring-boot:run
)

pause
