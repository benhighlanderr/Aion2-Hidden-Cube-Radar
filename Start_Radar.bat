@echo off
title Aion 2 3D Navigation Radar

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator privileges required for network packet capture...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~dpnx0\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ====================================================
echo             Starting Aion 2 3D Nav Radar...
echo ====================================================
echo.

py aion2_nav_radar.py
if %errorLevel% neq 0 (
    echo.
    echo ====================================================
    echo [ERROR] An error occurred while running the radar!
    echo Please make sure you ran "Install_Requirements.bat"
    echo and that Npcap is installed on your system.
    echo ====================================================
    pause
)
