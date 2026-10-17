@echo off
title Aion 2 Radar - Install Requirements

cd /d "%~dp0"
echo ====================================================
echo      Aion 2 Radar - Python Package Setup
echo ====================================================
echo.

py --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH!
    echo Please install Python 3.10+ from python.org and check "Add Python to PATH".
    echo.
    pause
    exit /b
)

echo [+] Python detected.
echo [+] Installing required packages (scapy, lz4, psutil)...
echo.

py -m pip install --upgrade pip
py -m pip install -r requirements.txt

echo.
echo ====================================================
echo [NOTE] Npcap is required for network packet capture.
echo If Npcap or Wireshark is not installed:
echo Download and install it from https://npcap.com/#download
echo (Check "Install Npcap in WinPcap API-compatible Mode" during installation)
echo ====================================================
echo.
echo [+] All requirements installed successfully!
echo [+] You can now start the radar via "Start_Radar.bat".
echo.
pause
