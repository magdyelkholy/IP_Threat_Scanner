@echo off
title IP Threat Scanner - Installation
color 0A

echo ========================================
echo    IP Threat Scanner v2.0 - Setup
echo ========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo.
    echo Please download and install Python from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed
python --version
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install requirements
echo Installing required packages...
pip install customtkinter requests --upgrade
echo.

if errorlevel 1 (
    echo [ERROR] Failed to install packages!
    echo Try running as Administrator.
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Installation Complete!
echo ========================================
echo.
echo You can now run the scanner using:
echo   - Double-click "run_scanner.bat"
echo   - Or run: python ip_scanner.py
echo.

pause
