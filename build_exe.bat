@echo off
title IP Threat Scanner - Build Executable
color 0B

echo ========================================
echo    Building Standalone Executable
echo ========================================
echo.

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
    echo.
)

echo [INFO] Building executable...
echo This may take a few minutes...
echo.

REM Build using spec file for better compatibility
pyinstaller --noconfirm ip_scanner.spec

if errorlevel 1 (
    echo.
    echo [WARNING] Spec build failed, trying simple build...
    echo.
    pyinstaller --noconfirm --onefile --windowed ^
        --name "IP_Threat_Scanner" ^
        --collect-data customtkinter ^
        ip_scanner.py
)

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    echo.
    echo Try these solutions:
    echo 1. Run as Administrator
    echo 2. Disable antivirus temporarily
    echo 3. Install Visual C++ Redistributable
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Build Complete!
echo ========================================
echo.
echo Executable location:
echo   dist\IP_Threat_Scanner.exe
echo.
echo You can distribute this .exe file to anyone!
echo No Python installation required on their computer.
echo.
echo File size: 
dir /s dist\IP_Threat_Scanner.exe 2>nul | findstr "IP_Threat_Scanner"
echo.

pause
