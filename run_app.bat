@echo off
setlocal
cd /d "%~dp0"

echo ===================================================
echo   Network Connection Test - Auto Runner
echo ===================================================

if not exist .venv (
    echo [INFO] Creating virtual environment .venv...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Please ensure Python is installed and valid.
        pause
        exit /b 1
    )
)

echo [INFO] Activating virtual environment...
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
) else (
    echo [ERROR] Virtual environment scripts not found.
    pause
    exit /b 1
)

echo [INFO] checking dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo.
echo [INFO] Starting Application...
echo [INFO] Please wait for the browser to open...

python app.py

pause
