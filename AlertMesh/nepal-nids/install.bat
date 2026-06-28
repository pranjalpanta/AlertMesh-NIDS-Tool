@echo off
setlocal
REM AlertMesh NIDS - Installation Script for Windows
REM Network-Based Intrusion Alert System with Advanced IP Logging for Corporate Offices in Nepal

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo ==========================================
echo   AlertMesh NIDS - Installation Script
echo ==========================================
echo.

REM Check Python
echo Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8 or higher.
    echo         Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found
python --version
echo.

REM Check if virtual environment exists
echo Checking virtual environment...
if exist venv (
    echo [WARNING] Virtual environment already exists
    set /p recreate="Recreate virtual environment? (y/n): "
    if /i "%recreate%"=="y" (
        echo Removing existing virtual environment...
        rmdir /s /q venv
        python -m venv venv
        echo [OK] Virtual environment recreated
    ) else (
        echo [OK] Using existing virtual environment
    )
) else (
    echo Creating virtual environment...
    python -m venv venv
    echo [OK] Virtual environment created
)
echo.

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
echo [OK] Virtual environment activated
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel >nul 2>&1
echo [OK] Pip upgraded
echo.

REM Install dependencies
echo Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [OK] Dependencies installed
echo.

REM Create .env file if it doesn't exist
echo Checking environment configuration...
if not exist src\.env (
    if exist src\.env.example (
        copy src\.env.example src\.env
        echo [OK] .env file created from .env.example
        echo [WARNING] Please edit src\.env with your credentials
    ) else (
        echo Creating basic .env file...
        (
            echo SECRET_KEY=generate_a_long_random_value_here
            echo SESSION_COOKIE_SECURE=False
            echo SESSION_COOKIE_HTTPONLY=True
            echo SESSION_COOKIE_SAMESITE=Lax
            echo USERNAME=change_this_admin_user
            echo PASSWORD=change_this_admin_password
            echo LOGIN_MAX_ATTEMPTS=5
            echo LOGIN_RATE_LIMIT_SECONDS=300
            echo TRUST_PROXY_HEADERS=false
            echo EMAIL_ENABLED=false
            echo SMTP_HOST=smtp.gmail.com
            echo SMTP_PORT=587
            echo SMTP_USE_TLS=true
            echo SMTP_USERNAME=
            echo SMTP_PASSWORD=
            echo SMTP_FROM=
            echo SMTP_TO=
            echo ALERT_COOLDOWN=60
            echo MAX_HISTORY=2000
            echo INCLUDE_DISCOVERY_TRAFFIC=false
            echo DASHBOARD_PACKET_CAPTURE_ENABLED=true
            echo PACKET_EXPORTS_ENABLED=false
            echo DASHBOARD_TIMEZONE=Asia/Kathmandu
            echo PROTECTED_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
            echo IGNORE_SOURCE_IPS=
            echo TRUSTED_SOURCE_IPS=
            echo ALERT_REJECT_TRUSTED_SOURCES=true
            echo ALERT_REQUIRE_PROTECTED_DESTINATION=true
            echo ALERT_MIN_CONFIDENCE=55
            echo ALERT_DEDUP_SECONDS=120
            echo ALERT_STRICT_MODE=false
            echo ALERT_ALLOWED_SOURCES=python,snort
            echo ALERT_ALLOWED_SNORT_SID_RANGES=9000001-9000013,9000024,9000026-9000029
            echo ALERT_ALLOW_LOW_CONFIDENCE=false
            echo ICMP_ALERT_THRESHOLD=5
            echo ICMP_ALERT_WINDOW=10
            echo EXPOSED_SERVICE_ALERT_THRESHOLD=3
            echo EXPOSED_SERVICE_ALERT_WINDOW=60
            echo TRACKER_CLEANUP_SECONDS=300
            echo GEOLOCATION_ENABLED=false
            echo WEBSITES_PORT=5001
            echo FLASK_ENV=development
            echo FLASK_DEBUG=False
            echo ALERTMESH_DB_PATH=alertmesh.db
            echo ALERTMESH_DB_BACKEND=sqlite
            echo MONGODB_URI=mongodb://localhost:27017
            echo MONGODB_DATABASE=alertmesh
            echo ALERT_RETENTION_DAYS=30
        ) > src\.env
        echo [OK] .env file created
        echo [WARNING] Please edit src\.env with your credentials
    )
) else (
    echo [OK] .env file already exists
)
echo.

REM Create logs directory
echo Creating logs directory...
if not exist src\logs mkdir src\logs
echo [OK] Logs directory created
echo.

REM Check Npcap (required for Scapy on Windows)
echo Checking Npcap installation...
if exist "%SystemRoot%\System32\Npcap\Packet.dll" (
    echo [OK] Npcap found
) else if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo [OK] Npcap found
) else if exist "%SystemRoot%\SysWOW64\Npcap\Packet.dll" (
    echo [OK] Npcap found
) else (
    echo [WARNING] Npcap not detected ^(needed for live packet capture^)
    echo   Download and install Npcap from: https://npcap.com/
    echo   Enable "WinPcap API-compatible mode" during install.
    echo   NOTE: Real packet capture will not work until Npcap is installed.
)
echo.

REM Check Snort
echo Checking Snort installation...
where snort >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Snort found on PATH
    snort -V
) else (
    echo [WARNING] Snort not found on PATH
    echo   Install Snort for Windows from: https://www.snort.org/downloads
    echo   Install Npcap first and run Snort from an Administrator terminal.
    echo   If snort.exe is not on PATH, set SNORT_EXE to the full path.
)
echo.

REM Print summary
echo ==========================================
echo   Installation Complete!
echo ==========================================
echo.
echo [OK] Virtual environment: venv\
echo [OK] Dependencies        : Installed
echo [OK] Configuration       : src\.env
echo [OK] Logs directory      : src\logs\
echo.
echo Next Steps:
echo.
echo   1. Configure email alerts:
echo      - Open src\.env
echo      - Set EMAIL_ENABLED=true and SMTP_* values
echo      - Run: python src\test_email.py
echo.
echo   2. Activate virtual environment:
echo        venv\Scripts\activate.bat
echo.
echo   3. Option A - Start the Python NIDS engine (in one terminal):
echo        cd src
echo        python nids.py
echo.
echo   3. Option B - Start Snort on Windows (recommended detector):
echo        cd src
echo        start_snort_windows.bat
echo.
echo      Then start the Snort alert ingester in another terminal:
echo        cd src
echo        start_snort_ingest_windows.bat
echo.
echo   4. Start the dashboard:
echo        cd src
echo        python app.py
echo.
echo   Access dashboard at: http://localhost:5001
echo   Dashboard login is read from src\.env ^(USERNAME and PASSWORD^)
echo.
echo [WARNING] Run as Administrator for live packet capture.
echo           Without admin rights or Npcap, no packet capture will run.
echo.
pause
