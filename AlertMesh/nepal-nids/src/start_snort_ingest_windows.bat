@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

cd /d "%~dp0"
if not exist logs mkdir logs

if "%SNORT_ALERT_FILE%"=="" set "SNORT_ALERT_FILE=%CD%\logs\alert.ids"
if "%ALERTMESH_DB_PATH%"=="" set "ALERTMESH_DB_PATH=%CD%\alertmesh.db"
if not exist "%CD%\logs" mkdir "%CD%\logs"
if not exist "%SNORT_ALERT_FILE%" type nul > "%SNORT_ALERT_FILE%"

echo ==========================================
echo   AlertMesh - Snort Alert Ingest
echo ==========================================
echo.
echo Watching: %SNORT_ALERT_FILE%
if /I "%ALERTMESH_DB_BACKEND%"=="mongodb" (
    echo Writing to: MongoDB from .env
) else (
    echo Writing to: %ALERTMESH_DB_PATH%
)
echo Keep this window open while Snort is running.
echo.

python snort_ingest.py --file "%SNORT_ALERT_FILE%"
