@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

cd /d "%~dp0"
if not exist logs mkdir logs

if "%NIDS_INTERFACE%"=="" set "NIDS_INTERFACE=Wi-Fi"

echo ==========================================
echo   AlertMesh - Start Python NIDS on Windows
echo ==========================================
echo.
echo This is the recommended Windows fallback when Snort cannot see interfaces.
echo It uses Scapy/Npcap and writes accepted alerts to the configured database.
echo.
echo Available interfaces:
python nids.py --list-interfaces
echo.
echo Using interface: %NIDS_INTERFACE%
echo.
echo Keep this window open. Press Ctrl+C to stop.
echo.
python nids.py --interface "%NIDS_INTERFACE%"
