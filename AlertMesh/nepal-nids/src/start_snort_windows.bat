@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

cd /d "%~dp0"
if not exist logs mkdir logs

if "%SNORT_EXE%"=="" (
    where snort >nul 2>&1
    if %errorlevel% equ 0 (
        set "SNORT_EXE=snort"
    ) else if exist "C:\Snort\bin\snort.exe" (
        set "SNORT_EXE=C:\Snort\bin\snort.exe"
    ) else if exist "C:\Program Files\Snort\bin\snort.exe" (
        set "SNORT_EXE=C:\Program Files\Snort\bin\snort.exe"
    ) else if exist "C:\Program Files (x86)\Snort\bin\snort.exe" (
        set "SNORT_EXE=C:\Program Files (x86)\Snort\bin\snort.exe"
    )
)

echo ==========================================
echo   AlertMesh - Start Snort on Windows
echo ==========================================
echo.
echo Using Snort executable: %SNORT_EXE%
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Snort packet capture must run from an Administrator terminal.
    echo.
    echo Close this window, open PowerShell as Administrator, then run:
    echo   cd /d "%CD%"
    echo   .\start_snort_windows.bat
    echo.
    pause
    exit /b 1
)

if "%SNORT_EXE%"=="" (
    echo [ERROR] snort.exe was not found.
    echo.
    echo Install Snort for Windows, or set SNORT_EXE to the full path:
    echo   set "SNORT_EXE=C:\Snort\bin\snort.exe"
    echo   .\start_snort_windows.bat
    echo.
    echo If Snort is installed somewhere else, use that full snort.exe path.
    pause
    exit /b 1
)

"%SNORT_EXE%" -V >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Could not run Snort executable:
    echo   %SNORT_EXE%
    echo.
    echo Set SNORT_EXE to the full path of snort.exe and try again.
    pause
    exit /b 1
)

if "%SNORT_INTERFACE%"=="" (
    echo Available interfaces:
    "%SNORT_EXE%" -W
    echo.
    echo If the Snort table above is empty, try one of these NPF device names:
    powershell -NoProfile -Command "Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true -and $_.GUID } | ForEach-Object { Write-Host ('  \Device\NPF_' + $_.GUID + '    ' + $_.NetConnectionID + ' / ' + $_.Name) }"
    echo.
    echo Recommended for normal Wi-Fi testing: choose the NPF line that says Wi-Fi.
    echo You may paste the full \Device\NPF_{...} value here.
    echo.
    set /p SNORT_INTERFACE="Enter Snort interface number/name: "
)

if "%SNORT_HOME_NET%"=="" (
    for /f "tokens=1,* delims==" %%A in ('findstr /b /i "PROTECTED_NETWORKS=" ".env" 2^>nul') do set "SNORT_HOME_NET=%%B"
)
if "%SNORT_HOME_NET%"=="" set "SNORT_HOME_NET=192.168.1.0/24"
for /f "tokens=1 delims=," %%A in ("%SNORT_HOME_NET%") do set "SNORT_HOME_NET=%%A"

echo.
echo Using HOME_NET: %SNORT_HOME_NET%
echo Testing Snort configuration...
"%SNORT_EXE%" -T -S HOME_NET="%SNORT_HOME_NET%" -c "%CD%\snort.conf" -l "%CD%\logs"
if errorlevel 1 (
    echo.
    echo [ERROR] Snort configuration test failed.
    echo Check snort.conf, local.rules, HOME_NET, and your Snort install path.
    pause
    exit /b 1
)

echo.
echo Starting Snort. Alerts will be written to: %CD%\logs\alert.ids
echo Keep this window open.
echo.
if not exist "%CD%\logs\alert.ids" type nul > "%CD%\logs\alert.ids"
"%SNORT_EXE%" -i %SNORT_INTERFACE% -S HOME_NET="%SNORT_HOME_NET%" -c "%CD%\snort.conf" -A fast -l "%CD%\logs"
