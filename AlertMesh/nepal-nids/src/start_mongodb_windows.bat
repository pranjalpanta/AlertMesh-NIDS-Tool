@echo off
setlocal

if "%MONGOD_EXE%"=="" (
    for /f "delims=" %%P in ('where mongod 2^>nul') do (
        if "%MONGOD_EXE%"=="" set "MONGOD_EXE=%%P"
    )
)
if "%MONGOD_EXE%"=="" set "MONGOD_EXE=C:\Program Files\MongoDB\Server\8.3\bin\mongod.exe"
set "MONGODB_DATA_DIR=%~dp0..\..\mongodb-data"
set "MONGODB_LOG_DIR=%~dp0..\..\mongodb-logs"

if not exist "%MONGOD_EXE%" (
    echo [ERROR] mongod.exe was not found at:
    echo   %MONGOD_EXE%
    echo.
    echo Install MongoDB Server, add mongod.exe to PATH, or set MONGOD_EXE before running this script.
    pause
    exit /b 1
)

if not exist "%MONGODB_DATA_DIR%" mkdir "%MONGODB_DATA_DIR%"
if not exist "%MONGODB_LOG_DIR%" mkdir "%MONGODB_LOG_DIR%"

tasklist /FI "IMAGENAME eq mongod.exe" | find /I "mongod.exe" >nul
if %errorlevel% equ 0 (
    echo MongoDB is already running.
    exit /b 0
)

echo Starting MongoDB on 127.0.0.1:27017...
start "AlertMesh MongoDB" /min "%MONGOD_EXE%" --dbpath "%MONGODB_DATA_DIR%" --logpath "%MONGODB_LOG_DIR%\mongod.log" --logappend --bind_ip 127.0.0.1 --port 27017
echo MongoDB start requested.
