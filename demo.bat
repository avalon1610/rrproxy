@echo off
REM RRProxy Demo Script for Windows
REM This script shows how to start both proxies and test them

echo RRProxy Demo Script
echo ==================

echo Building RRProxy...
cargo build --release

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo Starting Remote Proxy on port 8081...
start "Remote Proxy" cargo run --release -- remote --listen-addr 127.0.0.1:8081

timeout /t 2 /nobreak > nul

echo Starting Local Proxy on port 8080...
start "Local Proxy" cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --chunk-size 1024

timeout /t 2 /nobreak > nul

echo.
echo Proxies started!
echo - Local Proxy: http://127.0.0.1:8080
echo - Remote Proxy: http://127.0.0.1:8081
echo.
echo You can now test the proxy by sending requests to http://127.0.0.1:8080
echo.
echo Example commands:
echo   curl -X GET http://127.0.0.1:8080/test
echo   curl -X POST http://127.0.0.1:8080/api/data -d "test data"
echo.
echo Press any key to stop the demo...
pause > nul

echo Stopping proxies...
taskkill /F /FI "WINDOWTITLE eq Remote Proxy" 2>nul
taskkill /F /FI "WINDOWTITLE eq Local Proxy" 2>nul
echo Demo stopped.
