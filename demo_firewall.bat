@echo off
REM RRProxy Firewall Proxy Demo Script for Windows
REM This script demonstrates using RRProxy with a firewall proxy

echo RRProxy Firewall Proxy Demo
echo =============================

echo Building RRProxy...
cargo build --release

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo This demo shows how to use RRProxy with a firewall proxy.
echo.
echo Step 1: Starting Remote Proxy on port 8081...
start "Remote Proxy" cargo run --release -- remote --listen-addr 127.0.0.1:8081

timeout /t 2 /nobreak > nul

echo Step 2: Starting Local Proxy with firewall proxy support...
echo.
echo OPTION 1 - No firewall proxy (direct connection):
echo   cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081
echo.
echo OPTION 2 - With HTTP firewall proxy:
echo   cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --firewall-proxy http://proxy.company.com:8080
echo.
echo OPTION 3 - With SOCKS5 firewall proxy:
echo   cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --firewall-proxy socks5://proxy.company.com:1080
echo.
echo For this demo, we'll use OPTION 1 (no firewall proxy)
start "Local Proxy" cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --chunk-size 1024

timeout /t 2 /nobreak > nul

echo.
echo Proxies started!
echo - Local Proxy: http://127.0.0.1:8080 (receives client requests)
echo - Remote Proxy: http://127.0.0.1:8081 (forwards to target servers)
echo.
echo To use with a firewall proxy in your environment:
echo 1. Stop the local proxy
echo 2. Restart with: cargo run -- local --firewall-proxy http://your-proxy:port
echo.
echo Example test commands:
echo   curl -X GET http://127.0.0.1:8080/test
echo   curl -X POST http://127.0.0.1:8080/api/data -d "large data that will be chunked"
echo.
echo Architecture:
echo   Client -> Local Proxy -> [Firewall Proxy] -> Remote Proxy -> Target Server
echo.
echo Press any key to stop the demo...
pause > nul

echo Stopping proxies...
taskkill /F /FI "WINDOWTITLE eq Remote Proxy" 2>nul
taskkill /F /FI "WINDOWTITLE eq Local Proxy" 2>nul
echo Demo stopped.
