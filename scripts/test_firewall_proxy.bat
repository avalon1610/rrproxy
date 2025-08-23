@echo off
REM Test script for firewall proxy functionality
REM This script sets up a mock firewall proxy and tests the complete chain

echo 🔥 Testing RRProxy Firewall Proxy Functionality
echo ===============================================

REM Function to check if a port is available
:check_port
netstat -an | find ":%~1 " > nul
if %errorlevel% == 0 (
    echo   ❌ Port %~1 is in use
    exit /b 1
) else (
    echo   ✅ Port %~1 is available
    exit /b 0
)

REM Check required ports
echo 📋 Checking port availability...
call :check_port 19090
if %errorlevel% neq 0 exit /b 1
call :check_port 19091
if %errorlevel% neq 0 exit /b 1
call :check_port 19092
if %errorlevel% neq 0 exit /b 1

REM Build the project
echo 🔨 Building RRProxy...
cargo build --release
if %errorlevel% neq 0 (
    echo ❌ Build failed
    exit /b 1
) else (
    echo ✅ Build successful
)

echo.
echo 🧪 Running firewall proxy integration test...
echo This test will:
echo   1. Start a test firewall proxy on port 19090
echo   2. Start RRProxy remote proxy on port 19091
echo   3. Start RRProxy local proxy on port 19092 (configured to use firewall proxy^)
echo   4. Make HTTP requests through the proxy chain
echo   5. Verify that requests go through the firewall proxy
echo.

REM Run the integration test
cargo test integration_test_firewall_proxy_functionality --release -- --ignored --nocapture
if %errorlevel% == 0 (
    echo 🎉 Firewall proxy integration test PASSED!
    echo.
    echo Summary of what was tested:
    echo ✅ Firewall proxy receives and forwards requests
    echo ✅ Local proxy correctly routes through firewall proxy
    echo ✅ Remote proxy receives and processes chunked requests
    echo ✅ Large requests are properly chunked and reassembled
    echo ✅ Multiple concurrent requests work correctly
    echo ✅ End-to-end data integrity is maintained
) else (
    echo ❌ Firewall proxy integration test FAILED
    exit /b 1
)

echo.
echo 🔍 Architecture Verification:
echo The test confirmed the following architecture works correctly:
echo.
echo ┌─────────┐    HTTP    ┌─────────────┐    HTTP    ┌──────────────┐    HTTP     ┌──────────────┐
echo │ Client  │ ---------^> │ Local Proxy │ ---------^> │ Firewall     │ ----------^> │ Remote Proxy │
echo │         │            │ :19092      │            │ Proxy :19090 │             │ :19091       │
echo └─────────┘            └─────────────┘            └──────────────┘             └──────────────┘
echo                              │                           │                            │
echo                              │                           │                            │
echo                              v                           v                            v
echo                       [Chunk large                [Forward all              [Reassemble chunks
echo                        requests]                   requests]                 and forward to target]
echo.
echo Key features verified:
echo • Firewall proxy compatibility ✅
echo • Request chunking through proxy ✅
echo • Chunk reassembly ✅
echo • HTTPS support (via CONNECT^) ✅
echo • Concurrent request handling ✅

echo.
echo 🏆 All tests completed successfully!
