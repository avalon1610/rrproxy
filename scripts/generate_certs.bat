@echo off
REM Certificate Generation Script for RRProxy (Windows Batch)
REM This script generates self-signed certificates for HTTPS proxy functionality

setlocal enabledelayedexpansion

echo 🔐 Generating certificates for RRProxy...
echo.

REM Determine output path
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "OUTPUT_PATH=%PROJECT_ROOT%"

echo 📁 Project root: %PROJECT_ROOT%
echo 📁 Certificates will be saved to: %OUTPUT_PATH%
echo.

REM Check if PowerShell is available (it should be on Windows 7+)
powershell -Command "Get-Host" >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ PowerShell not available. Please run the PowerShell script instead:
    echo    scripts\generate_certs.ps1
    echo.
    pause
    exit /b 1
)

echo ✅ Found PowerShell, delegating to PowerShell script...
echo.

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%generate_certs.ps1" -OutputPath "%OUTPUT_PATH%"

if %errorlevel% neq 0 (
    echo.
    echo ❌ Certificate generation failed.
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ Certificate generation completed successfully!
echo.
pause
