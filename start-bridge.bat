@echo off
title Claude Local Bridge
echo ============================================
echo   Claude Local Bridge - Starting...
echo ============================================
echo.

:: Ensure Tailscale is connected
echo [1/2] Checking Tailscale...
"%ProgramFiles%\Tailscale\tailscale.exe" status >nul 2>&1
if errorlevel 1 (
    echo      Tailscale not connected. Starting login...
    "%ProgramFiles%\Tailscale\tailscale.exe" login
    timeout /t 5 /nobreak >nul
)
for /f "tokens=*" %%i in ('"%ProgramFiles%\Tailscale\tailscale.exe" ip -4 2^>nul') do set TSIP=%%i
echo      Tailscale IP: %TSIP%
echo      MCP Endpoint: http://%TSIP%:9120/mcp/sse
echo      Dashboard:    http://%TSIP%:9120/
echo.

:: Start the bridge server
echo [2/2] Starting bridge server...
echo.

cd /d J:\claude-local-bridge
python -m app.main ^
  --roots ^
  "J:\claude wow addon trials" ^
  "J:\claude-local-bridge" ^
  "J:\clawbot search" ^
  "J:\hue projects" ^
  "J:\kalshi-weather-trader" ^
  "J:\political news app" ^
  "J:\QBO FOSS alternative" ^
  "J:\wow macros interface and tweaks" ^
  "J:\distcc for claw project" ^
  "J:\latchpac test suite buildout" ^
  "J:\openclaw model load optimizer" ^
  --host 0.0.0.0 ^
  --port 9120

pause
