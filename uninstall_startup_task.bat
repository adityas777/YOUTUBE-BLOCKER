@echo off
:: Ensure script is running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ==========================================================
    echo [Error] Please run this batch file as Administrator!
    echo         Right-click -> Run as administrator
    echo ==========================================================
    pause
    exit /b 1
)

echo [System] Stopping and deleting Scheduled Task "HybridAdBlocker"...
schtasks /delete /tn "HybridAdBlocker" /f

echo [System] Killing active background Python and Live DPI processes...
taskkill /f /im python.exe /fi "COMMANDLINE eq *dns_server.py*" 2>nul
taskkill /f /im python.exe /fi "COMMANDLINE eq *dashboard.py*" 2>nul
taskkill /f /im python.exe /fi "COMMANDLINE eq *block_ads.py*" 2>nul
taskkill /f /im live_dpi.exe 2>nul

echo [System] Restoring network adapter DNS settings...
python dns_server.py --restore-only

echo [System] Background services stopped and uninstalled successfully.
pause
