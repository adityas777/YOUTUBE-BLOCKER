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

echo [System] Creating Scheduled Task to run Hybrid Ad-Blocker at startup...
schtasks /create /tn "HybridAdBlocker" /tr "powershell.exe -WindowStyle Hidden -Command %~sdp0run_blocker.bat" /sc onlogon /rl HIGHEST /f

if %errorLevel%==0 (
    echo [System] Task created successfully!
    echo [System] Starting the background services now...
    schtasks /run /tn "HybridAdBlocker"
    echo [System] Started! The ad blocker and dashboard are now running permanently in the background.
    echo          Open http://127.0.0.1:5000 in your browser.
) else (
    echo [Error] Failed to create scheduled task.
)
pause
