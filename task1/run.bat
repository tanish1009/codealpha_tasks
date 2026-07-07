@echo off
setlocal

net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    goto :eof
)

:run
cd /d "%~dp0"
python app.py
if errorlevel 1 (
    echo.
    echo Something went wrong while running the sniffer.
    echo Make sure the required packages are installed:
    echo     pip install PyQt5 scapy psutil
    echo Windows also requires Npcap ^(https://npcap.com^) to be installed.
    echo.
    pause
)

endlocal
