@echo off
setlocal
cd /d "%~dp0"
rem Brug projektets virtuelle miljoe, naar det findes.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" "ping_gui.py"
) else (
    python "ping_gui.py"
)
if errorlevel 1 (
    echo.
    echo Kontroller Python, Tkinter, Scapy og Npcap.
    echo Proev at hoejreklikke denne fil og vaelge Koer som administrator.
    pause
)
endlocal
