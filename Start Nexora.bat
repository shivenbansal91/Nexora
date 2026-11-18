@echo off
setlocal
title Nexora - Local Server
cd /d "%~dp0"
if errorlevel 1 goto failed

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" start_nexora.py
    goto result
)
python --version >nul 2>&1
if not errorlevel 1 (
    python start_nexora.py
    goto result
)
py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 start_nexora.py
    goto result
)
echo Python was not found. Install Python and the dependencies in requirements.txt.
goto failed

:result
if errorlevel 1 goto failed
exit /b 0

:failed
echo.
echo Nexora could not start. See the error above.
pause
exit /b 1
