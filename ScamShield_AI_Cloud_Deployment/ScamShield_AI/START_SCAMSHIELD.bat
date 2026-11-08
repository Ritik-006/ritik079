@echo off
setlocal
cd /d "%~dp0"
title ScamShield AI
if not exist ".venv\Scripts\python.exe" (
  echo First-time setup has not been completed.
  echo Starting SETUP_ONCE.bat...
  call "%~dp0SETUP_ONCE.bat"
  if errorlevel 1 exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo ERROR: Project Python environment was not created.
  pause
  exit /b 1
)
echo Starting ScamShield AI...
echo Keep this window open while using the app.
start "" /min cmd /c "timeout /t 3 /nobreak ^>nul ^& start "" http://127.0.0.1:5000"
".venv\Scripts\python.exe" app.py
echo.
echo ScamShield AI has stopped.
pause
