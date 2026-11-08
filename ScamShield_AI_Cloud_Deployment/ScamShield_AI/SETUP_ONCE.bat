@echo off
setlocal
cd /d "%~dp0"
title ScamShield AI - First-time setup
echo ==========================================
echo       ScamShield AI - First-time setup
echo ==========================================
echo.
where py >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python Launcher (py) was not found.
  echo Install Python 3.11 or newer from python.org and enable the Python Launcher.
  echo Then run SETUP_ONCE.bat again.
  pause
  exit /b 1
)
py -3 --version
if errorlevel 1 (
  echo ERROR: Python 3 could not be started.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating the private project environment...
  py -3 -m venv .venv
  if errorlevel 1 goto failed
)
echo.
echo Updating pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto failed
echo.
echo Installing ScamShield AI packages. This may take several minutes.
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo.
echo Setup completed successfully.
echo Next time, double-click START_SCAMSHIELD.bat
pause
exit /b 0
:failed
echo.
echo SETUP FAILED. Check your internet connection and the error above.
echo If an error mentions Qiskit Aer or Python 3.13 compatibility,
echo send a photo of the complete error message.
pause
exit /b 1
