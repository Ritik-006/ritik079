@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'ScamShield AI.lnk')); $s.TargetPath=(Join-Path '%~dp0' 'START_SCAMSHIELD.bat'); $s.WorkingDirectory='%~dp0'; $s.Description='Start ScamShield AI'; $s.Save()"
if errorlevel 1 (
  echo Could not create shortcut automatically.
) else (
  echo Desktop shortcut created: ScamShield AI
)
pause
