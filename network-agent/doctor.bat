@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
if not exist ".venv\Scripts\python.exe" (
  echo  [X] Run install.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m netagent doctor
echo.
pause
