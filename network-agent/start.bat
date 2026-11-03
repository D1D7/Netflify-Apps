@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
if not exist ".venv\Scripts\python.exe" (
  echo  [X] Run install.bat first.
  pause
  exit /b 1
)
echo.
echo  ===== NetAgent is starting =====
echo  App:  http://127.0.0.1:8080   (phone: your Tailscale address)
echo  Stop: close this window or press Ctrl+C
echo.
".venv\Scripts\python.exe" -m netagent serve
echo.
echo  NetAgent stopped.
pause
