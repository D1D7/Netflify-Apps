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
:run
".venv\Scripts\python.exe" -m netagent serve
if "%errorlevel%"=="75" (
  echo  Restarting after update...
  timeout /t 3 /nobreak >nul
  goto run
)
echo.
echo  NetAgent stopped.
pause
