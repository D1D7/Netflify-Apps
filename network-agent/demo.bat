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
echo  ===== NetAgent DEMO (simulated network) =====
echo  App:      http://127.0.0.1:8090
echo  Password: netagent-demo
echo  Your real settings and devices are not touched.
echo  Stop: close this window or press Ctrl+C
echo.
start "" cmd /c "timeout /t 8 >/dev/null & start http://127.0.0.1:8090"
".venv\Scripts\python.exe" -m netagent.demo
echo.
echo  Demo stopped.
pause
