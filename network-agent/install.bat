@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
echo.
echo  ===== NetAgent: installation =====
echo.

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo  [X] Python not found.
  echo      Install Python 3.12 from https://www.python.org/downloads/
  echo      IMPORTANT: tick "Add python.exe to PATH" in the installer, then run install.bat again.
  echo.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo  Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo  [X] Could not create the virtual environment.
    pause
    exit /b 1
  )
)

echo  Installing libraries (first time takes a few minutes)...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo  [X] Library installation failed. Copy the error above and send it to Claude.
  pause
  exit /b 1
)

if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo  Created .env
)
if not exist "inventory\devices.yaml" (
  copy "inventory\devices.example.yaml" "inventory\devices.yaml" >nul
  echo  Created inventory\devices.yaml
)

echo.
echo  ===== Installed. Checking the setup... =====
".venv\Scripts\python.exe" -m netagent doctor --offline

echo.
echo  Next steps:
echo    1. notepad .env                    (API key, passwords)
echo    2. notepad inventory\devices.yaml  (your devices)
echo    3. setup-password.bat              (app password + 2FA)
echo    4. start.bat                       (start NetAgent)
echo.
pause
