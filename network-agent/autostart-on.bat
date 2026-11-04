@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo  [X] Run install.bat first.
  pause
  exit /b 1
)
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
echo CreateObject("WScript.Shell").Run "wscript.exe ""%~dp0netagent-background.vbs""", 0, False> "%STARTUP%\NetAgent.vbs"
if errorlevel 1 (
  echo  [X] Could not add NetAgent to Startup.
  pause
  exit /b 1
)
echo.
echo  NetAgent will now start automatically (in the background) when you log in to Windows.
echo  Starting it now...
start "" wscript.exe "%~dp0netagent-background.vbs"
echo.
echo  App:   http://127.0.0.1:8080
echo  Logs:  logs\netagent.log
echo  Stop / remove autostart:  autostart-off.bat
echo.
pause
