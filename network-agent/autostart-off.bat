@echo off
setlocal
cd /d "%~dp0"
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
if exist "%STARTUP%\NetAgent.vbs" del "%STARTUP%\NetAgent.vbs"
if not exist logs mkdir logs
echo stop> logs\stop.flag
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*netagent serve*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
echo.
echo  Autostart removed and the background NetAgent stopped.
echo  To run it manually: start.bat
echo.
pause
