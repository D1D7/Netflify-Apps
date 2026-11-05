@echo off
setlocal
cd /d "%~dp0"
echo.
echo  Making a ZIP to share NetAgent (code only, no passwords or private data)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0share.ps1"
echo.
pause
