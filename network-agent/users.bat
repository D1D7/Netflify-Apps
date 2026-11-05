@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
chcp 65001 >nul
if not exist ".venv\Scripts\python.exe" (
  echo  [X] Run install.bat first.
  pause
  exit /b 1
)
:menu
echo.
echo  ===== NetAgent users =====
".venv\Scripts\python.exe" -m netagent user-list
echo.
echo   1 = add a view-only user (sees everything, changes nothing)
echo   2 = add an admin user
echo   3 = delete a user
echo   4 = exit
set "choice="
set /p choice= Choose 1-4: 
if "%choice%"=="1" goto add_viewer
if "%choice%"=="2" goto add_admin
if "%choice%"=="3" goto del
goto end
:add_viewer
set "uname="
set /p uname= User name (latin letters, e.g. gio): 
if not "%uname%"=="" ".venv\Scripts\python.exe" -m netagent user-add "%uname%" --role viewer
goto menu
:add_admin
set "uname="
set /p uname= User name (latin letters, e.g. gio): 
if not "%uname%"=="" ".venv\Scripts\python.exe" -m netagent user-add "%uname%" --role admin
goto menu
:del
set "uname="
set /p uname= User name to delete: 
if not "%uname%"=="" ".venv\Scripts\python.exe" -m netagent user-del "%uname%"
goto menu
:end
endlocal
