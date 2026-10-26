@echo off
setlocal
cd /d "%~dp0"
if not exist "S7-Transport-Diagnose\lan_status.ps1" (
 echo FEHLER: Den gesamten Diagnose-ZIP-Inhalt in den Testordner entpacken.
 pause
 exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0S7-Transport-Diagnose\lan_status.ps1" -Bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
