@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo Diese Datei gehoert neben Test-LAN-Verbindung.cmd in den vorhandenen Testordner.
 pause
 exit /b 2
)
if not exist "S7-Verbindungsbericht\connection_report.py" (
 echo CMD-Datei UND den kompletten Ordner S7-Verbindungsbericht gemeinsam entpacken.
 pause
 exit /b 2
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Verbindungsbericht\connection_report.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
