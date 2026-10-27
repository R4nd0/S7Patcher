@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo UPDATE ABGEBROCHEN: Diese Datei gehoert in den vorhandenen S7-Testordner.
 pause
 exit /b 2
)
if not exist "S7-Befehlsvorlauf-Update\update_turn_offset.py" (
 echo UPDATE ABGEBROCHEN: CMD-Dateien UND den kompletten Ordner S7-Befehlsvorlauf-Update entpacken.
 pause
 exit /b 2
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Befehlsvorlauf-Update\update_turn_offset.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
