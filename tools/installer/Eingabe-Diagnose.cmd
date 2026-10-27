@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo DIAGNOSE BEENDET: Diese Datei gehoert in den laufenden Testordner.
 pause
 exit /b 2
)
if not exist "S7-Eingabe-Diagnose\observe_input_pump.py" (
 echo DIAGNOSE BEENDET: CMD-Datei UND Ordner S7-Eingabe-Diagnose entpacken.
 pause
 exit /b 2
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Eingabe-Diagnose\observe_input_pump.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
