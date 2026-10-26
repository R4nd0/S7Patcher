@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo UPDATE ABGEBROCHEN: Diese Datei gehoert in den neuen installierten Testordner.
 pause
 exit /b 2
)
for %%F in (update_lan_transport_diagnostic.py update_join_menu.py compatibility.py bba.py prepare.py uplay_r1_loader.dll LICENSE.S7Packer.txt) do (
 if not exist "S7-Transport-Diagnose\%%F" (
  echo UPDATE ABGEBROCHEN: Das Update wurde nicht vollstaendig entpackt.
  echo Fehlende Datei: "%~dp0S7-Transport-Diagnose\%%F"
  echo CMD-Dateien UND den gesamten Ordner S7-Transport-Diagnose gemeinsam
  echo neben Test-LAN-Verbindung.cmd kopieren. Nicht aus der ZIP-Ansicht starten.
  pause
  exit /b 2
 )
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Transport-Diagnose\update_lan_transport_diagnostic.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
