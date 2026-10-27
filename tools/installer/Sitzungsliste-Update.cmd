@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo UPDATE ABGEBROCHEN: Diese Datei gehoert in den aktualisierten Testordner.
 pause
 exit /b 2
)
for %%F in (update_lan_catalogue_routes.py update_join_menu.py compatibility.py bba.py prepare.py S7Patcher.dll LICENSE.S7Packer.txt) do (
 if not exist "S7-Sitzungsliste-Update\%%F" (
  echo UPDATE ABGEBROCHEN: Das Update wurde nicht vollstaendig entpackt.
  echo Fehlende Datei: "%~dp0S7-Sitzungsliste-Update\%%F"
  echo Die CMD-Datei UND den gesamten Ordner S7-Sitzungsliste-Update
  echo neben Test-LAN-Verbindung.cmd kopieren. Nicht aus der ZIP-Ansicht starten.
  pause
  exit /b 2
 )
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Sitzungsliste-Update\update_lan_catalogue_routes.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
