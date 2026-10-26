@echo off
setlocal
cd /d "%~dp0"
if not exist "Runtime\python\python.exe" (
 echo UPDATE ABGEBROCHEN: Dieser Ordner ist nicht der installierte Testordner.
 echo Bitte den gesamten ZIP-Inhalt neben Test-LAN-Verbindung.cmd entpacken.
 pause
 exit /b 2
)
for %%F in (update_gateway_sentinel.py update_join_menu.py compatibility.py bba.py prepare.py S7Patcher.dll LICENSE.S7Packer.txt) do (
 if not exist "S7-Gateway-Update\%%F" (
  echo UPDATE ABGEBROCHEN: Das Update wurde nicht vollstaendig entpackt.
  echo Fehlende Datei: "%~dp0S7-Gateway-Update\%%F"
  echo Die CMD-Datei UND den Ordner S7-Gateway-Update aus dem ZIP
  echo gemeinsam in diesen Testordner kopieren. Unterordner beibehalten.
  echo Keine Datei direkt aus der ZIP-Ansicht starten.
  pause
  exit /b 2
 )
)
"%~dp0Runtime\python\python.exe" -B "%~dp0S7-Gateway-Update\update_gateway_sentinel.py" --bundle "%~dp0."
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
