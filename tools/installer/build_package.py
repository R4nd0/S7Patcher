"""Build an offline Windows x64 preparation package, without any game data.

Requires a tested adapter/service, a local .NET 10 runtime and the pinned official
CPython embeddable ZIP. All runtime licenses are included. No downloads here.
"""
import argparse
import json
from pathlib import Path
import shutil
import zipfile

import compatibility as content
from install import write_json, FORMAT

PYTHON_SHA256 = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
ADAPTER_SHA256 = 'a59def58f827508d06c95e2787762681f19da4f74390cf205b19f500eaa60b1e'
SERVICE_SHA256 = 'a4e300b091e289175f4866f82303b78e05b77aa82cffe958324b6c591d622914'
ARCHIVE_SHA256 = '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'


def build(adapter, service, dotnet, python_zip, output):
    adapter, service, dotnet, python_zip, output = map(content.plain, (adapter, service, dotnet, python_zip, output))
    repo = Path(__file__).resolve().parents[2]
    if output.exists() or not output.parent.is_dir():
        raise ValueError('Output must be a new directory with an existing parent')
    if any(output.is_relative_to(p) or p.is_relative_to(output) for p in (repo, service, dotnet, python_zip.parent, adapter.parent)):
        raise ValueError('Output overlaps package inputs')
    if content.digest(adapter) != ADAPTER_SHA256 or content.digest(python_zip) != PYTHON_SHA256:
        raise ValueError('Adapter or Python distribution fingerprint mismatch')
    if content.digest(service / 'S7Patcher.dll') != SERVICE_SHA256:
        raise ValueError('Service fingerprint does not match the tested LAN build')
    version = '10.0.13'
    for path in (dotnet / 'dotnet.exe', dotnet / 'host/fxr' / version / 'hostfxr.dll',
                 dotnet / 'shared/Microsoft.NETCore.App' / version / 'System.Private.CoreLib.dll'):
        if not path.is_file(): raise ValueError('Expected tested .NET runtime is absent')
    with zipfile.ZipFile(python_zip) as archive:
        for item in archive.infolist():
            # Official archive is flat. Refuse paths/links rather than trusting ZIP extraction.
            if '/' in item.filename or '\\' in item.filename or ':' in item.filename or item.filename in ('.', '..'):
                raise ValueError('Unexpected Python ZIP path')
        output.mkdir()
        runtime = output / 'Runtime/python'; runtime.mkdir(parents=True)
        archive.extractall(runtime)
    net = output / 'Runtime/dotnet'; net.mkdir()
    for name in ('dotnet.exe', 'LICENSE.txt', 'ThirdPartyNotices.txt'):
        shutil.copyfile(dotnet / name, net / name)
    for relative in ('host/fxr/' + version, 'shared/Microsoft.NETCore.App/' + version):
        shutil.copytree(dotnet / relative, net / relative)
    server = output / 'Payload/Server'; server.mkdir(parents=True)
    for name in ('S7Patcher.dll', 'S7Patcher.deps.json', 'S7Patcher.runtimeconfig.json'):
        shutil.copyfile(service / name, server / name)
    shutil.copyfile(adapter, output / 'Payload/uplay_r1_loader.dll')
    names = ['installer/install.py', 'installer/start.py', 'installer/launch_lan.py', 'installer/compatibility.py',
             'offline-ui/launch_local.py', 'offline-ui/patch-spec.json', 'lan/bba.py', 'lan/prepare.py',
             'installer/update_join_menu.py', 'offline-ui/join-menu-update.json']
    for name in names:
        target = output / 'Tools' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / 'tools' / name, target)
    shutil.copyfile(repo / 'LICENSE', output / 'Tools/LICENSE.txt')
    write_json(output / 'package.json', {'format': FORMAT,
        'capabilities': {'local_test': True, 'lan_host': False, 'lan_join': False},
        'join_menu_update': True,
        'patched_archive_sha256': ARCHIVE_SHA256,
        'files': content.inventory(output, ('Payload', 'Runtime', 'Tools'))})
    (output / 'Installieren.cmd').write_text('@echo off\n"%~dp0Runtime\\python\\python.exe" -B "%~dp0Tools\\installer\\install.py" --package "%~dp0."\npause\n', encoding='ascii')
    (output / 'LIESMICH.txt').write_text(
        'S7 LAN-Testpaket v3: vollstaendige Installation\n\n'
        'Paket vollstaendig entpacken und Installieren.cmd starten.\n'
        'Den eigenen S7-History-Installationsordner und einen neuen Testordner eingeben.\n'
        'Den Ziel-Unterordner vorher nicht anlegen. Alle bisherigen Korrekturen sind enthalten.\n'
        'Eine separate Kopie benoetigt etwa 7 GB freien Speicher. Das Original bleibt erhalten.\n'
        'Python und .NET sind enthalten; keine Systeminstallation oder Administratorrechte erforderlich.\n\n'
        'Enthalten: Entwicklungsmodus, bekannte Zusatzinhalte, volle Kampagnenauswahl, maximal vier physische CPU-Kerne ohne SMT.\n'
        'Kampagnenauswahl und CPU-Zuordnung sind im Spiel bestaetigt; weitere Belohnungen noch nicht vollstaendig geprueft.\n'
        'Dies ist die getestete LAN-Version fuer weitere Spieltests, noch keine stabile Freigabe.\n'
        'Das gleiche Paket ist fuer beide PCs vorgesehen. Lokale Spielerkennungen entstehen auf jedem PC neu.\n'
        'Nur dieses Paket weitergeben, niemals die vorbereitete Spielkopie oder LocalData.\n'
        'Dateistand-pruefen.cmd prueft die vorbereitete Kopie; compatibility.json enthaelt nur Dateinamen und Pruefsummen.\n'
        'Test-LAN-Verbindung.cmd verbindet zwei explizit angegebene PCs fuer den Sitzungstest.\n'
        'Zuerst Host starten, danach den Mitspieler. Auf beiden PCs dieselbe Paketversion verwenden.\n'
        'TCP 9110 und UDP 9111 muessen am Host fuer den anderen PC erreichbar sein.\n'
        'Host: Auswahl 1, eigene IPv4-Adresse und die Adresse des Mitspielers eingeben.\n'
        'Mitspieler: Auswahl 2, eigene IPv4-Adresse und die Adresse des Hosts eingeben.\n'
        'Eine oeffentliche Lobby mit freiem Platz erstellen; der Mitspieler waehlt sie aus und tritt bei.\n'
        'Das Starterfenster waehrend des Spielens geoeffnet lassen.\n'
        'Beitritt und gemeinsamer Partiestart sind mit zwei getrennten PCs im LAN bestaetigt.\n'
        'Bekanntes Problem: Befehle des Mitspielers werden derzeit etwa 30 Sekunden verzoegert wirksam.\n'
        'Im LAN-Test trat ausserdem ein Verbindungsabbruch auf; seine Ursache ist noch offen.\n'
        'Hostrichtungswechsel und laengere Partien zwischen getrennten PCs werden noch geprueft.\n'
        'Der LAN-Dienst endet mit dem Hostspiel, spaetestens nach 24 Stunden.\n'
        'Gleiche Dateien verhindern nicht alle Synchronisationsfehler der Spielsimulation.\n', encoding='utf-8')
    (output / 'RUNTIME-SOURCES.txt').write_text(
        'CPython 3.14.10 Windows embeddable x64\n'
        'https://www.python.org/downloads/release/python-31410/\n'
        'https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip\nSHA256 ' + PYTHON_SHA256 + '\n'
        'License: Runtime/python/LICENSE.txt\n\n'
        '.NET 10.0.13 Windows x64 runtime from the development SDK runtime.\n'
        'Licenses: Runtime/dotnet/LICENSE.txt and ThirdPartyNotices.txt\n', encoding='utf-8')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('adapter', 'service', 'dotnet', 'python-zip', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(build(args.adapter, args.service, args.dotnet, args.python_zip, args.output))
