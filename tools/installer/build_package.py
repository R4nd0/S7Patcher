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
ADAPTER_SHA256 = '17d86b1ebfe670a838ff89dbdddd8e477ef1abc128001eb301268930c9c3ed09'
ARCHIVE_SHA256 = 'ebee0ff593cdb9c38442d03875041f8c1825c0fc3e2414291098e08f3517ced5'


def build(adapter, service, dotnet, python_zip, output):
    adapter, service, dotnet, python_zip, output = map(content.plain, (adapter, service, dotnet, python_zip, output))
    repo = Path(__file__).resolve().parents[2]
    if output.exists() or not output.parent.is_dir():
        raise ValueError('Output must be a new directory with an existing parent')
    if any(output.is_relative_to(p) or p.is_relative_to(output) for p in (repo, service, dotnet, python_zip.parent, adapter.parent)):
        raise ValueError('Output overlaps package inputs')
    if content.digest(adapter) != ADAPTER_SHA256 or content.digest(python_zip) != PYTHON_SHA256:
        raise ValueError('Adapter or Python distribution fingerprint mismatch')
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
    names = ['installer/install.py', 'installer/start.py', 'installer/compatibility.py',
             'offline-ui/launch_local.py', 'offline-ui/patch-spec.json', 'lan/bba.py', 'lan/prepare.py']
    for name in names:
        target = output / 'Tools' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / 'tools' / name, target)
    shutil.copyfile(repo / 'LICENSE', output / 'Tools/LICENSE.txt')
    write_json(output / 'package.json', {'format': FORMAT,
        'capabilities': {'local_test': True, 'lan_host': False, 'lan_join': False},
        'patched_archive_sha256': ARCHIVE_SHA256,
        'files': content.inventory(output, ('Payload', 'Runtime', 'Tools'))})
    (output / 'Installieren.cmd').write_text('@echo off\n"%~dp0Runtime\\python\\python.exe" -B "%~dp0Tools\\installer\\install.py" --package "%~dp0."\npause\n', encoding='ascii')
    (output / 'LIESMICH.txt').write_text(
        'S7 Patch-Installer: Vorbereitungsversion\n\n'
        'Paket vollstaendig entpacken und Installieren.cmd starten.\n'
        'Den eigenen S7-History-Installationsordner und einen neuen Testordner eingeben.\n'
        'Eine separate Kopie benoetigt etwa 7 GB freien Speicher. Das Original bleibt erhalten.\n'
        'Python und .NET sind enthalten; keine Systeminstallation oder Administratorrechte erforderlich.\n\n'
        'Enthalten: Entwicklungsmodus, bekannte Zusatzinhalte, volle Kampagnenauswahl, maximal vier physische CPU-Kerne ohne SMT.\n'
        'Kampagnenauswahl und CPU-Zuordnung sind im Spiel bestaetigt; weitere Belohnungen noch nicht vollstaendig geprueft.\n'
        'Diese Version bereitet lokale Tests vor. Beitritt und Hosting zwischen PCs sind noch nicht freigegeben.\n'
        'Das gleiche Paket ist fuer beide PCs vorgesehen. Lokale Spielerkennungen entstehen auf jedem PC neu.\n'
        'Nur dieses Paket weitergeben, niemals die vorbereitete Spielkopie oder LocalData.\n'
        'Dateistand-pruefen.cmd prueft die vorbereitete Kopie; compatibility.json enthaelt nur Dateinamen und Pruefsummen.\n'
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
