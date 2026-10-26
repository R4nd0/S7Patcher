"""Prepare an independent S7 test copy using the recipient's own game files.

Offline preparation only. No game launch, firewall rule, account access or
working-LAN claim. Failed copies retain INSTALLATION-INCOMPLETE.txt and no
starter. Existing output is never overwritten or automatically deleted.
"""
import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compatibility as content

FORMAT = 's7-patch-package-v1'
EXPECTED_EXE = '4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f'
EXPECTED_ARCHIVE = '766ae21ef06709309a68fb5bb792b0fd56373c668f02140122eef181917b0b94'


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def package_manifest(root):
    root = content.plain(root)
    manifest_path = content.plain(root / 'package.json')
    if manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Installationsmanifest zu gross.')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (manifest.get('format') != FORMAT or manifest.get('capabilities') != {'local_test': True, 'lan_host': False, 'lan_join': False}
            or not isinstance(manifest.get('files'), dict) or not manifest['files']):
        raise ValueError('Unbekanntes Installationspaket.')
    actual = content.inventory(root, ('Payload', 'Runtime', 'Tools'))
    expected = manifest['files']
    if actual != expected:
        raise ValueError('Das Installationspaket ist unvollstaendig oder veraendert.')
    return manifest


def source_base(root):
    root = content.plain(root)
    bases = [root / name for name in ('Base', 'Data/Base') if (root / name / 'Bin/Settlers7R.exe').is_file()]
    if len(bases) != 1:
        raise ValueError('Bitte den S7-Installationsordner mit genau einem Base-Ordner auswaehlen.')
    base = content.plain(bases[0])
    exe = content.plain(base / 'Bin/Settlers7R.exe')
    archive = content.plain(base / 'BBA/Interface.bba')
    if content.digest(exe) != EXPECTED_EXE or content.digest(archive) != EXPECTED_ARCHIVE:
        raise ValueError('Diese Spielversion ist veraendert oder wird noch nicht unterstuetzt.')
    return base


def prepare(package, source, destination, emit=print):
    package, source, destination = map(content.plain, (package, source, destination))
    for protected in (source, package):
        if destination.is_relative_to(protected) or protected.is_relative_to(destination):
            raise ValueError('Der neue Testordner muss getrennt von Spiel und Installer liegen.')
    if destination.exists() or not destination.parent.is_dir():
        raise ValueError('Bitte einen neuen Testordner in einem vorhandenen Ordner angeben.')
    manifest = package_manifest(package)
    base = source_base(source)
    emit('Pruefe die Spieldateien. Das kann etwas dauern ...')
    # Validate every source path before creating output; no links/hardlinks used.
    files = []
    stack = [base]
    while stack:
        for path in sorted(stack.pop().iterdir()):
            content.plain(path)
            if path.is_dir(): stack.append(path)
            elif path.is_file(): files.append(path)
            else: raise ValueError('Unbekannter Dateityp in der Spielinstallation.')
    required = sum(p.stat().st_size for p in files) + sum(p.stat().st_size for p in package.rglob('*') if p.is_file()) + 512 * 1024 * 1024
    if shutil.disk_usage(destination.parent).free < required:
        raise ValueError('Nicht genug freier Speicher fuer eine unabhaengige Testkopie.')
    destination.mkdir()
    incomplete = destination / 'INSTALLATION-INCOMPLETE.txt'
    incomplete.write_text('Vorbereitung nicht abgeschlossen. Diesen Ordner nicht starten.\n', encoding='utf-8')
    for index, path in enumerate(files, 1):
        content.plain(path)
        target = destination / 'Base' / path.relative_to(base)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Copy bytes (not hard links) and verify against the still-present source.
        with path.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
        if content.digest(target) != content.digest(path):
            raise ValueError('Spieldatei hat sich waehrend des Kopierens geaendert.')
        emit(f'Spieldateien kopiert: {index}/{len(files)}')
    # Reuse the existing hash-locked patcher; patch the copied archive only.
    tools = package / 'Tools'
    sys.path.insert(0, str(tools / 'lan'))
    spec = importlib.util.spec_from_file_location('s7_installer_archive', tools / 'lan/prepare.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    stage = destination / 'ArchiveStage'
    # Archive preparation requires an output outside the input root. Use original
    # source, with a new staging directory inside this separate destination.
    module.prepare(source, stage, tools / 'offline-ui/patch-spec.json', profile='offline-ui')
    staged = stage / base.relative_to(source) / 'BBA/Interface.bba'
    shutil.copyfile(staged, destination / 'Base/BBA/Interface.bba')
    if content.digest(destination / 'Base/BBA/Interface.bba') != manifest['patched_archive_sha256']:
        raise ValueError('Der vorbereitete Menuepatch stimmt nicht mit dem Paket ueberein.')
    shutil.copyfile(package / 'Payload/uplay_r1_loader.dll', destination / 'Base/Bin/uplay_r1_loader.dll')
    shutil.copytree(package / 'Payload/Server', destination / 'Server')
    shutil.copytree(package / 'Runtime', destination / 'Runtime')
    (destination / 'Launcher').mkdir()
    for original, target in [('offline-ui/launch_local.py', 'launch_local.py'), ('installer/compatibility.py', 'compatibility.py')]:
        shutil.copyfile(tools / original, destination / 'Launcher' / target)
    shutil.copyfile(tools / 'installer/start.py', destination / 'Launcher/start.py')
    shutil.copyfile(tools / 'LICENSE.txt', destination / 'Launcher/LICENSE.txt')
    bundle = {'format': 's7-local-experimental-v1', 'runtime_verified': False, 'lan_verified': False,
              'files': {name: content.digest(destination / name) for name in
                        ('Base/Bin/Settlers7R.exe', 'Base/Bin/uplay_r1_loader.dll', 'Base/BBA/Interface.bba')}}
    if bundle['files']['Base/Bin/Settlers7R.exe'] != EXPECTED_EXE:
        raise ValueError('Spielprogramm hat sich waehrend der Vorbereitung geaendert.')
    # Detect modified payloads during copying, before publishing any starter.
    package_manifest(package)
    if content.digest(destination / 'Base/Bin/uplay_r1_loader.dll') != manifest['files']['payload/uplay_r1_loader.dll']:
        raise ValueError('Adapterkopie stimmt nicht ueberein.')
    for folder in ('Server',):
        if content.inventory(destination, (folder,)) != content.inventory(package / 'Payload', (folder,)):
            raise ValueError('Dienstkopie stimmt nicht ueberein.')
    if content.inventory(destination, ('Runtime',)) != content.inventory(package, ('Runtime',)):
        raise ValueError('Laufzeitkopie stimmt nicht ueberein.')
    for original, target in [('offline-ui/launch_local.py', 'launch_local.py'),
                             ('installer/compatibility.py', 'compatibility.py'), ('installer/start.py', 'start.py')]:
        if content.digest(tools / original) != content.digest(destination / 'Launcher' / target):
            raise ValueError('Starterkopie stimmt nicht ueberein.')
    write_json(destination / 'local-bundle.json', bundle)
    write_json(destination / 'compatibility.json', content.create(destination))
    (destination / 'LIESMICH.txt').write_text(
        'S7 lokale Testkopie\n\nStart-S7-Test.cmd startet den lokalen Test.\n'
        'Host und Beitritt zwischen PCs sind noch nicht freigegeben.\n'
        'Dateistand-pruefen.cmd prueft Spiel und Patch auf Veraenderungen.\n'
        'compatibility.json kann zum Vergleich auf den zweiten PC kopiert werden.\n'
        'Gleiche Dateien allein garantieren keine desyncfreie Simulation.\n'
        'Die Originalinstallation wurde nicht veraendert. Zum Entfernen diese getrennte Kopie loeschen.\n', encoding='utf-8')
    starter = '@echo off\n"%~dp0Runtime\\python\\python.exe" -B "%~dp0Launcher\\start.py" --bundle "%~dp0."\nif errorlevel 1 pause\n'
    with (destination / 'Start-S7-Test.cmd').open('x', encoding='ascii') as stream: stream.write(starter)
    with (destination / 'Dateistand-pruefen.cmd').open('x', encoding='ascii') as stream:
        stream.write('@echo off\n"%~dp0Runtime\\python\\python.exe" -B "%~dp0Launcher\\compatibility.py" --bundle "%~dp0."\npause\n')
    incomplete.unlink()
    emit('Testkopie ist vorbereitet. LAN-Host/Beitritt sind noch nicht freigegeben.')
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument('--source'); parser.add_argument('--destination')
    args = parser.parse_args()
    try:
        print('S7 Patch-Vorbereitung: getrennte Testkopie, noch kein spielbares LAN.')
        source = args.source or input('S7-Installationsordner: ').strip().strip('"')
        destination = args.destination or input('Neuer Ordner fuer die Testkopie: ').strip().strip('"')
        if not source or not destination: raise ValueError('Beide Ordner werden benoetigt.')
        prepare(Path(args.package), Path(source), Path(destination))
        return 0
    except (OSError, ValueError, KeyError, TypeError, EOFError) as exc:
        print('Vorbereitung abgebrochen: ' + str(exc)); return 2


if __name__ == '__main__':
    raise SystemExit(main())
