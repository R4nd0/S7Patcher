"""Apply one hash-locked menu delta to an installed two-peer test copy.

Runs only with S7 closed. No game launch, network, account or firewall access.
The existing launcher lock is held throughout. A persistent journal and backups
allow recovery after interruption; unexpected external changes fail closed.
"""
import argparse
from contextlib import contextmanager
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compatibility as content
from bba import Archive
from prepare import apply_edits, sha256, KNOWN_EXE

ARCHIVE = 'Base/BBA/Interface.bba'
FILES = (ARCHIVE, 'local-bundle.json', 'compatibility.json')
OLD = 'ebee0ff593cdb9c38442d03875041f8c1825c0fc3e2414291098e08f3517ced5'
NEW = '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'
ADAPTER = '441dcb75fe925a44de302859dcaef3bedff5ad49f8831a73b6fb0d1c49d5ae9f'
BACKUP = 'Before-join-menu-v1'


def ensure_closed():
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
         "if (Get-Process -Name Settlers7R -ErrorAction SilentlyContinue) { exit 7 }; exit 0"],
        capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode == 7:
        raise ValueError('Bitte S7 vollstaendig beenden und das Update erneut starten.')
    if result.returncode != 0:
        raise ValueError('Laufende Spiele konnten nicht sicher geprueft werden.')


@contextmanager
def session_lock(root):
    data = content.plain(root / 'LocalData')
    data.mkdir(exist_ok=True)
    with content.plain(data / 'session.lock').open('a+b') as lock:
        if lock.tell() == 0:
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise ValueError('Der Spielstarter laeuft noch. Bitte S7 und seinen Starter schliessen.') from None
        try:
            yield
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def atomic_write(path, value, staging):
    # Stage outside fingerprinted folders. An interrupted write must not leave
    # a stray Base/*.tmp that prevents recovery on the next invocation.
    with tempfile.NamedTemporaryFile(dir=staging, prefix='update-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value); stream.flush(); os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def recover(root, backup):
    journal_path = content.plain(backup / 'transaction.json')
    if not journal_path.exists():
        raise ValueError('Unvollstaendige Update-Vorbereitung. Sicherung bitte zur Diagnose aufbewahren.')
    journal = json.loads(journal_path.read_text(encoding='utf-8'))
    if journal.get('files') is None or set(journal['files']) != set(FILES):
        raise ValueError('Ungueltige Update-Sicherung.')
    originals = {}
    for name in FILES:
        record = journal['files'][name]
        original = content.plain(backup / name).read_bytes()
        if sha256(original) != record['old']:
            raise ValueError('Update-Sicherung wurde veraendert.')
        if content.digest(content.plain(root / name)) not in (record['old'], record['new']):
            raise ValueError('Dateien nach dem Update extern veraendert; keine automatische Wiederherstellung.')
        originals[name] = original
    # Validate all inputs before restoring any. Completed updates are not undone.
    if all(content.digest(root / name) == journal['files'][name]['new'] for name in FILES):
        return
    for name in FILES:
        if content.digest(root / name) != journal['files'][name]['old']:
            atomic_write(root / name, originals[name], backup)


def build_archive(original, spec):
    if (spec.get('format') != 's7-join-menu-update-v1'
            or spec.get('source_archive_sha256') != OLD
            or spec.get('patched_archive_sha256') != NEW or sha256(original) != OLD):
        raise ValueError('Dieses Update passt nicht zum vorhandenen Menuearchiv.')
    archive = Archive(original)
    replacements = {item['path']: apply_edits(archive.read(item['path']), item) for item in spec['files']}
    if set(replacements) != {'Script/local/menu/panel/menu/play/multiplayer/sessionList.lua'}:
        raise ValueError('Unerwarteter Menue-Patch.')
    patched = archive.replace(replacements)
    if sha256(patched) != NEW:
        raise ValueError('Die erzeugte Menueversion hat eine falsche Pruefsumme.')
    check = Archive(patched)
    if archive.entries.keys() != check.entries.keys():
        raise ValueError('Archiv-Dateiliste wurde veraendert.')
    for name, entry in archive.entries.items():
        if entry.values[4] != 256 and check.read(name) != replacements.get(name, archive.read(name)):
            raise ValueError('Archivpruefung fehlgeschlagen.')
    return patched


def apply_locked(root, spec):
    if (root / 'INSTALLATION-INCOMPLETE.txt').exists():
        raise ValueError('Die Testinstallation ist unvollstaendig.')
    backup = content.plain(root / 'LocalData' / BACKUP)
    if backup.exists():
        recover(root, backup)
    expected = content.verify(root)
    old_bytes = {name: content.plain(root / name).read_bytes() for name in FILES}
    manifest = json.loads(old_bytes['local-bundle.json'])
    hashes = manifest.get('files', {})
    allowed = {'Base/Bin/Settlers7R.exe': KNOWN_EXE, 'Base/Bin/uplay_r1_loader.dll': ADAPTER,
               ARCHIVE: sha256(old_bytes[ARCHIVE])}
    if manifest.get('format') != 's7-local-experimental-v1' or hashes != allowed:
        raise ValueError('Dieses Update braucht die bekannte LAN-Testkopie.')
    if any(expected['files'].get(name.lower()) != value for name, value in allowed.items()):
        raise ValueError('Startmanifest und Dateivergleich widersprechen sich.')
    if allowed[ARCHIVE] == NEW:
        return 'Das Menue-Update ist bereits installiert.'
    patched = build_archive(old_bytes[ARCHIVE], spec)
    manifest['files'][ARCHIVE] = NEW
    expected['files'][ARCHIVE.lower()] = NEW
    expected['content_id'] = content.fingerprint(expected['files'])
    new_bytes = {ARCHIVE: patched, 'local-bundle.json': encoded(manifest), 'compatibility.json': encoded(expected)}
    # Preserve every other hash; never regenerate an inventory to bless changes.
    if not backup.exists():
        backup.mkdir()
        for name, value in old_bytes.items():
            target = content.plain(backup / name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(value); stream.flush(); os.fsync(stream.fileno())
        with (backup / 'transaction.json').open('xb') as stream:
            stream.write(encoded({'files': {n: {'old': sha256(old_bytes[n]), 'new': sha256(new_bytes[n])} for n in FILES}}))
            stream.flush(); os.fsync(stream.fileno())
    # Recheck immediately before mutation; a user may have started a game meanwhile.
    ensure_closed()
    if any(content.digest(root / name) != sha256(old_bytes[name]) for name in FILES):
        raise ValueError('Dateien wurden waehrend des Updates veraendert.')
    try:
        for name in FILES:
            atomic_write(root / name, new_bytes[name], backup)
        content.verify(root)
    except Exception:
        recover(root, backup)
        raise
    return 'Menue-Update installiert. Bitte auch auf dem anderen PC anwenden.'


def run(root, spec):
    root = content.plain(root)
    ensure_closed()
    with session_lock(root):
        return apply_locked(root, spec)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    try:
        spec = json.loads(Path(__file__).with_name('join-menu-update.json').read_text(encoding='utf-8'))
        print(run(Path(args.bundle), spec))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('UPDATE ABGEBROCHEN: ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
