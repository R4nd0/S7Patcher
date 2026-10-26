"""Deterministic content manifest. No account, path, player or machine identifiers.

This detects file differences, not divergence of an already running simulation.
LAN admission must call the same comparison before permitting a future join.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

FORMAT = 's7-content-v1'
ROOTS = ('Base', 'Server', 'Launcher')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def plain(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise ValueError('Verknuepfungen sind im Testordner nicht erlaubt.')
    return path.resolve(strict=False)


def inventory(root, directories=ROOTS):
    root = plain(root)
    records = {}
    for directory in directories:
        start = plain(root / directory)
        if not start.is_dir():
            raise ValueError('Ein benoetigter Ordner fehlt: ' + directory)
        stack = [start]
        while stack:
            for path in sorted(stack.pop().iterdir()):
                plain(path)
                if path.is_dir():
                    stack.append(path)
                elif path.is_file():
                    key = path.relative_to(root).as_posix().lower()
                    if key in records:
                        raise ValueError('Mehrdeutiger Dateiname im Testordner.')
                    records[key] = digest(path)
                else:
                    raise ValueError('Unbekannter Dateityp im Testordner.')
    return records


def fingerprint(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def create(root):
    files = inventory(root)
    return {'format': FORMAT, 'content_id': fingerprint(files), 'files': files,
            'simulation_sync_verified': False, 'lan_join_verified': False}


def validate(value):
    if not isinstance(value, dict) or value.get('format') != FORMAT or not isinstance(value.get('files'), dict):
        raise ValueError('Unbekanntes Vergleichsformat.')
    files = value['files']
    if not files or len(files) > 20000:
        raise ValueError('Ungueltige Dateiliste.')
    for name, hash_value in files.items():
        if not isinstance(name, str) or name != name.lower() or '\\' in name or ':' in name:
            raise ValueError('Ungueltiger Dateipfad.')
        parts = PurePosixPath(name).parts
        if not parts or parts[0] not in tuple(x.lower() for x in ROOTS) or '..' in parts or name.startswith('/'):
            raise ValueError('Dateipfad ausserhalb der Vergleichsordner.')
        if not isinstance(hash_value, str) or len(hash_value) != 64 or any(c not in '0123456789abcdef' for c in hash_value):
            raise ValueError('Ungueltige Dateipruefsumme.')
    if value.get('content_id') != fingerprint(files):
        raise ValueError('Die Vergleichsdatei ist beschaedigt.')
    return value


def load(path):
    if Path(path).stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Vergleichsdatei ist zu gross.')
    return validate(json.loads(Path(path).read_text(encoding='utf-8')))


def compare(left, right):
    validate(left); validate(right)
    return sorted(name for name in left['files'].keys() | right['files'].keys()
                  if left['files'].get(name) != right['files'].get(name))


def verify(root):
    expected = load(plain(Path(root) / 'compatibility.json'))
    changed = compare(expected, create(root))
    if changed:
        raise ValueError('Spieldateien wurden veraendert; bitte Testkopie neu vorbereiten: ' + ', '.join(changed[:8]))
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--compare')
    args = parser.parse_args()
    try:
        local = verify(Path(args.bundle))
        if args.compare:
            changed = compare(local, load(args.compare))
            if changed:
                print('Unterschiedliche Spiel-/Patchdateien:\n' + '\n'.join(changed[:20])); return 2
        print('Dateistand stimmt ueberein. Das ist kein Nachweis einer desyncfreien Partie.')
        print('Vergleichskennung: ' + local['content_id'])
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(str(exc)); return 2


if __name__ == '__main__':
    raise SystemExit(main())
