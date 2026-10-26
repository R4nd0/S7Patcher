"""Portable prepared-copy launcher with a full content check before startup."""
import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compatibility
import launch_local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    root = compatibility.plain(Path(args.bundle))
    try:
        if (root / 'INSTALLATION-INCOMPLETE.txt').exists():
            raise ValueError('Die Vorbereitung wurde nicht abgeschlossen.')
        print('Pruefe den Spiel- und Patchstand ...', flush=True)
        compatibility.verify(root)
        # The portable service keeps both PCs on the same local-test code path.
        # LAN roles cannot be enabled by an installer setting or guessed address.
        return launch_local.run(SimpleNamespace(bundle=str(root),
            dotnet=str(root / 'Runtime/dotnet/dotnet.exe'), server=str(root / 'Server/S7Patcher.dll'),
            local_connect_probe=True, local_session_display_probe=False, launch_game=not args.check_only))
    except (OSError, ValueError, RuntimeError, TimeoutError, launch_local.http.client.HTTPException) as exc:
        print('Start abgebrochen: ' + str(exc)); return 2


if __name__ == '__main__':
    raise SystemExit(main())
