"""Hash-locked native Join Session request gate update for the two-PC test."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_join_menu as updater

OLD_ADAPTER = '441dcb75fe925a44de302859dcaef3bedff5ad49f8831a73b6fb0d1c49d5ae9f'
NEW_ADAPTER = 'f40d6aa17da87876abac5e8523ca6505b16c1ffb067d133956001882440bf71d'
MENU = '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'


def payload(original, spec):
    data = Path(__file__).with_name('uplay_r1_loader.dll').read_bytes()
    if updater.sha256(original) != OLD_ADAPTER or updater.sha256(data) != NEW_ADAPTER:
        raise ValueError('Adapter-Paket passt nicht oder wurde veraendert.')
    return data


def plan():
    return updater.UpdatePlan('Base/Bin/uplay_r1_loader.dll', OLD_ADAPTER, NEW_ADAPTER,
        'Before-join-adapter-v1', {'Base/Bin/Settlers7R.exe': updater.KNOWN_EXE,
                                'Base/BBA/Interface.bba': MENU}, payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    try:
        print(updater.run(Path(args.bundle), {}, plan()))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('UPDATE ABGEBROCHEN: ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
