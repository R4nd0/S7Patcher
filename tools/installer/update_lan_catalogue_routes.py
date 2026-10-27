"""Hash-locked owned-route projection for LAN discovery, using the safe updater."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_join_menu as updater

OLD_SERVICE = '717618883ffb9cfccadad39e3bdd1369ad2cb2abfcb348bc300401f1a8ff8755'
NEW_SERVICE = 'a4e300b091e289175f4866f82303b78e05b77aa82cffe958324b6c591d622914'
ADAPTER = 'a59def58f827508d06c95e2787762681f19da4f74390cf205b19f500eaa60b1e'
MENU = '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'


def payload(original, spec):
    data = Path(__file__).with_name('S7Patcher.dll').read_bytes()
    if updater.sha256(original) != OLD_SERVICE or updater.sha256(data) != NEW_SERVICE:
        raise ValueError('Dienst-Paket passt nicht oder wurde veraendert.')
    return data


def plan():
    return updater.UpdatePlan('Server/S7Patcher.dll', OLD_SERVICE, NEW_SERVICE,
        'Before-lan-catalogue-routes-v1', {'Base/Bin/Settlers7R.exe': updater.KNOWN_EXE,
            'Base/Bin/uplay_r1_loader.dll': ADAPTER, 'Base/BBA/Interface.bba': MENU}, payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    try:
        root = Path(args.bundle)
        print(updater.run(root, {}, plan()))
        print('Vergleichskennung: ' + updater.content.load(root / 'compatibility.json')['content_id'])
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('UPDATE ABGEBROCHEN: ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
