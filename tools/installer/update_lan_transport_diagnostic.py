"""Hash-locked, separate-copy LAN socket observation update; no policy changes."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_join_menu as updater

OLD_ADAPTER = 'c3de5276657c61df27ac8be9f0597ce91749469bffb9ef59bc6e55847d2ca4ec'
NEW_ADAPTER = 'a59def58f827508d06c95e2787762681f19da4f74390cf205b19f500eaa60b1e'
MENU = '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'


def payload(original, spec):
    data = Path(__file__).with_name('uplay_r1_loader.dll').read_bytes()
    if updater.sha256(original) != OLD_ADAPTER or updater.sha256(data) != NEW_ADAPTER:
        raise ValueError('Adapter-Paket passt nicht oder wurde veraendert.')
    return data


def plan():
    return updater.UpdatePlan('Base/Bin/uplay_r1_loader.dll', OLD_ADAPTER, NEW_ADAPTER,
        'Before-lan-transport-diagnostic-v1', {'Base/Bin/Settlers7R.exe': updater.KNOWN_EXE,
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
