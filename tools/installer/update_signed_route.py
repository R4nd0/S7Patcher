"""Install native signed Storm connection ID support, with both games closed."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_join_menu as updater

OLD_SERVICE = '044931d88c501a11a792067af97935ba1a3920cb85c54fbf140f0c4948c2f787'
NEW_SERVICE = '7d61a238e8af9355a9054fdf22debf6ca1c5777ebed154aba90a35d40568bafe'


def payload(original, spec):
    data = Path(__file__).with_name('S7Patcher.dll').read_bytes()
    if updater.sha256(original) != OLD_SERVICE or updater.sha256(data) != NEW_SERVICE:
        raise ValueError('Dienst-Paket passt nicht oder wurde veraendert.')
    return data


def plan():
    return updater.UpdatePlan('Server/S7Patcher.dll', OLD_SERVICE, NEW_SERVICE,
        'Before-signed-route-v1', {'Base/Bin/Settlers7R.exe': updater.KNOWN_EXE,
            'Base/Bin/uplay_r1_loader.dll': 'f40d6aa17da87876abac5e8523ca6505b16c1ffb067d133956001882440bf71d',
            'Base/BBA/Interface.bba': '2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad'}, payload)


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
