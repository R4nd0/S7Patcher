"""Stage fast main-menu startup and hidden online promotions in a new directory.

Uses the same fingerprint checks and full archive verification as the LAN
diagnostic. Never installs or launches the game. Requires the original HE build.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

LAN = Path(__file__).resolve().parents[1] / "lan"
sys.path.insert(0, str(LAN))
module_spec = importlib.util.spec_from_file_location("s7_archive_prepare", LAN / "prepare.py")
archive_prepare = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(archive_prepare)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installation")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = archive_prepare.prepare(args.installation, args.output,
            Path(__file__).with_name("patch-spec.json"), profile="offline-ui")
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exception:
        print(json.dumps({"status": "error", "message": str(exception), "installed": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
