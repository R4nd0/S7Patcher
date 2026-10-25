"""Stage a hash-locked S7 History menu/archive diagnostic, without installing it.

Only a new, explicit output directory is written. No game executable, archive,
user configuration, network configuration or account data is modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from bba import Archive

KNOWN_EXE = "4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f"
KNOWN_ARCHIVE = "766ae21ef06709309a68fb5bb792b0fd56373c668f02140122eef181917b0b94"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_checked(path, expected):
    data = path.read_bytes()
    if sha256(data) != expected:
        raise ValueError("Unsupported or modified input; SHA-256 mismatch: " + str(path))
    return data


def apply_edits(original, item):
    if sha256(original) != item["source_sha256"]:
        raise ValueError("Lua source fingerprint mismatch: " + item["path"])
    edits = sorted(item["edits"], key=lambda value: value["offset"])
    cursor = 0
    result = bytearray()
    for edit in edits:
        offset = edit["offset"]
        before = bytes.fromhex(edit["before_hex"])
        if not before or offset < cursor or offset + len(before) > len(original):
            raise ValueError("Overlapping or invalid Lua delta: " + item["path"])
        if original[offset:offset + len(before)] != before:
            raise ValueError("Expected original Lua bytes do not match: " + item["path"])
        result.extend(original[cursor:offset])
        result.extend(edit["after_utf8"].encode("utf-8"))
        cursor = offset + len(before)
    result.extend(original[cursor:])
    if sha256(result) != item["patched_sha256"]:
        raise ValueError("Patched Lua fingerprint mismatch: " + item["path"])
    return bytes(result)


def prepare(installation, output, specification):
    root = Path(installation).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Supply the installation folder, not an executable")
    bases = [base for base in (root / "Base", root / "Data" / "Base")
             if (base / "Bin" / "Settlers7R.exe").is_file() and (base / "BBA" / "Interface.bba").is_file()]
    if len(bases) != 1:
        raise ValueError("Expected exactly one installation with Base/Bin or Data/Base/Bin and Base/BBA/Interface.bba")
    base = bases[0]
    destination = Path(output).resolve()
    if destination.exists():
        raise ValueError("Output must be a NEW directory; nothing will be overwritten")
    protected_directories = (root, base.resolve(strict=True),
                             (base / "Bin").resolve(strict=True), (base / "BBA").resolve(strict=True))
    if any(destination.is_relative_to(path) or path.is_relative_to(destination) for path in protected_directories):
        raise ValueError("Output must be separate from the game installation")
    if not destination.parent.is_dir():
        raise ValueError("The output parent directory must already exist")

    exe_path = base / "Bin" / "Settlers7R.exe"
    archive_path = base / "BBA" / "Interface.bba"
    read_checked(exe_path, KNOWN_EXE)
    original = read_checked(archive_path, KNOWN_ARCHIVE)
    spec_bytes = Path(specification).read_bytes()
    spec = json.loads(spec_bytes)
    if spec.get("schema_version") != 1 or not spec.get("files"):
        raise ValueError("Unsupported or empty patch specification")
    archive = Archive(original)
    replacements = {}
    for item in spec["files"]:
        name = item["path"].replace("\\", "/")
        if not name.startswith("Script/") or not name.endswith(".lua") or name in replacements:
            raise ValueError("Unexpected or duplicate patch target: " + name)
        if name not in archive.entries:
            raise ValueError("Patch target does not exist in the original archive: " + name)
        replacements[name] = apply_edits(archive.read(name), item)
    patched = archive.replace(replacements)
    check = Archive(patched)
    verified_count = 0
    for name, entry in archive.entries.items():
        if entry.values[4] != 256:
            expected = replacements.get(name)
            if expected is None:
                expected = archive.read(name)
            if check.read(name) != expected:
                raise ValueError("Staged archive content mismatch: " + name)
            verified_count += 1

    # Validate everything before creating the output. Recheck the game inputs
    # so a concurrently changed installation cannot be marked as validated.
    read_checked(exe_path, KNOWN_EXE)
    read_checked(archive_path, KNOWN_ARCHIVE)
    artifact_relative = base.relative_to(root) / "BBA" / "Interface.bba"
    manifest = {
        "schema_version": 1,
        "status": "menu-diagnostic-staged-not-installed",
        "lan_compatibility_verified": False,
        "installed": False,
        "source_executable_sha256": KNOWN_EXE,
        "source_archive_sha256": KNOWN_ARCHIVE,
        "staged_archive_sha256": sha256(patched),
        "patch_specification_sha256": sha256(spec_bytes),
        "artifact": artifact_relative.as_posix(),
        "verified_archive_files": verified_count,
        "changed_files": [{"path": item["path"], "source_sha256": item["source_sha256"],
                           "patched_sha256": item["patched_sha256"], "edit_count": len(item["edits"])} for item in spec["files"]],
        "notes": ["This is a menu/archive diagnostic, not a replacement server or playable LAN patch.",
                  "The native LAN Join implementation in this build is a success-returning stub. LAN Join is disabled in the diagnostic menu.",
                  "Native LAN Create still requires login and NAT readiness. These archive deltas do not remove those native requirements.",
                  "Original game files, user settings and system network settings were not modified.",
                  "The staged archive contains local game data. Do not publish it or commit it to source control."]
    }
    destination.mkdir()  # Fails if a concurrent process created the directory.
    artifact = destination / artifact_relative
    artifact.parent.mkdir(parents=True)
    with artifact.open("xb") as stream:
        stream.write(patched)
    with (destination / "manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    return {"status": manifest["status"], "output": str(destination), "files_changed": len(replacements),
            "verified_archive_files": verified_count, "installed": False, "lan_compatibility_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installation")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.installation, args.output, Path(__file__).with_name("patch-spec.json"))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exception:
        print(json.dumps({"status": "error", "message": str(exception), "installed": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
