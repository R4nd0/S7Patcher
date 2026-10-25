"""Standard-library regressions. No Ubisoft data or installation is required.

Set S7_INSTALLATION to run an additional read-only, hash-locked integration test.
All output is written to a new temporary directory, never into the installation.
"""
import copy
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "lan"
sys.path.insert(0, str(TOOLS))
import bba
import prepare


def synthetic_archive():
    """A tiny, invented v6 archive with one compressed and one plain file."""
    raw = bytearray(b"BAF\x06" + b"\0" * 28)
    struct.pack_into("<I", raw, 8, 16)
    directory = bytearray(276)
    struct.pack_into("<I", directory, 4, 272)
    struct.pack_into("<I", directory, 272, 2)
    for name, data, kind in [("Script/example.lua", b"return false\n", 17),
                             ("Script/unchanged.lua", b"return 123\n", 0)]:
        encoded_name = name.encode("ascii")
        payload = bba._gzip_xor(gzip.compress(data, mtime=0), len(encoded_name), True) if kind == 17 else data
        values = [0] * 16
        values[2], values[3], values[4] = len(data), bba.crc32(data), kind
        values[6], values[8], values[9] = len(raw), len(payload), bba.crc32(payload)
        values[12] = len(encoded_name)
        directory.extend(struct.pack("<16I", *values))
        directory.extend(encoded_name)
        directory.extend(b"\0" * (4 - len(encoded_name) % 4))
        raw.extend(payload)
    struct.pack_into("<I", directory, 8, len(directory))
    # Invented lookup data is deliberately nonzero, so preserving it is checked.
    directory.extend(struct.pack("<5I", 2, 0x12345678, 276, 0x90ABCDEF, 360))
    encrypted = bba.crypt(directory, bba.FILE_KEYS, 1532281822, 8, True)
    header = struct.pack("<4I", len(raw), 0, len(encrypted), bba.crc32(encrypted))
    raw[16:32] = bba.crypt(header, bba.HEAD_KEYS, 1231853475, 7, True)
    return bytes(raw + encrypted)


def specification():
    return {"schema_version": 1, "files": [{
        "path": "Script/example.lua", "source_sha256": prepare.sha256(b"return false\n"),
        "patched_sha256": prepare.sha256(b"return true\n"),
        "edits": [{"offset": 7, "before_hex": b"false".hex(), "after_utf8": "true", "reason": "test"}]
    }]}


class ArchiveTests(unittest.TestCase):
    def test_append_preserves_old_bytes_untouched_file_and_hash_table(self):
        original = synthetic_archive()
        archive = bba.Archive(original)
        result = archive.replace({"Script/example.lua": b"return true\n"})
        changed = bba.Archive(result)
        self.assertEqual(result[:16], original[:16])
        self.assertEqual(result[32:len(original)], original[32:])
        self.assertEqual(changed.directory[changed.hash_table_offset:], archive.directory[archive.hash_table_offset:])
        self.assertEqual(changed.read("Script/example.lua"), b"return true\n")
        self.assertEqual(changed.read("Script/unchanged.lua"), b"return 123\n")
        self.assertEqual(changed.entries["Script/unchanged.lua"].values, archive.entries["Script/unchanged.lua"].values)
        v = changed.entries["Script/example.lua"].values
        self.assertEqual(v[9], bba.crc32(result[v[6]:v[6] + v[8]]))

    def test_directory_corruption_is_rejected(self):
        original = bytearray(synthetic_archive())
        original[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "directory CRC32"):
            bba.Archive(original)

    def test_content_corruption_is_rejected(self):
        original = bytearray(synthetic_archive())
        entry = bba.Archive(original).entries["Script/unchanged.lua"]
        original[entry.values[6]] ^= 1
        with self.assertRaisesRegex(ValueError, "decompressed size/CRC32"):
            bba.Archive(original).read(entry.name)

    def test_unknown_target_cannot_add_files(self):
        with self.assertRaises(KeyError):
            bba.Archive(synthetic_archive()).replace({"new.lua": b"return true"})


class DeltaTests(unittest.TestCase):
    def test_delta_requires_source_before_bytes_and_result_fingerprints(self):
        item = specification()["files"][0]
        self.assertEqual(prepare.apply_edits(b"return false\n", item), b"return true\n")
        for field in ("source_sha256", "patched_sha256"):
            invalid = copy.deepcopy(item)
            invalid[field] = "0" * 64
            with self.assertRaises(ValueError):
                prepare.apply_edits(b"return false\n", invalid)
        invalid = copy.deepcopy(item)
        invalid["edits"][0]["before_hex"] = b"FALSE".hex()
        with self.assertRaisesRegex(ValueError, "original Lua bytes"):
            prepare.apply_edits(b"return false\n", invalid)

    def test_overlapping_deltas_rejected(self):
        invalid = specification()["files"][0]
        invalid["edits"].append(copy.deepcopy(invalid["edits"][0]))
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            prepare.apply_edits(b"return false\n", invalid)


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="s7-diagnostic-test-", dir=os.environ.get("S7_TEST_TEMP"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.game = self.root / "game"
        self.base = self.game / "Base"
        (self.base / "Bin").mkdir(parents=True)
        (self.base / "BBA").mkdir()
        self.exe = self.base / "Bin" / "Settlers7R.exe"
        self.exe.write_bytes(b"invented test executable")
        self.archive = self.base / "BBA" / "Interface.bba"
        self.archive.write_bytes(synthetic_archive())
        self.spec = self.root / "deltas.json"
        self.spec.write_text(json.dumps(specification()), encoding="utf-8")
        self.output = self.root / "new-output"
        self.constants = patch.multiple(prepare, KNOWN_EXE=prepare.sha256(self.exe.read_bytes()),
                                       KNOWN_ARCHIVE=prepare.sha256(self.archive.read_bytes()))
        self.constants.start()
        self.addCleanup(self.constants.stop)

    def run_prepare(self, output=None):
        return prepare.prepare(self.game, output or self.output, self.spec)

    def test_success_only_writes_new_artifact_and_manifest(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.game.rglob("*") if path.is_file()}
        result = self.run_prepare()
        self.assertFalse(result["installed"])
        self.assertFalse(result["lan_compatibility_verified"])
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.game.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        files = {path.relative_to(self.output).as_posix() for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(files, {"Base/BBA/Interface.bba", "manifest.json"})
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "menu-diagnostic-staged-not-installed")
        self.assertEqual(manifest["verified_archive_files"], 2)

    def test_unknown_executable_rejected_before_output(self):
        self.exe.write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_unknown_archive_rejected_before_output(self):
        self.archive.write_bytes(b"different archive")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_lua_source_rejected_before_output(self):
        invalid = specification()
        invalid["files"][0]["source_sha256"] = "0" * 64
        self.spec.write_text(json.dumps(invalid), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source fingerprint"):
            self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_untouched(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(ValueError, "NEW directory"):
            self.run_prepare()
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_output_inside_installation_rejected(self):
        unsafe = self.game / "new-output"
        with self.assertRaisesRegex(ValueError, "separate"):
            self.run_prepare(unsafe)
        self.assertFalse(unsafe.exists())

    def test_output_inside_junction_target_rejected(self):
        real_assets = self.root / "game-assets-outside-install-root"
        self.base.rename(real_assets)
        if os.name == "nt":
            environment = dict(os.environ, S7_TEST_LINK=str(self.base), S7_TEST_TARGET=str(real_assets))
            create = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                     "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:S7_TEST_LINK -Target $env:S7_TEST_TARGET | Out-Null"],
                                    env=environment, capture_output=True, text=True)
            if create.returncode:
                self.skipTest("Windows junction creation unavailable: " + create.stderr)
        else:
            self.base.symlink_to(real_assets, target_is_directory=True)
        unsafe = real_assets / "new-output"
        with self.assertRaisesRegex(ValueError, "separate"):
            self.run_prepare(unsafe)
        self.assertFalse(unsafe.exists())

    def test_data_base_layout(self):
        (self.game / "Data").mkdir()
        self.base.rename(self.game / "Data" / "Base")
        self.run_prepare()
        self.assertTrue((self.output / "Data" / "Base" / "BBA" / "Interface.bba").is_file())

    def test_ambiguous_layout_rejected(self):
        other = self.game / "Data" / "Base"
        (other / "Bin").mkdir(parents=True)
        (other / "BBA").mkdir()
        (other / "Bin" / "Settlers7R.exe").write_bytes(b"fake")
        (other / "BBA" / "Interface.bba").write_bytes(b"fake")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.run_prepare()
        self.assertFalse(self.output.exists())


@unittest.skipUnless(os.environ.get("S7_INSTALLATION"), "Set S7_INSTALLATION for the read-only real-game integration test")
class RealInstallationTests(unittest.TestCase):
    def test_real_archive_and_every_unchanged_entry(self):
        game = Path(os.environ["S7_INSTALLATION"]).resolve()
        base = next(base for base in (game / "Base", game / "Data" / "Base") if (base / "BBA" / "Interface.bba").is_file())
        paths = [base / "Bin" / "Settlers7R.exe", base / "BBA" / "Interface.bba"]
        before = {path: (prepare.sha256(path.read_bytes()), path.stat().st_mtime_ns) for path in paths}
        before_files = sorted(str(path) for path in base.rglob("*"))
        with tempfile.TemporaryDirectory(prefix="s7-real-diagnostic-test-", dir=os.environ.get("S7_TEST_TEMP")) as temporary:
            output = Path(temporary) / "new-output"
            result = prepare.prepare(game, output, TOOLS / "patch-spec.json")
            self.assertEqual(result["files_changed"], 6)
            self.assertEqual(result["verified_archive_files"], 284)
            manifest = json.loads((output / "manifest.json").read_text())
            staged = bba.Archive((output / manifest["artifact"]).read_bytes())
            original = bba.Archive(paths[1].read_bytes())
            changes = {item["path"]: item for item in json.loads((TOOLS / "patch-spec.json").read_text())["files"]}
            for name, entry in original.entries.items():
                if entry.values[4] != 256:
                    expected = prepare.apply_edits(original.read(name), changes[name]) if name in changes else original.read(name)
                    self.assertEqual(staged.read(name), expected, name)
        self.assertEqual(before, {path: (prepare.sha256(path.read_bytes()), path.stat().st_mtime_ns) for path in paths})
        self.assertEqual(before_files, sorted(str(path) for path in base.rglob("*")))


if __name__ == "__main__":
    unittest.main()
