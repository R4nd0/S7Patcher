"""Invented files only; real archive integration is an explicit separate check."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools/installer'
sys.path.insert(0, str(TOOLS))
import compatibility as content
import install


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('S7_TEST_TEMP_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'package'; self.source = self.root / 'game'; self.destination = self.root / 'copy'
        def write(root, name, value):
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value)
        self.write = write
        for name, value in [('Base/Bin/Settlers7R.exe', b'invented exe'), ('Base/BBA/Interface.bba', b'invented archive'),
                            ('Base/Bin/uplay_r1_loader.dll', b'invented original loader'), ('Base/BBA/map.bba', b'invented map')]:
            write(self.source, name, value)
        for name in ['Payload/uplay_r1_loader.dll', 'Payload/Server/S7Patcher.dll', 'Runtime/python/python.exe',
                     'Runtime/dotnet/dotnet.exe', 'Tools/offline-ui/patch-spec.json', 'Tools/LICENSE.txt']:
            write(self.package, name, b'invented package')
        for original, target in [('compatibility.py', 'installer/compatibility.py'), ('start.py', 'installer/start.py'), ('launch_lan.py', 'installer/launch_lan.py')]:
            write(self.package, 'Tools/' + target, (TOOLS / original).read_bytes())
        write(self.package, 'Tools/offline-ui/launch_local.py', b'# invented launcher fixture\n')
        write(self.package, 'Tools/lan/prepare.py', b'''from pathlib import Path
def prepare(source, output, specification, profile):
    base = 'Base' if (Path(source)/'Base').exists() else 'Data/Base'
    path = Path(output)/base/'BBA/Interface.bba'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'invented patched archive')
''')
        self.manifest()
        for name, value in [('EXPECTED_EXE', b'invented exe'), ('EXPECTED_ARCHIVE', b'invented archive')]:
            mock = patch.object(install, name, hashlib.sha256(value).hexdigest()); mock.start(); self.addCleanup(mock.stop)

    def manifest(self):
        self.data = {'format': install.FORMAT, 'capabilities': {'local_test': True, 'lan_host': False, 'lan_join': False},
                     'patched_archive_sha256': hashlib.sha256(b'invented patched archive').hexdigest(),
                     'files': content.inventory(self.package, ('Payload', 'Runtime', 'Tools'))}
        (self.package / 'package.json').write_text(json.dumps(self.data))

    def prepare(self):
        return install.prepare(self.package, self.source, self.destination, emit=lambda _: None)

    def test_prepares_separate_copy_without_identity_or_original_changes(self):
        before = content.inventory(self.source, ('Base',))
        self.prepare()
        self.assertEqual(before, content.inventory(self.source, ('Base',)))
        self.assertEqual((self.destination / 'Base/BBA/Interface.bba').read_bytes(), b'invented patched archive')
        self.assertFalse((self.destination / 'INSTALLATION-INCOMPLETE.txt').exists())
        self.assertFalse((self.destination / 'LocalData').exists())
        self.assertTrue((self.destination / 'Start-S7-Test.cmd').is_file())
        content.verify(self.destination)
        (self.destination / 'Base/BBA/map.bba').write_bytes(b'changed')
        self.assertEqual((self.source / 'Base/BBA/map.bba').read_bytes(), b'invented map')
        with self.assertRaisesRegex(ValueError, 'veraendert'): content.verify(self.destination)

    def test_alternate_data_layout_becomes_canonical(self):
        (self.source / 'Data').mkdir()
        (self.source / 'Base').rename(self.source / 'Data/Base')
        self.prepare()
        self.assertTrue((self.destination / 'Base/Bin/Settlers7R.exe').is_file())
        content.verify(self.destination)

    def test_overlaps_existing_and_dotdot_are_rejected_before_copy(self):
        for destination in (self.source / 'new', self.package / 'new', self.root,
                            self.source / '..' / 'game' / 'nested'):
            with self.assertRaises(ValueError): install.prepare(self.package, self.source, destination, emit=lambda _: None)
        self.assertFalse((self.source / 'nested').exists())

    def test_modified_package_and_unsupported_executable_reject_before_output(self):
        (self.package / 'Payload/uplay_r1_loader.dll').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.destination.exists())
        self.manifest()
        (self.source / 'Base/Bin/Settlers7R.exe').write_bytes(b'unsupported')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.destination.exists())

    def test_extra_payload_file_and_false_capability_claim_rejected(self):
        (self.package / 'Payload/extra').write_bytes(b'extra')
        with self.assertRaises(ValueError): self.prepare()
        self.manifest(); self.data['capabilities']['lan_join'] = True
        (self.package / 'package.json').write_text(json.dumps(self.data))
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.destination.exists())

    def test_copy_failure_keeps_marker_and_no_starter(self):
        with patch.object(install.shutil, 'copyfileobj', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError): self.prepare()
        self.assertTrue((self.destination / 'INSTALLATION-INCOMPLETE.txt').is_file())
        self.assertFalse((self.destination / 'Start-S7-Test.cmd').exists())

    def test_disk_space_rejection_has_no_output(self):
        with patch.object(install.shutil, 'disk_usage', return_value=type('Disk', (), {'free': 0})()):
            with self.assertRaisesRegex(ValueError, 'Speicher'): self.prepare()
        self.assertFalse(self.destination.exists())

    def test_content_identity_is_path_independent_and_sensitive_to_all_files(self):
        self.prepare(); first = content.create(self.destination)
        other = self.root / 'other'; install.shutil.copytree(self.destination, other)
        self.assertEqual(content.create(other)['content_id'], first['content_id'])
        for relative in ('Base/BBA/new-map.bba', 'Server/S7Patcher.dll', 'Launcher/start.py'):
            with self.subTest(relative=relative):
                target = other / relative; old = target.read_bytes() if target.exists() else None
                target.write_bytes(b'changed')
                self.assertEqual(content.compare(first, content.create(other)), [relative.lower()])
                if old is None: target.unlink()
                else: target.write_bytes(old)
        (other / 'Base/BBA/map.bba').unlink()
        self.assertEqual(content.compare(first, content.create(other)), ['base/bba/map.bba'])
        self.assertNotIn(str(self.destination), json.dumps(first))
        self.assertFalse(first['simulation_sync_verified'])

    def test_changed_manifest_and_invalid_paths_rejected(self):
        self.prepare(); original = content.create(self.destination)
        changed = copy.deepcopy(original); changed['content_id'] = '0' * 64
        with self.assertRaises(ValueError): content.validate(changed)
        for name in ('../outside', '/base/absolute', 'base/../outside', 'base/a:stream', 'Base/uppercase', 'base\\backslash'):
            changed = copy.deepcopy(original); changed['files'][name] = '0' * 64
            changed['content_id'] = content.fingerprint(changed['files'])
            with self.assertRaises(ValueError): content.validate(changed)

    def test_source_link_rejected_without_following(self):
        outside = self.root / 'outside'; outside.write_bytes(b'outside')
        link = self.source / 'Base/BBA/link'
        try: link.symlink_to(outside)
        except OSError: self.skipTest('Windows symlink privilege unavailable')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.destination.exists())


if __name__ == '__main__':
    unittest.main()
