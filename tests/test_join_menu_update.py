import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools/installer'), str(ROOT / 'tools/lan')]
import update_join_menu as update
import compatibility as content


class MenuUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('S7_TEST_TEMP_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.values = {update.ARCHIVE: b'old menu', 'Base/Bin/Settlers7R.exe': b'fixture exe',
                       'Base/Bin/uplay_r1_loader.dll': b'fixture adapter',
                       'Server/server': b'server', 'Launcher/launcher': b'launcher'}
        for name, value in self.values.items():
            p = self.root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(value)
        self.new = b'new menu'
        for name, value in [('OLD', self.values[update.ARCHIVE]), ('NEW', self.new),
                            ('KNOWN_EXE', b'fixture exe'), ('ADAPTER', b'fixture adapter')]:
            mock = patch.object(update, name, update.sha256(value)); mock.start(); self.addCleanup(mock.stop)
        manifest = {'format': 's7-local-experimental-v1', 'files': {
            name: update.sha256(self.values[name]) for name in list(self.values)[:3]}}
        (self.root / 'local-bundle.json').write_bytes(update.encoded(manifest))
        (self.root / 'compatibility.json').write_bytes(update.encoded(content.create(self.root)))
        self.before = {n: (self.root / n).read_bytes() for n in update.FILES}
        mock = patch.object(update, 'ensure_closed'); self.closed = mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(update, 'build_archive', return_value=self.new)
        self.builder = mock.start(); self.addCleanup(mock.stop)

    def run_update(self):
        return update.run(self.root, {})

    def assert_original(self):
        for name, value in self.before.items(): self.assertEqual((self.root / name).read_bytes(), value)
        content.verify(self.root)

    def test_success_backup_inventory_and_idempotence(self):
        old_id = content.verify(self.root)['content_id']
        self.run_update()
        self.assertNotEqual(old_id, content.verify(self.root)['content_id'])
        self.assertEqual((self.root / update.ARCHIVE).read_bytes(), self.new)
        for name, value in self.before.items():
            self.assertEqual((self.root / 'LocalData' / update.BACKUP / name).read_bytes(), value)
        self.assertIn('bereits', self.run_update())
        self.assertEqual(self.builder.call_count, 1)
        self.assertFalse((self.root / 'LocalData/local-profile-id.txt').exists())

    def test_changed_nonmenu_file_rejected_before_patch(self):
        (self.root / 'Server/server').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.run_update()
        self.builder.assert_not_called()
        self.assertEqual((self.root / update.ARCHIVE).read_bytes(), self.before[update.ARCHIVE])

    def test_manifest_mismatch_rejected(self):
        value = json.loads(self.before['local-bundle.json']); value['files'][update.ARCHIVE] = '0'*64
        (self.root / 'local-bundle.json').write_bytes(update.encoded(value))
        with self.assertRaises(ValueError): self.run_update()
        self.builder.assert_not_called()

    def test_running_game_rejected_without_writes(self):
        self.closed.side_effect = ValueError('game running')
        with self.assertRaises(ValueError): self.run_update()
        self.assertFalse((self.root / 'LocalData').exists())
        self.assert_original()

    def test_launcher_lock_rejected(self):
        with update.session_lock(self.root):
            with self.assertRaises(ValueError): self.run_update()
        self.assert_original()

    def test_atomic_failure_rolls_back(self):
        original = update.atomic_write
        failed = False
        def write(path, value, staging):
            nonlocal failed
            if path.name == 'local-bundle.json' and not failed:
                failed = True
                raise OSError('simulated disk failure')
            return original(path, value, staging)
        with patch.object(update, 'atomic_write', side_effect=write):
            with self.assertRaises(OSError): self.run_update()
        self.assert_original()
        self.run_update(); content.verify(self.root)

    def test_interruption_recovered_on_next_run(self):
        original = update.atomic_write
        def write(path, value, staging):
            if path.name == 'local-bundle.json': raise KeyboardInterrupt()
            original(path, value, staging)
        with patch.object(update, 'atomic_write', side_effect=write):
            with self.assertRaises(KeyboardInterrupt): self.run_update()
        self.assertEqual((self.root / update.ARCHIVE).read_bytes(), self.new)
        self.run_update(); content.verify(self.root)

    def test_tampered_backup_rejected(self):
        self.run_update()
        (self.root / 'LocalData' / update.BACKUP / update.ARCHIVE).write_bytes(b'bad backup')
        with self.assertRaises(ValueError): self.run_update()

    def test_external_mutation_after_update_rejected_without_rollback(self):
        self.run_update()
        (self.root / update.ARCHIVE).write_bytes(b'external')
        with self.assertRaises(ValueError): self.run_update()
        self.assertEqual((self.root / update.ARCHIVE).read_bytes(), b'external')

    def test_game_started_during_preparation_rejected(self):
        self.closed.side_effect = [None, ValueError('game started')]
        with self.assertRaises(ValueError): self.run_update()
        self.assert_original()


if __name__ == '__main__': unittest.main()
