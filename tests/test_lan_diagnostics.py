import base64
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools/installer'))
import diagnose_lan as diagnostic

class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('S7_TEST_TEMP_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = []
        self.config = {'content_id':'a'*64, 'prudp_urls':['prudp:/address=192.168.10.10;port=9111'],
                       'public_key':base64.b64encode(b'ECS1'+bytes([32,0,0,0])+bytes(64)).decode()}
        self.compatibility = SimpleNamespace(plain=MagicMock(return_value=self.root), verify=MagicMock(return_value={'content_id':'a'*64}))
        self.local = SimpleNamespace(lan_pair=MagicMock(), verify_bundle=MagicMock())
        self.launcher = SimpleNamespace(UDP_PORT=9111,remote_configuration=MagicMock(return_value=self.config),check_content=MagicMock())
        self.socket = MagicMock()
        mock = patch.object(diagnostic.socket, 'socket',return_value=self.socket)
        mock.start(); self.addCleanup(mock.stop)
    def run_check(self):
        return diagnostic.check(self.root,'192.168.10.20','192.168.10.10', compatibility=self.compatibility,
            launcher=self.launcher,local_launcher=self.local,emit=lambda text,**kwargs:self.output.append(text))
    def test_success_without_files_or_identity(self):
        self.assertEqual(self.run_check(),0)
        self.assertEqual(list(self.root.iterdir()),[])
        self.assertEqual(sum(s.startswith('OK:') for s in self.output),7)
        self.launcher.remote_configuration.assert_called_once_with('192.168.10.10','192.168.10.20')
    def test_wrong_local_address_never_contacts_host(self):
        error=OSError(10049,'sensitive text');error.winerror=10049
        self.socket.__enter__.return_value.bind.side_effect=error
        with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
        self.assertEqual(caught.exception.stage,'Eigene Adresse')
        self.assertIn('gehoert nicht zu diesem PC',diagnostic.explain(caught.exception.stage,error))
        self.launcher.remote_configuration.assert_not_called()
    def test_content_integrity_failure_before_network(self):
        self.compatibility.verify.side_effect=ValueError('sensitive file content')
        with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
        self.assertEqual(caught.exception.stage,'Dateipruefung')
        self.launcher.remote_configuration.assert_not_called()
    def test_unfinished_installation_stops(self):
        (self.root/'INSTALLATION-INCOMPLETE.txt').write_text('fixture')
        with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
        self.assertEqual(caught.exception.stage,'Dateipruefung')
        self.compatibility.verify.assert_not_called()
    def test_host_timeout_has_dedicated_step(self):
        self.launcher.remote_configuration.side_effect=TimeoutError()
        with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
        self.assertEqual(caught.exception.stage,'Hostverbindung')
        self.assertIn('nicht rechtzeitig',diagnostic.explain(caught.exception.stage,caught.exception.cause))
    def test_mismatched_content_has_dedicated_step(self):
        self.launcher.check_content.side_effect=ValueError('sensitive hash')
        with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
        self.assertEqual(caught.exception.stage,'Dateivergleich')
    def test_bad_endpoint_and_key_rejected(self):
        for key,value in [('prudp_urls',['prudp:/address=8.8.8.8;port=9111']),('public_key','bad')]:
            with self.subTest(key=key):
                old=self.config[key];self.config[key]=value
                with self.assertRaises(diagnostic.DiagnosticFailure) as caught:self.run_check()
                self.assertEqual(caught.exception.stage,'Serverkonfiguration')
                self.config[key]=old
    def test_errors_do_not_echo_payload(self):
        for error in (ValueError('SECRET PAYLOAD'),ConnectionRefusedError(10061,'SECRET PAYLOAD'),PermissionError(13,'SECRET PAYLOAD')):
            self.assertNotIn('SECRET',diagnostic.explain('Hostverbindung',error))
    def test_refusal_distinct_from_timeout(self):
        self.assertIn('abgelehnt',diagnostic.explain('Hostverbindung',ConnectionRefusedError(10061,'x')))

if __name__=='__main__':unittest.main()
