import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/installer'))
import connection_report as report


class ConnectionReportTests(unittest.TestCase):
    def test_does_not_export_unknown_text_or_untrusted_properties(self):
        records = [
            {'event': 'local-login-session-expired', 'reason': 'response-ack-timeout',
             'address': 'secret', 'message': 'secret', 'source_role': 'configured-peer',
             'elapsed_milliseconds': 1234},
            {'event': 'local-login-message-rejected', 'reason': 'secret',
             'source_role': 'secret', 'elapsed_milliseconds': 'secret'},
            {'event': 'secret', 'reason': 'secret'},
            {'event': ['secret'], 'reason': {'secret': True}},
            {'event': 'local-login-message-rejected', 'reason': ['secret']},
        ]
        value = report.summarize(b'\n'.join(json.dumps(x).encode() for x in records))
        serialized = json.dumps(value)
        self.assertNotIn('secret', serialized)
        self.assertEqual(value['counts']['local-login-session-expired:response-ack-timeout'], 1)
        self.assertTrue(value['event_clock_present'])
        self.assertTrue(value['transport_roles_present'])

    def test_old_logs_do_not_acquire_invented_time_or_source(self):
        value = report.summarize(b'{"event":"local-post-login-request-observed","reason":"matchmaking-migrate-session-v1"}')
        self.assertFalse(value['event_clock_present'])
        self.assertFalse(value['transport_roles_present'])
        self.assertNotIn('elapsed_milliseconds', value['notable_records'][0])

    def test_bounded_tails_malformed_lines_and_chronology(self):
        records = [{'event': 'local-login-session-expired', 'reason': 'response-ack-timeout'}] * 40
        value = report.summarize(b'bad\n' + b'\n'.join(json.dumps(x).encode() for x in records))
        self.assertEqual(value['malformed_records'], 1)
        self.assertEqual(len(value['notable_records']), 32)
        self.assertEqual(value['notable_records'][-1]['record'], 41)
        self.assertEqual(len(value['last_known_records']), 8)

    def test_reads_only_newest_named_log_and_latest_native_start(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('S7_TEST_TEMP_ROOT')) as temp:
            root = Path(temp)
            data = root / 'LocalData'; data.mkdir()
            (data / '20261027-110000-aaaaaaaa-lan-server.jsonl').write_text('{"event":"configuration-server-error"}')
            (data / '20261027-120000-bbbbbbbb-lan-server.jsonl').write_text('{"event":"local-ping-ack-sent"}')
            (data / 'account.json').write_text('secret')
            (data / 'native-status.txt').write_text('local-platform-start-requested\nlocal-game-login-status-not-ready\nlocal-platform-start-requested\nlocal-game-login-status-connected\nsecret\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output): report.report(root)
            values = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(values[0]['counts'], {'local-ping-ack-sent': 1})
            self.assertEqual(values[1]['labels'], ['local-platform-start-requested', 'local-game-login-status-connected'])
            self.assertNotIn('secret', output.getvalue())
            log = data / '20261027-120000-bbbbbbbb-lan-server.jsonl'
            raw, truncated = report.tail(log, 5)
            self.assertTrue(truncated)
            self.assertEqual(raw, b'')


if __name__ == '__main__':
    unittest.main()
