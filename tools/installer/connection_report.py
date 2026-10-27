"""Read fixed diagnostic categories from the current test folder, without writes.

No game memory, accounts, configuration, packet payloads or arbitrary log text.
The newest strictly named host log is read from a bounded tail. Older service
builds have no event clock/role; report that absence rather than guessing.
"""
import argparse
from collections import Counter, deque
import json
from pathlib import Path
import re
import stat

LIMIT = 16 * 1024 * 1024
LOG_NAME = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{8}-lan-server\.jsonl')
EVENTS = frozenset('''configuration-server-ready configuration-server-stopped
configuration-server-error local-login-session-expired local-login-message-rejected
local-post-login-request-observed local-session-create-response-queued
local-session-update-response-queued local-session-leave-response-queued
local-session-join-response-queued local-session-join-success-response-queued
local-session-get-response-queued local-session-search-response-queued
local-session-join-failure-observed local-login-response-queued
local-login-ack-observed local-ping-ack-sent connect-probe-request-rejected'''.split())
REASONS = frozenset('''probe-lifetime-ended keepalive-maximum-ended
keepalive-idle-timeout response-ack-timeout response-budget-exhausted
response-fragment-limit unsupported-session-operation missing-syn-context
changed-connect-context local-bind-key-or-io-failure
local-session-record-created local-session-metadata-updated
local-session-record-left local-session-confirmed-member-left
local-session-pending-member-left local-session-leave-owner-or-space-mismatch
local-session-update-owner-or-space-mismatch local-session-owner-not-registered
local-join-reservation-created local-join-member-confirmed
matchmaking-migrate-session-v1 matchmaking-report-migration-success-v1
matchmaking-leave-session-v1 matchmaking-update-session-v1
matchmaking-create-session-v1 matchmaking-create-session2-v1
matchmaking-search-sessions-v1 matchmaking-get-session-v1
matchmaking-join-session-v1 matchmaking-report-join-success-v1
matchmaking-report-join-failure-v1 matchmaking-report-connectivity-v1
matchmaking-report-qos-v1 local-login-response-created
local-register-response-created'''.split())
ROLES = frozenset(('loopback', 'service-local', 'configured-peer'))
NATIVE = frozenset('''local-platform-start-requested local-platform-started
local-game-login-status-connected local-game-login-status-not-ready
local-command-offset-unknown-latency-default local-network-core-pump-active
lab-native-core-natural-progress-observed lab-native-core-resumed-after-owner-update
lab-native-join-completion-succeeded lab-native-join-completion-link-reach-failed
lab-native-join-request-pending lab-native-host-join-gate-open'''.split())


def safe(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Links und Umleitungen werden nicht gelesen.')
    return path


def tail(path, limit=LIMIT):
    with safe(path).open('rb') as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - limit))
        if size > limit:
            stream.readline(limit)  # Bound even a single oversized record.
        return stream.read(limit), size > limit


def project(record, index):
    if not isinstance(record, dict) or not isinstance(record.get('event'), str):
        return None
    if record['event'] not in EVENTS:
        return None
    result = {'record': index, 'event': record['event']}
    if 'reason' in record:
        reason = record['reason']
        result['reason'] = reason if isinstance(reason, str) and reason in REASONS else 'other-redacted-reason'
    role = record.get('source_role')
    if isinstance(role, str) and role in ROLES:
        result['source_role'] = role
    elapsed = record.get('elapsed_milliseconds')
    if type(elapsed) is int and 0 <= elapsed <= 7 * 86400000:
        result['elapsed_milliseconds'] = elapsed
    return result


def summarize(raw):
    counts = Counter()
    chronology = deque(maxlen=32)
    last = deque(maxlen=8)
    malformed = 0
    clocks = roles = False
    for index, line in enumerate(raw.splitlines(), 1):
        if not line:
            continue
        if len(line) > 65536:
            malformed += 1
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            malformed += 1
            continue
        item = project(record, index)
        if item is None:
            continue
        key = item['event'] + (':' + item['reason'] if 'reason' in item else '')
        counts[key] += 1
        clocks |= 'elapsed_milliseconds' in item
        roles |= 'source_role' in item
        last.append(item)
        if item['event'] not in ('local-login-ack-observed', 'local-ping-ack-sent',
                'local-session-search-response-queued', 'local-session-update-response-queued'):
            chronology.append(item)
    return {'event': 'service-log-summary', 'counts': dict(sorted(counts.items())),
            'malformed_records': malformed, 'event_clock_present': clocks,
            'transport_roles_present': roles, 'notable_records': list(chronology),
            'last_known_records': list(last)}


def report(root):
    root = safe(root)
    data = safe(root / 'LocalData')
    names = sorted(p.name for p in data.iterdir() if LOG_NAME.fullmatch(p.name))
    if names:
        raw, truncated = tail(data / names[-1])
        result = summarize(raw)
        result['tail_truncated'] = truncated
        result['host_log_run_local'] = names[-1][:15]  # Time only, no random suffix.
        result['host_log_may_predate_current_game'] = True
        print(json.dumps(result, separators=(',', ':')), flush=True)
    else:
        print(json.dumps({'event': 'no-host-service-log'}), flush=True)
    path = data / 'native-status.txt'
    if path.exists():
        raw, truncated = tail(path, 256 * 1024)
        lines = raw.decode('ascii', errors='replace').splitlines()
        starts = [i for i, line in enumerate(lines) if line == 'local-platform-start-requested']
        labels = [line for line in lines[starts[-1]:] if line in NATIVE] if starts else []
        print(json.dumps({'event': 'native-fixed-status', 'current_start_found': bool(starts),
                          'tail_truncated': truncated, 'labels': labels}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    print('S7 Verbindungsbericht: nur lesend, keine Spieldateien geaendert.', flush=True)
    try:
        report(args.bundle)
        return 0
    except (OSError, ValueError):
        print('BERICHT BEENDET: Testordner oder begrenzte Diagnosedateien nicht lesbar.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
