"""Bounded routing observer, not a replacement game server. Never launches a game."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import signal
import socketserver
import struct
import sys
import threading
import time

EXPECTED_SHA = '4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f'
PROLOGUE = bytes.fromhex('55 8b ec 6a ff 68 32 ec 00 01 64 a1 00 00 00 00')
CONFIG_PATH = '/public/rendezvous/v1/configuration'
SCRIPT_FAILURE_CODES = frozenset({
    'architecture-mismatch', 'module-lookup-failed', 'module-not-ready',
    'process-path-validation-failed', 'process-path-mismatch',
    'target-memory-unreadable', 'prologue-mismatch',
    'replacement-allocation-failed', 'interceptor-install-failed',
    'hook-setup-failed',
})


def validate_target(path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('target-sha256-mismatch')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != 0x14c:
        raise ValueError('target-not-pe32-ia32')
    if data[0xA896A0:0xA896A0+len(PROLOGUE)] != PROLOGUE:
        raise ValueError('target-file-bytes-mismatch')


def process_path(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return Path(buffer.value).resolve()
    finally:
        kernel.CloseHandle(handle)
    return None


class RoutingState:
    """Fail-closed ordering. A generation token proves timing, not a socket's PID."""
    def __init__(self, emit, hook_only=False):
        self.emit = emit
        self.hook_only = hook_only
        self.lock = threading.RLock()
        self.generation = 0
        self.attached = self.ready = self.redirected = self.observed = False
        self.failed = False
        self.completed = False
        self.pending_calls = set()
        self.last_call = 0

    def attach(self):
        with self.lock:
            self.generation += 1
            self.attached = True
            self.ready = self.redirected = self.observed = False
            self.completed = False
            self.pending_calls.clear()
            self.last_call = 0
            self.emit({'event': 'attached-to-authorized-process', 'generation': self.generation})
            return self.generation

    def detach(self, generation):
        with self.lock:
            if generation != self.generation or not self.attached:
                return
            self.attached = self.ready = self.redirected = self.observed = False
            self.completed = False
            self.pending_calls.clear()
            self.emit({'event': 'session-detached', 'generation': generation})

    def fail(self, reason):
        with self.lock:
            if not self.failed:
                self.failed = True
                self.observed = False
                self.emit({'event': 'probe-failed', 'reason': reason})

    def message(self, generation, message):
        with self.lock:
            if generation != self.generation or not self.attached or self.failed:
                return
            if message.get('type') == 'error':
                self.fail('script-validation-or-runtime-failure')
                return
            payload = message.get('payload')
            if message.get('type') != 'send' or not isinstance(payload, dict):
                self.fail('unexpected-script-message')
                return
            event = payload.get('event')
            if event == 'hook-validation-failed':
                code = payload.get('code')
                # Whitelist the entire value; never inspect or serialize a
                # raw Frida error, stack or arbitrary script payload field.
                known = type(code) is str and code in SCRIPT_FAILURE_CODES
                self.fail('script-' + code if known else 'script-unclassified-validation-failure')
            elif event == 'hook-ready' and payload.get('arch') == 'ia32' and not self.ready:
                self.ready = True
                self.emit({'event': 'hook-ready', 'generation': generation, 'arch': 'ia32'})
            elif event == 'sandbox-redirected' and self.ready:
                if self.hook_only:
                    call = payload.get('count')
                    if type(call) is not int or call != self.last_call + 1:
                        self.fail('script-call-order-failed')
                        return
                    self.last_call = call
                    self.pending_calls.add(call)
                    self.completed = False
                if not self.redirected:
                    self.redirected = True
                    self.emit({'event': 'sandbox-redirected', 'generation': generation})
            elif event == 'sandbox-call-finished' and self.ready and self.redirected:
                if self.hook_only:
                    call = payload.get('count')
                    if type(call) is not int or call not in self.pending_calls:
                        self.fail('script-call-order-failed')
                        return
                    self.pending_calls.remove(call)
                    if not self.pending_calls:
                        self.completed = True
                        self.emit({'event': 'redirection-completed', 'generation': generation,
                                   'claim': 'hook-only-constructor-returned-no-server-or-login-claim'})
            elif event in ('sandbox-read-skipped', 'unexpected-sandbox-skipped'):
                self.fail('sandbox-validation-failed')
            else:
                self.fail('script-event-order-or-validation-failed')

    def request_token(self):
        with self.lock:
            if self.hook_only:
                return None
            if self.attached and self.ready and self.redirected and not self.failed:
                return self.generation
            return None

    def observe_http(self, token):
        with self.lock:
            if token is None or token != self.request_token():
                return False
            if not self.observed:
                self.observed = True
                self.emit({'event': 'routing-correlated', 'generation': token,
                           'claim': 'temporal-correlation-only-request-source-unverified'})
            return True

    def outcome(self):
        with self.lock:
            if self.failed:
                return 3
            if self.hook_only:
                return 0 if self.completed and self.attached else None
            if self.observed and self.attached:
                return 0
            return None


class ProbeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Eligibility predates all reads; later callbacks cannot promote a request.
        token = self.server.state.request_token()
        deadline = time.monotonic() + self.server.request_timeout
        count, first, tail = 0, bytearray(), bytearray()
        first_done = False
        try:
            while count < 32768:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                self.request.settimeout(remaining)
                # No read-ahead into a body; retain no header values, only the
                # bounded first line and last four terminator bytes.
                byte = self.request.recv(1)
                if not byte:
                    raise OSError('incomplete-request')
                count += 1
                if not first_done:
                    if len(first) < 2049:
                        first.extend(byte)
                    if byte == b'\n':
                        first_done = True
                tail.extend(byte)
                del tail[:-4]
                if tail == b'\r\n\r\n' or tail[-2:] == b'\n\n':
                    break
            else:
                raise OSError('header-limit')
            pieces = bytes(first).split(b' ', 2) if first_done and len(first) <= 2048 else []
            method = 'GET' if len(pieces) == 3 and pieces[0] == b'GET' else 'other'
            path = pieces[1].split(b'?', 1)[0] if len(pieces) == 3 else b''
            whitelisted = path == CONFIG_PATH.encode('ascii')
            self.request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            self.server.emit({'event': 'http-observation', 'method': method,
                              'path': CONFIG_PATH if whitelisted else 'unlisted',
                              'request_bytes_read': count, 'status': 503})
            if method == 'GET' and whitelisted:
                self.server.state.observe_http(token)
        except (OSError, TimeoutError):
            self.server.emit({'event': 'incomplete-local-request', 'request_bytes_read': count})


class ProbeServer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_timeout = 2.0


def close_listener(server, thread):
    """Stop accepting and drain every bounded request worker before log close."""
    server.shutdown()
    thread.join()
    server.server_close()


class ProbeRunner:
    MAX_GENERATIONS = 3
    MAX_ATTEMPTS = 9
    ATTEMPTS_PER_PID = 3

    def __init__(self, device, frida, target, source, state, stop,
                 path_reader=process_path, validator=validate_target,
                 now=time.monotonic, sleep=time.sleep):
        self.device, self.frida, self.target, self.source = device, frida, target, source
        self.state, self.emit, self.stop = state, state.emit, stop
        self.path_reader, self.validator, self.now, self.sleep = path_reader, validator, now, sleep
        self.session = self.script = None
        self.generation = 0
        self.detached = threading.Event()
        self.closing = set()
        self.attempts = {}
        self.total_attempts = self.enumeration_failures = 0
        self.retryable = tuple(getattr(frida, name) for name in
                               ('ProcessNotFoundError', 'PermissionDeniedError', 'TransportError'))

    def close_session(self):
        generation, script, session = self.generation, self.script, self.session
        self.script = self.session = None
        self.closing.add(generation)
        if session is not None:
            self.state.detach(generation)
        okay = True
        for obj, method in ((script, 'unload'), (session, 'detach')):
            if obj is None:
                continue
            try:
                getattr(obj, method)()
            except (self.frida.InvalidOperationError, self.frida.ProcessNotFoundError):
                pass
            except Exception:
                okay = False
                self.emit({'event': 'cleanup-operation-failed', 'operation': method})
        return okay

    def _detached(self, generation, *_):
        if generation in self.closing or generation != self.generation:
            return
        self.state.detach(generation)
        self.detached.set()

    def step(self):
        if self.session is not None:
            if not self.detached.is_set():
                return
            if not self.close_session():
                self.state.fail('session-cleanup-failed')
                return
        if self.generation >= self.MAX_GENERATIONS:
            self.state.fail('session-generation-limit')
            return
        if self.total_attempts >= self.MAX_ATTEMPTS:
            self.state.fail('attach-attempt-limit')
            return
        try:
            processes = self.device.enumerate_processes()
        except self.retryable:
            self.enumeration_failures += 1
            self.emit({'event': 'process-enumeration-retry', 'attempt': self.enumeration_failures})
            if self.enumeration_failures >= 3:
                self.state.fail('process-enumeration-failed')
            return
        for proc in processes:
            if proc.name.lower() != 'settlers7r.exe' or self.path_reader(proc.pid) != self.target:
                continue
            if self.attempts.get(proc.pid, 0) >= self.ATTEMPTS_PER_PID:
                continue
            self.validator(self.target)
            self.attempts[proc.pid] = self.attempts.get(proc.pid, 0) + 1
            self.total_attempts += 1
            try:
                session = self.device.attach(proc.pid)
            except self.retryable:
                # Includes VirtualAllocEx/access-denied TransportError. Never
                # serialize exception text or attach by process name alone.
                self.emit({'event': 'attach-retry', 'attempt': self.total_attempts,
                           'pid_attempt': self.attempts[proc.pid]})
                self.sleep(0.5)
                return
            self.session = session
            self.detached.clear()
            self.generation = generation = self.state.attach()
            session.on('detached', lambda *args: self._detached(generation, *args))
            try:
                self.script = session.create_script(self.source)
                self.script.on('message', lambda message, _: self.state.message(generation, message))
                self.script.load()
            except self.retryable:
                # The launcher can end the process after attach but before the
                # script has loaded. Reset this generation before trying again.
                self.emit({'event': 'session-initialization-interrupted', 'generation': generation})
                self._detached(generation)
            except self.frida.InvalidOperationError:
                if session.is_detached:
                    self._detached(generation)
                if not self.detached.is_set():
                    raise
                # Only retry an invalid operation when the detached callback
                # or Frida's session status confirms it ended during setup.
                self.emit({'event': 'session-initialization-interrupted', 'generation': generation})
            return

    def run(self, seconds):
        deadline = self.now() + max(1, min(seconds, 900))
        result = 2
        try:
            self.emit({'event': 'watcher-ready', 'scope': 'exact-authorized-process-path'})
            while self.now() < deadline and not self.stop.is_set():
                self.step()
                outcome = self.state.outcome()
                if outcome is not None:
                    result = outcome
                    break
                self.sleep(0.05)
            if self.stop.is_set():
                result = 130
        except KeyboardInterrupt:
            self.stop.set()
            result = 130
        except Exception:
            self.state.fail('watcher-or-script-load-failed')
            result = 3
        finally:
            cleanup_okay = self.close_session()
            if not cleanup_okay:
                result = 3
            if result == 130:
                self.emit({'event': 'probe-interrupted'})
            elif result == 2:
                self.emit({'event': 'redirection-not-completed' if self.state.hook_only else 'routing-not-observed'})
            self.emit({'event': 'hook-session-cleanup-complete' if cleanup_okay else 'hook-session-cleanup-incomplete'})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True, help='Exact executable path of the user-authorized test process')
    parser.add_argument('--module-dir', type=Path, required=True, help='Directory containing the installed frida Python module')
    parser.add_argument('--log', type=Path, required=True, help='Local scratch JSONL file, outside the repository')
    parser.add_argument('--seconds', type=int, default=300, help='Total maximum listener/watcher duration')
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--hook-only', action='store_true',
                        help='Only redirect and wait for constructor return; do not bind or observe HTTP')
    options = parser.parse_args()
    target = options.target.resolve(strict=True)
    if target.name.lower() != 'settlers7r.exe':
        raise ValueError('unexpected-executable-name')
    validate_target(target)
    if options.validate_only:
        print(json.dumps({'event': 'target-file-verified', 'sha256': EXPECTED_SHA, 'arch': 'ia32'}), flush=True)
        return 0
    sys.path.insert(0, str(options.module_dir.resolve(strict=True)))
    import frida  # Optional for importing and running stdlib tests.
    source = Path(__file__).with_suffix('.js').read_text(encoding='utf8')
    source = source.replace('__TARGET_PATH_JSON__', json.dumps(str(target)))
    options.log.parent.mkdir(parents=True, exist_ok=True)
    lock, stop = threading.Lock(), threading.Event()
    previous_signals = {}
    for name in ('SIGINT', 'SIGBREAK'):
        signum = getattr(signal, name, None)
        if signum is not None:
            previous_signals[signum] = signal.signal(signum, lambda *_: stop.set())
    try:
        with options.log.open('a', encoding='utf8') as log:
            def emit(data):
                line = json.dumps(data, ensure_ascii=True)
                with lock:
                    log.write(line + '\n')
                    log.flush()
                    print(line, flush=True)
            state = RoutingState(emit, hook_only=options.hook_only)
            if options.hook_only:
                emit({'event': 'hook-only-mode', 'http_listener': False})
                runner = ProbeRunner(frida.get_local_device(), frida, target, source, state, stop)
                return runner.run(options.seconds)
            server = ProbeServer(('127.0.0.1', 9110), ProbeHandler)
            server.emit, server.state = emit, state
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05})
            thread.start()
            try:
                emit({'event': 'listener-ready', 'address': '127.0.0.1', 'port': 9110, 'response_status': 503})
                runner = ProbeRunner(frida.get_local_device(), frida, target, source, state, stop)
                result = runner.run(options.seconds)
            finally:
                close_listener(server, thread)
                emit({'event': 'listener-closed-and-workers-joined'})
            return result
    finally:
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
