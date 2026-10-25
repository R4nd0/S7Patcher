"""Stdlib-only tests: fake Frida sessions, local sockets; never attach to a game."""
import http.client
import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from loopback_probe import (CONFIG_PATH, SCRIPT_FAILURE_CODES, ProbeHandler, ProbeRunner, ProbeServer, main,
                            RoutingState, close_listener, validate_target)


def send(state, generation, event, **values):
    state.message(generation, {'type': 'send', 'payload': {'event': event, **values}})


def arm(state):
    generation = state.attach()
    send(state, generation, 'hook-ready', arch='ia32')
    send(state, generation, 'sandbox-redirected')
    return generation


class RoutingStateTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.state = RoutingState(self.events.append)

    def test_requires_full_order_and_live_session(self):
        self.assertFalse(self.state.observe_http(self.state.request_token()))
        gen = self.state.attach()
        self.assertFalse(self.state.observe_http(self.state.request_token()))
        send(self.state, gen, 'hook-ready', arch='ia32')
        early = self.state.request_token()
        send(self.state, gen, 'sandbox-redirected')
        self.assertFalse(self.state.observe_http(early))
        self.assertTrue(self.state.observe_http(self.state.request_token()))
        self.assertEqual(self.state.outcome(), 0)
        self.assertEqual(self.events[-1]['claim'], 'temporal-correlation-only-request-source-unverified')
        self.state.detach(gen)
        self.assertIsNone(self.state.outcome())

    def test_old_request_and_callbacks_cannot_arm_replacement(self):
        old = arm(self.state)
        token = self.state.request_token()
        self.state.detach(old)
        new = self.state.attach()
        send(self.state, old, 'hook-ready', arch='ia32')
        send(self.state, old, 'sandbox-redirected')
        self.assertIsNone(self.state.request_token())
        self.assertFalse(self.state.observe_http(token))
        send(self.state, new, 'hook-ready', arch='ia32')
        send(self.state, new, 'sandbox-redirected')
        self.assertFalse(self.state.observe_http(token))
        self.assertTrue(self.state.observe_http(new))

    def test_script_error_invalidates_success_without_leaking_error(self):
        gen = arm(self.state)
        self.state.observe_http(gen)
        self.state.message(gen, {'type': 'error', 'description': 'test-secret-stack'})
        self.assertEqual(self.state.outcome(), 3)
        self.assertFalse(self.state.observe_http(gen))
        self.assertNotIn('test-secret', json.dumps(self.events))

    def test_redirect_before_ready_and_wrong_arch_fail_closed(self):
        for payload in ({'event': 'sandbox-redirected'}, {'event': 'hook-ready', 'arch': 'x64'}):
            state = RoutingState(self.events.append)
            state.message(state.attach(), {'type': 'send', 'payload': payload})
            self.assertEqual(state.outcome(), 3)

    def test_known_script_validation_codes_are_terminal_and_redacted(self):
        for code in SCRIPT_FAILURE_CODES:
            with self.subTest(code=code):
                events = []
                state = RoutingState(events.append, hook_only=True)
                gen = state.attach()
                send(state, gen, 'hook-validation-failed', code=code,
                     stack='test-secret-stack', url='test-secret-url')
                send(state, gen, 'hook-ready', arch='ia32')
                self.assertEqual(state.outcome(), 3)
                self.assertEqual(events[-1]['reason'], 'script-' + code)
                self.assertNotIn('test-secret', json.dumps(events))
                self.assertFalse(state.ready)

    def test_unrecognized_script_failure_is_not_echoed(self):
        for code in ('prologue-mismatch?test-secret', {'test-secret': 1}, None):
            state = RoutingState(self.events.append)
            send(state, state.attach(), 'hook-validation-failed', code=code)
            self.assertEqual(state.outcome(), 3)
            self.assertEqual(self.events[-1]['reason'], 'script-unclassified-validation-failure')
        self.assertNotIn('test-secret', json.dumps(self.events))

    def test_hook_ready_path_validation_is_whitelisted(self):
        for value in ('native-exact', 'native-file-identity', 'test-secret-path', {'test-secret': 1}, None):
            with self.subTest(value=value):
                events = []
                state = RoutingState(events.append)
                send(state, state.attach(), 'hook-ready', arch='ia32', path_validation=value)
                self.assertTrue(state.ready)
                if type(value) is str and value in ('native-exact', 'native-file-identity'):
                    self.assertEqual(events[-1]['path_validation'], value)
                else:
                    self.assertNotIn('path_validation', events[-1])
                self.assertNotIn('test-secret', json.dumps(events))

    def test_duplicate_detach_is_idempotent(self):
        gen = self.state.attach()
        self.state.detach(gen)
        self.state.detach(gen)
        self.assertEqual(sum(e['event'] == 'session-detached' for e in self.events), 1)


class RoutingObserverTests(unittest.TestCase):
    def request(self, path, ready=False):
        events = []
        state = RoutingState(events.append)
        if ready:
            arm(state)
        server = ProbeServer(('127.0.0.1', 0), ProbeHandler)
        server.emit, server.state = events.append, state
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            connection = http.client.HTTPConnection(*server.server_address, timeout=3)
            connection.request('GET', path, headers={'Authorization': 'test-secret-header', 'Cookie': 'test-secret-cookie'})
            response = connection.getresponse()
            status, body = response.status, response.read()
            connection.close()
        finally:
            close_listener(server, thread)
        return status, body, events, state.outcome()

    def test_config_request_returns_503_and_redacts_headers_and_query(self):
        status, body, events, outcome = self.request(CONFIG_PATH+'?ticket=test-secret-query', ready=True)
        self.assertEqual((status, body, outcome), (503, b'', 0))
        observed = next(event for event in events if event['event'] == 'http-observation')
        self.assertEqual(observed['path'], CONFIG_PATH)
        self.assertGreater(observed['request_bytes_read'], 0)
        serialized = json.dumps(events)
        for forbidden in ('test-secret', 'Authorization', 'Cookie', 'ticket=', '?'):
            self.assertNotIn(forbidden, serialized)

    def test_unsolicited_allowed_route_is_not_success(self):
        self.assertIsNone(self.request(CONFIG_PATH)[3])

    def test_other_path_is_not_logged_and_does_not_count_as_routing(self):
        status, _, events, outcome = self.request('/test-secret-path?test-secret-query', ready=True)
        self.assertEqual(status, 503)
        self.assertIsNone(outcome)
        self.assertNotIn('test-secret', json.dumps(events))
        self.assertEqual(events[-1]['path'], 'unlisted')

    def test_shutdown_joins_inflight_worker_before_log_close(self):
        events, started, closed = [], threading.Event(), threading.Event()
        def emit(event):
            self.assertFalse(closed.is_set(), 'worker wrote after log closed')
            events.append(event)
        class SignalingHandler(ProbeHandler):
            def handle(self):
                started.set()
                super().handle()
        server = ProbeServer(('127.0.0.1', 0), SignalingHandler)
        server.emit, server.state, server.request_timeout = emit, RoutingState(emit), 0.15
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        client = socket.create_connection(server.server_address, timeout=2)
        client.sendall(b'GET /incomplete HTTP/1.1\r\n')
        self.assertTrue(started.wait(1))
        close_listener(server, thread)
        closed.set()
        client.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(events[-1]['event'], 'incomplete-local-request')
        self.assertTrue(all(not worker.is_alive() for worker in server._threads))

    def test_unrecognized_binary_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'Settlers7R.exe'
            target.write_bytes(b'not-a-game-executable')
            with self.assertRaisesRegex(ValueError, 'target-sha256-mismatch'):
                validate_target(target)


class HookOnlyStateTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.state = RoutingState(self.events.append, hook_only=True)
        self.generation = self.state.attach()
        send(self.state, self.generation, 'hook-ready', arch='ia32')

    def test_redirect_without_return_cannot_succeed_or_claim_http(self):
        send(self.state, self.generation, 'sandbox-redirected', count=1)
        self.assertIsNone(self.state.outcome())
        self.assertIsNone(self.state.request_token())
        self.assertFalse(self.state.observe_http(self.generation))
        self.assertFalse(any(e['event'] == 'routing-correlated' for e in self.events))
        send(self.state, self.generation, 'sandbox-call-finished', count=1)
        self.assertEqual(self.state.outcome(), 0)
        self.assertEqual(self.events[-1]['event'], 'redirection-completed')
        self.assertEqual(self.events[-1]['claim'], 'hook-only-constructor-returned-no-server-or-login-claim')

    def test_every_inflight_invocation_must_return(self):
        for call in (1, 2):
            send(self.state, self.generation, 'sandbox-redirected', count=call)
        send(self.state, self.generation, 'sandbox-call-finished', count=1)
        self.assertIsNone(self.state.outcome())
        send(self.state, self.generation, 'sandbox-call-finished', count=2)
        self.assertEqual(self.state.outcome(), 0)

    def test_finish_without_matching_redirect_fails_closed(self):
        send(self.state, self.generation, 'sandbox-call-finished', count=1)
        self.assertEqual(self.state.outcome(), 3)

    def test_wrong_invocation_or_script_error_is_terminal(self):
        send(self.state, self.generation, 'sandbox-redirected', count=1)
        send(self.state, self.generation, 'sandbox-call-finished', count=2)
        self.assertEqual(self.state.outcome(), 3)
        send(self.state, self.generation, 'sandbox-call-finished', count=1)
        self.assertEqual(self.state.outcome(), 3)
        state = RoutingState(self.events.append, hook_only=True)
        gen = state.attach()
        send(state, gen, 'hook-ready', arch='ia32')
        send(state, gen, 'sandbox-redirected', count=1)
        state.message(gen, {'type': 'error', 'description': 'test-secret'})
        send(state, gen, 'sandbox-call-finished', count=1)
        self.assertEqual(state.outcome(), 3)
        self.assertNotIn('test-secret', json.dumps(self.events))

    def test_old_generation_return_cannot_complete_new_session(self):
        send(self.state, self.generation, 'sandbox-redirected', count=1)
        self.state.detach(self.generation)
        new = self.state.attach()
        send(self.state, new, 'hook-ready', arch='ia32')
        send(self.state, new, 'sandbox-redirected', count=1)
        send(self.state, self.generation, 'sandbox-call-finished', count=1)
        self.assertIsNone(self.state.outcome())
        send(self.state, new, 'sandbox-call-finished', count=1)
        self.assertEqual(self.state.outcome(), 0)

    def test_hook_only_cli_never_constructs_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'Settlers7R.exe'
            target.touch()
            log = Path(directory)/'probe.jsonl'
            argv = ['loopback_probe', '--target', str(target), '--module-dir', directory,
                    '--log', str(log), '--hook-only']
            frida = SimpleNamespace(get_local_device=lambda: object())
            with mock.patch.object(sys, 'argv', argv), mock.patch.dict(sys.modules, {'frida': frida}), \
                    mock.patch('loopback_probe.validate_target'), \
                    mock.patch('loopback_probe.ProbeServer', side_effect=AssertionError('unexpected-listener')), \
                    mock.patch('loopback_probe.ProbeRunner') as runner, contextlib.redirect_stdout(io.StringIO()):
                runner.return_value.run.return_value = 0
                self.assertEqual(main(), 0)
                self.assertTrue(runner.call_args.args[4].hook_only)
            self.assertNotIn('listener-ready', log.read_text())
            self.assertIn('hook-only-mode', log.read_text())


class ProcessNotFoundError(Exception): pass
class PermissionDeniedError(Exception): pass
class TransportError(Exception): pass
class InvalidOperationError(Exception): pass
FAKE_FRIDA = SimpleNamespace(ProcessNotFoundError=ProcessNotFoundError,
                             PermissionDeniedError=PermissionDeniedError,
                             TransportError=TransportError,
                             InvalidOperationError=InvalidOperationError)


class FakeScript:
    def __init__(self, on_load=None, unload_error=False):
        self.callback = None
        self.on_load = on_load
        self.unloaded = False
        self.unload_error = unload_error
    def on(self, event, callback):
        assert event == 'message'
        self.callback = callback
    def load(self):
        if self.on_load:
            self.on_load(self)
    def send(self, event, **payload):
        self.callback({'type': 'send', 'payload': {'event': event, **payload}}, None)
    def unload(self):
        self.unloaded = True
        if self.unload_error:
            raise TransportError('test-secret-cleanup-error')


class FakeSession:
    def __init__(self, script):
        self.script, self.callback = script, None
        self.detach_called = False
        self.is_detached = False
    def on(self, event, callback):
        assert event == 'detached'
        self.callback = callback
    def create_script(self, _):
        return self.script
    def detach(self):
        self.detach_called = True
        self.is_detached = True
        self.callback('application-requested')
    def disappear(self):
        self.is_detached = True
        self.callback('process-terminated')


class FakeDevice:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = []
        self.pid = 10
    def enumerate_processes(self):
        return [SimpleNamespace(name='Settlers7R.exe', pid=self.pid)]
    def attach(self, pid):
        self.calls.append(pid)
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


class FakeClock:
    def __init__(self):
        self.value = 0
        self.callback = None
    def now(self): return self.value
    def sleep(self, amount):
        self.value += amount
        if self.callback:
            self.callback()


class LifecycleTests(unittest.TestCase):
    def make_runner(self, actions, hook_only=False):
        events, clock, stop = [], FakeClock(), threading.Event()
        state = RoutingState(events.append, hook_only=hook_only)
        device = FakeDevice(actions)
        target = Path('authorized/Settlers7R.exe')
        runner = ProbeRunner(device, FAKE_FRIDA, target, 'guarded source', state, stop,
                             path_reader=lambda _: target, validator=lambda _: None,
                             now=clock.now, sleep=clock.sleep)
        return runner, state, device, clock, events, stop

    def test_transient_access_and_missing_process_retry_then_correlate(self):
        session = FakeSession(FakeScript())
        runner, state, device, _, events, _ = self.make_runner([
            PermissionDeniedError('secret'), TransportError('VirtualAllocEx secret'), session])
        def loaded(script):
            script.send('hook-ready', arch='ia32')
            script.send('sandbox-redirected')
            state.observe_http(state.request_token())
        session.script.on_load = loaded
        self.assertEqual(runner.run(5), 0)
        self.assertEqual(len(device.calls), 3)
        self.assertTrue(session.script.unloaded and session.detach_called)
        self.assertNotIn('secret', json.dumps(events))

    def test_process_not_found_attempts_are_bounded_per_pid(self):
        runner, _, device, _, events, _ = self.make_runner([ProcessNotFoundError('secret')]*3)
        self.assertEqual(runner.run(5), 2)
        self.assertEqual(len(device.calls), 3)
        self.assertEqual(sum(e['event'] == 'attach-retry' for e in events), 3)

    def test_detach_resets_flags_and_reattaches_new_generation(self):
        first, second = FakeSession(FakeScript()), FakeSession(FakeScript())
        runner, state, device, clock, _, _ = self.make_runner([first, second])
        first.script.on_load = lambda script: (script.send('hook-ready', arch='ia32'), script.send('sandbox-redirected'))
        def change_process():
            if runner.generation == 1:
                first.disappear()
                device.pid = 11
        clock.callback = change_process
        def loaded(script):
            self.assertFalse(state.redirected)
            self.assertIsNone(state.request_token())
            self.assertFalse(state.observe_http(1))
            first.script.send('sandbox-redirected')  # delayed obsolete callback
            self.assertFalse(state.redirected)
            script.send('hook-ready', arch='ia32')
            script.send('sandbox-redirected')
            state.observe_http(state.request_token())
        second.script.on_load = loaded
        self.assertEqual(runner.run(5), 0)
        self.assertEqual(device.calls, [10, 11])
        self.assertEqual(runner.generation, 2)
        self.assertTrue(first.detach_called and second.detach_called)

    def test_three_generations_is_a_hard_limit(self):
        sessions = [FakeSession(FakeScript()) for _ in range(3)]
        runner, _, device, clock, _, _ = self.make_runner(sessions)
        def disappear():
            if runner.session is not None:
                runner.session.disappear()
                device.pid += 1
        clock.callback = disappear
        self.assertEqual(runner.run(10), 3)
        self.assertEqual(len(device.calls), 3)

    def test_nine_total_attempts_is_a_hard_limit(self):
        runner, _, device, clock, _, _ = self.make_runner([TransportError('secret')]*9)
        clock.callback = lambda: setattr(device, 'pid', device.pid+1)
        self.assertEqual(runner.run(20), 3)
        self.assertEqual(len(device.calls), 9)

    def test_script_validation_error_is_terminal_and_redacted(self):
        session = FakeSession(FakeScript(lambda s: s.callback({'type': 'error', 'stack': 'secret'}, None)))
        runner, _, device, _, events, _ = self.make_runner([session])
        self.assertEqual(runner.run(10), 3)
        self.assertEqual(len(device.calls), 1)
        self.assertTrue(session.script.unloaded and session.detach_called)
        self.assertNotIn('secret', json.dumps(events))

    def test_module_and_prologue_failures_are_not_retried(self):
        for code in ('module-not-ready', 'prologue-mismatch'):
            session = FakeSession(FakeScript(lambda s: s.send('hook-validation-failed', code=code)))
            runner, _, device, _, events, _ = self.make_runner([session], hook_only=True)
            self.assertEqual(runner.run(5), 3)
            self.assertEqual(len(device.calls), 1)
            self.assertTrue(session.script.unloaded and session.detach_called)
            self.assertIn('script-' + code, [e.get('reason') for e in events])

    def test_process_disappearing_during_script_load_retries_new_generation(self):
        def vanish(_):
            raise ProcessNotFoundError('test-secret-race')
        first, second = FakeSession(FakeScript(vanish)), FakeSession(FakeScript())
        runner, state, _, _, events, _ = self.make_runner([first, second])
        def loaded(script):
            script.send('hook-ready', arch='ia32')
            script.send('sandbox-redirected')
            state.observe_http(state.request_token())
        second.script.on_load = loaded
        self.assertEqual(runner.run(5), 0)
        self.assertEqual(runner.generation, 2)
        self.assertTrue(first.detach_called and second.detach_called)
        self.assertNotIn('test-secret', json.dumps(events))

    def test_keyboard_interrupt_and_stop_event_clean_up(self):
        for keyboard in (True, False):
            session = FakeSession(FakeScript())
            runner, _, _, clock, events, stop = self.make_runner([session])
            def interrupt():
                if keyboard:
                    raise KeyboardInterrupt
                stop.set()
            clock.callback = interrupt
            self.assertEqual(runner.run(5), 130)
            self.assertTrue(session.script.unloaded and session.detach_called)
            self.assertEqual(events[-1]['event'], 'hook-session-cleanup-complete')

    def test_invalid_operation_retries_only_after_confirmed_detach(self):
        for confirmed in ('callback', 'status', None):
            first, second = FakeSession(FakeScript()), FakeSession(FakeScript())
            runner, state, device, _, _, _ = self.make_runner([first, second])
            def vanished(_):
                if confirmed == 'callback':
                    first.disappear()
                elif confirmed == 'status':
                    first.is_detached = True
                raise InvalidOperationError('test-secret')
            first.script.on_load = vanished
            def loaded(script):
                script.send('hook-ready', arch='ia32')
                script.send('sandbox-redirected')
                state.observe_http(state.request_token())
            second.script.on_load = loaded
            self.assertEqual(runner.run(5), 0 if confirmed else 3)
            self.assertEqual(len(device.calls), 2 if confirmed else 1)

    def test_unload_error_does_not_skip_detach(self):
        session = FakeSession(FakeScript(unload_error=True))
        runner, _, _, _, events, _ = self.make_runner([session])
        self.assertEqual(runner.run(1), 3)
        self.assertTrue(session.detach_called)
        self.assertNotIn('test-secret', json.dumps(events))
        self.assertEqual(events[-1]['event'], 'hook-session-cleanup-incomplete')

    def test_wrong_path_is_never_attached(self):
        runner, _, device, _, _, _ = self.make_runner([])
        runner.path_reader = lambda _: Path('different/Settlers7R.exe')
        self.assertEqual(runner.run(1), 2)
        self.assertEqual(device.calls, [])

    def test_hook_only_success_keeps_script_alive_until_constructor_returns(self):
        session = FakeSession(FakeScript())
        runner, _, _, clock, events, _ = self.make_runner([session], hook_only=True)
        def loaded(script):
            script.send('hook-ready', arch='ia32')
            script.send('sandbox-redirected', count=1)
        session.script.on_load = loaded
        def returned():
            self.assertFalse(session.script.unloaded)
            self.assertFalse(session.detach_called)
            session.script.send('sandbox-call-finished', count=1)
            clock.callback = None
        clock.callback = returned
        self.assertEqual(runner.run(5), 0)
        self.assertTrue(session.script.unloaded and session.detach_called)
        names = [event['event'] for event in events]
        self.assertLess(names.index('redirection-completed'), names.index('session-detached'))
        self.assertNotIn('routing-correlated', names)

    def test_hook_only_without_constructor_return_times_out(self):
        session = FakeSession(FakeScript())
        runner, _, _, _, events, _ = self.make_runner([session], hook_only=True)
        session.script.on_load = lambda script: (script.send('hook-ready', arch='ia32'),
                                                 script.send('sandbox-redirected', count=1))
        self.assertEqual(runner.run(1), 2)
        self.assertIn('redirection-not-completed', [event['event'] for event in events])
        self.assertNotIn('redirection-completed', [event['event'] for event in events])


if __name__ == '__main__':
    unittest.main()
