# S7 History bootstrap routing probe

This is a research observer, **not a replacement multiplayer server**. By default it replies HTTP 503 and cannot create, find, join, or run a game. The ordinary Ubisoft/UbiServices initialization and login remain in place. Its HTTP result is a local bootstrap request temporally correlated with the guarded hook's redirect. The listener cannot prove which process sent that request. An optional hook-only mode leaves HTTP to an already running separate local service.

Use only a user-authorized test process. The Ubisoft launcher may replace a separately launched copy with the installed executable; the target must match the actual authorized process. The watcher never launches or stops a game. It checks the exact process executable path, the executable SHA256, PE32/ia32 architecture, and the target function's bytes on disk and in memory. It temporarily replaces one sandbox-selection argument with `localhost` and detaches after the observation or deadline. It never edits the executable on disk. The temporary hook is limited to the validated S7 History Ubisoft binary with SHA256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.

The observer binds only `127.0.0.1:9110`. It records GET/other, the whitelisted `/public/rendezvous/v1/configuration` path without its query, the bytes read, and response status. It discards headers without recording them, does not read the request body, and does not read account credentials or client caches. Keep the scratch log outside the repository. Do not add packet captures, game files, or authorization material to this project.

Requires Python, Frida's Python module, Windows, and sufficient access to attach to the test process. Example:

```powershell
python tools/research/loopback_probe.py --target "C:\path\to\authorized-game\Base\Bin\Settlers7R.exe" --module-dir "C:\path\to\python-libs" --log "C:\scratch\s7-routing.jsonl" --seconds 300
```

Wait for `listener-ready` and `watcher-ready`, then start the authorized game through its ordinary launcher. No interface/archive patch is required. `attached-to-authorized-process` precedes `hook-ready`, which confirms the in-memory guards and hook installation. Only `sandbox-redirected` followed by a whitelisted HTTP request in the same live session permits `routing-correlated`. An unsolicited request, a request already being read before the redirect, an old session's callback, or any script error cannot produce success. The source remains unverified; this is no authentication, multiplayer, or offline-play result.

The watcher polls every 50 ms and handles launcher process replacement. It allows at most three attach attempts per PID, nine attempts overall, and three successfully attached session generations. Process-not-found, permission-denied and Frida transport failures (including VirtualAllocEx access denied) are retried within those limits. Every detached session loses its previous readiness, redirect and request state. Script errors stop the probe; raw exception messages and script stacks are never logged. The sandbox identifier is read byte by byte, ASCII only, stopping at NUL within 15 bytes.

Hook setup reports only fixed, Python-whitelisted failure categories: architecture/path mismatch, module lookup failure, module not yet present, unreadable target memory, prologue mismatch, replacement allocation failure, or interceptor installation failure. The prefix is `script-`. Unknown script payloads and uncaught errors remain generic. Only a null result from Frida's documented `Process.findModuleByName` permits waiting: at most 40 lookups, spaced 50 ms apart, within a two-second window. No memory is read, replacement allocated or interceptor installed while the module is absent. Once present, the same exact path and byte guards run. Exhaustion reports `script-module-not-ready`; it does not establish that the earlier failure was a loader race. All other failures are immediately terminal, including lookup exceptions and unreadable or mismatched bytes. No guards are relaxed and no exception text, addresses, actual bytes, URLs or account values are logged. Duplicate detach notifications are suppressed.

The module wait uses one unpinned Frida script timer at a time. Unloading its script discards the pending callback; it does not keep a process or listener alive. The native argument-use pin is acquired only after an actual constructor invocation is redirected. Timer tests exercise delayed module appearance, the attempt/deadline limits, and unchanged guards after waiting using a mock scheduler; they do not establish Frida's native unloading behavior.

For an **already running separate configuration service**, add `--hook-only`:

```powershell
python tools/research/loopback_probe.py --target "C:\path\to\authorized-game\Base\Bin\Settlers7R.exe" --module-dir "C:\path\to\python-libs" --log "C:\scratch\s7-hook.jsonl" --seconds 300 --hook-only
```

This mode does not bind port 9110, start a service, read HTTP traffic, or produce `routing-correlated`. Wait for `hook-only-mode` and `watcher-ready`, then launch the authorized game normally. `redirection-completed` means the guarded constructor returned after consuming the replacement sandbox argument. It requires `hook-ready`, an actual redirect, and matching `sandbox-call-finished` callbacks for every in-flight redirected invocation in the same session. It does not establish any request, configuration acceptance, server login or working game. Inspect the separate service's limited logs independently.

Use ordinary Ctrl+C to request a cooperative stop. The probe unloads its script and detaches, stops accepting connections, and joins all HTTP workers before closing its log. Each request has a two-second total read deadline and a 32 KiB header limit. The log ends with `hook-session-cleanup-complete` and `listener-closed-and-workers-joined`; any `cleanup-operation-failed` means cleanup was not fully confirmed. Forced termination of the Python process can prevent these confirmations. The game is never terminated by the probe.

Each actually redirected invocation pins the Frida script until its `onLeave` callback unpins it, keeping the replacement string and wrapper alive during native argument use. This uses Frida's documented [Script lifetime API](https://frida.re/docs/javascript-api/#script). Cleanup requested during such an invocation waits for that invocation to return and can therefore extend beyond the watch deadline; do not interpret an absent cleanup confirmation as completion. Hook-only mode has no listener to close and ends with the hook-session cleanup event alone.

Exit codes are 0 for temporal correlation (default) or completed argument redirection (hook-only), 2 for no corresponding completion within the deadline, 3 for a validation/lifecycle/cleanup failure, and 130 for interruption. A timeout can mean initialization happened before attach; merely waiting after the initial connection does not necessarily invoke this constructor again. It does not prove the path is unavailable. Use `--validate-only` to check the executable without binding or attaching.

Run the stdlib-only tests without installing Frida:

```powershell
python -m unittest discover -s tools/research -p test_loopback_probe.py -v
node tools/research/test_loopback_probe_js.js
```

Tests use fake Frida sessions and short-lived localhost sockets. They check event ordering, stale-generation rejection, bounded retries/restarts, redaction, failure and interrupt cleanup, and draining a partially received request before log closure. Hook-only tests additionally verify that no listener is created, no HTTP claim can occur, every matching constructor-return event is required, and successful cleanup occurs after the return. The optional Node built-in-only suite executes the actual hook source against mock APIs to verify setup categories and fail-closed installation. They never start or attach to a game. These tests do not establish that the game's live bootstrap will occur after attach or exercise Frida's native pin/unpin implementation.

Evidence behind the selected hook: at preferred VA `0xE8A2A0`, argument5 is the sandbox-friendly-name string wrapper. The client compares it case-insensitively with `localhost`, then selects address127.0.0.1 and port9110. Code at `0xE8FE2D..0xE8FE46` builds the plain HTTP configuration URL. The UbiServices facade must already exist. Later authentication, cryptographic negotiation, PRUDP and matchmaking remain unimplemented here.
