# Local S7 development handoff

Updated 2026-10-26. Baseline implementation commit: `b94c978`.

## Verified

The separate History Edition test copy reaches the main menu directly without
Ubisoft Connect, startup movies or a click gate. The user confirmed this.
The native adapter establishes a genuine local Login/Register exchange and
the service acknowledges keepalives beyond three minutes. The real connected
state now enables the multiplayer menu. The user opened an empty session list.

The last native change passed 218 checks and 14 original-byte guard checks,
plus configuration validation. The keepalive service passed 612 checks.
These are separate results, not evidence of a playable LAN match.

## Current blocker: discovery does not reach the server

A bounded observer saw seven online discovery requests and seven calls to the
native session-search function. The LAN discovery path was not called.
The search returns at its NAT/network-readiness gate before sending an RPC.
Therefore the empty session list is not a successful empty server response.

Static addresses below refer only to the SHA-256-guarded original executable
documented in `NATIVE-LOCAL-START.md` (preferred image base `0x400000`):

- Online path: `EDA550 -> EF83A0 -> EFD410 -> ED2710 -> ED6C00`.
- `ED6C00` passes the replaced login query at `ED6C2B`, then calls `ED7270`
  at `ED6C3A`. The latter returns false in the observed run.
- `ED7270` reaches `C8FFD0` on the network owner (`Network + 0xA18`).
- `C8FFD0` first checks owner byte `+0x3A`, then the actual RendezVous
  connected state, then a conditional dependency involving `+0x249/+0x25C`.
- A bounded static scan found a write to owner `+0x3A` at `C927C2`, from a
  virtual `+0x14` result. Investigate its enclosing initializer and the actual
  dependency. Do not simply force the readiness flag true.

The native update bridge and real connection state must remain intact.
The SDK-level Ubisoft readiness predicate is not globally patched.
Next milestones are real discovery RPC handling, session creation/joining,
and only then a two-client match test. Full network isolation and LAN are
still unverified. Existing experiments allow loopback only.

### Core-update bridge: live verification

A subsequent live run confirmed real RV connectivity but zero calls to the
outer network update `ED7950`, core update `CBC710`, or network-result callback
`C92600` during 20 seconds. The owner received 319 bridge ticks and four search
calls. Owner `+0x1C` was null; master `+0x4C4` and owner `+0x18/+0x3A` were zero.
The master already referenced the core; the core and implementation tables
were `10940A0` and `1099548`, respectively.

The prepared adapter adds guarded master dispatch `ED3BA0` followed by core
update `CBC710(..., 3)`, matching their relative order in `ED7950`. It retains
the existing owner fallback only if no owner callback ran. Synthetic tests
cover recursive entry, ordering, duplicate suppression, incomplete objects
and teardown at master, core and owner callback boundaries. It passed 147 bootstrap checks,
88 platform checks, 18 connection-state checks, 38 network-guard checks,
14 original-byte comparisons and the real configuration/fingerprint rejection
test. The candidate was deployed after the user closed S7, retaining the previous
adapter as `LocalData/adapter-b94c978.dll`; all bundle hashes and the no-game-launch
preflight passed. One configuration-fixture run timed out without service output;
a repeat passed. The user then opened the session list with the new adapter.

Two bounded live observations counted 636/632 core updates and 318/316 owner
updates per 20 seconds. Local Login/Register and keepalives remained active.
The core scheduler returned success (1). Master start `C8F9D0`, its completion
`C917A0`, and network event `C92600` remained at zero. Master child count was
four, master flags `+0x4C4..+0x4C8` were `[0,0,0,1,0]`; owner attachment/readiness
remained false. Thus core dispatch works, but startup/discovery is not solved.
Next inspect the native command queue: startup completion attaches each child
and only then marks the master started. Do not replace that with flag writes.

## Local workspace (not portable paths)

The containing output directory holds `S7-Local.code-workspace` and the separate
`S7-Local-Test` bundle. User launcher: `Test-Lokale-Anmeldung.cmd` inside that
bundle. The launcher creates fresh local service/configuration state each run.
Its active keepalive peer has a 20-minute hard limit and a two-minute idle limit.
Do not assume an old game process still has a usable service session.

The chat workspace's `work/` contains the private static analysis scripts,
bounded observers, SDK and compiler outputs. It is outside this repository.
Latest adapter with live core-update verification: `work/native-core-build`.
Previous menu-only bridge build: `work/native-menu-build`.
The original installation is `C:/Spiele/thesettlers7` and must remain unchanged.

## TokenSave

Initialized and queried successfully on 2026-10-26 using TokenSave 7.15.0.
The initial index contains 80 source/artifact files and 1,587 symbols.
Use an absolute `graph_root` for MCP queries. `tokensave sync` refreshes local
changes; the index is ignored by Git. No global settings or Git hooks were
installed. No Cairn journal was initialized.

The existing workspace file opens the repository. Registering its folder in
the Codex project sidebar is a separate UI step; this chat can already work
on the repository and query its TokenSave index.
