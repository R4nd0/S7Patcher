# Local S7 development handoff

Updated 2026-10-26. Baseline implementation commit: `b94c978`.

## Verified

The separate History Edition test copy reaches the main menu directly without
Ubisoft Connect, startup movies or a click gate. The user confirmed this.
The native adapter establishes a genuine local Login/Register exchange and
the service acknowledges keepalives beyond three minutes. The real connected
state now enables the multiplayer menu. The user opened an empty session list.

The current native change passed 335 adapter checks, 38 network-guard checks
and 17 original-byte comparisons, plus configuration validation. The
current search-capable service passes 1,924 checks.
These are separate results, not evidence of a playable LAN match.

## Current blocker: live verification of the empty search response

The SpaceId transfer and real `SearchSessions_V1` requests are live-verified.
The service now has a tested, bounded handler returning two genuinely empty
result collections. The game must still verify that response. Hosting,
joining, match startup and LAN transport remain unimplemented.

Earlier observations established the following startup/readiness blockers,
subsequently addressed by the scoped changes documented below.
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
The command queue was initialized but empty, with zero queue ticks. A further
read-only check found `Network + 0xA71 == 1`: startup is deliberately skipped.
The platform object at `13789D0` has table `112BE3C`; its `+0x28` method
`4C7CE0` returns the offline byte `+0x80`, populated from our intentionally true
`UPLAY_USER_IsInOfflineMode` result at `4C7F5A..4C7F65`. `ED480A` calls that
predicate and `ED4815..ED482C` skips the whole Startup ECHO sequence. This is
separate from actual transport readiness.

### Local-start policy: live verification

The next adapter replaces only the five-byte `MOV EAX,[EDX+28]; CALL EAX`
sequence at `ED480A` with a guarded local-start decision. With the probe enabled,
on the bootstrap thread and exact known platform instance, it allows the
original Startup ECHO job. Other inputs skip startup. It does not modify the
platform offline bit, Ubisoft session state, master attachment or NAT flags.
Original shutdown observes the resulting network startup policy normally.

Validation: 161 bootstrap, 88 platform, 18 connection-state and 38 network-guard
checks; 15 byte guards; real configuration/fingerprint rejection test all pass.
Build: `work/native-startup-build`. Deployed after the user closed S7, retaining
`LocalData/adapter-23123b5.dll`; bundle hash validation and no-game-launch preflight
passed. The user opened the session list. A three-minute early observer recorded
one master start request/completion with success (1), 5 network-result events,
2,886 command queue ticks and 5,812 core ticks. Network skip is 0, master started
and owner attached are 1. The actual local Login/Register connection persists.
Owner interface-present is 1 and its result is success (1), but readiness
`+0x3A` remains 0. No session search RPC reached the service yet. This change is
committed/pushed as `fafb4c2`; the earlier core bridge is `23123b5`.

### Local session-search policy: first live crash and deployed correction

The new candidate replaces only `ED6C3A` (the readiness check within session
search). It requires the real local connected/not-pending facade, current owned
network/core objects, bootstrap thread, configured UDP port, started master,
attached owner, interface presence, a successful network result and no optional
`+0x249` dependency. This is an explicit policy for the loopback search request,
not a claim that the native NAT status is ready. It changes no readiness flags,
other `ED7270` callers, hosting or joining. The exact underlying reason for
native readiness remaining false is still unresolved; it is not established
that it specifically denotes Internet reachability.

Build: `work/native-search-build`. Validation: 185 bootstrap, 88 platform,
18 connection-state, 38 network-guard checks, 16 original-byte checks and real
configuration/fingerprint validation pass. Candidate `ebd75de` was deployed after
the user closed S7 and the host process check confirmed it was stopped. The
previous adapter is retained as `LocalData/adapter-fafb4c2.dll`. Bundle hashes
and the no-game-launch preflight passed. The user reported an error/exit. The
bounded observer confirmed search entry and dispatch after successful native
startup, then process termination. Windows recorded access violation
`0xC0000005` at game offset `0x6B0E30` (`AB0E30`). The search helper calls
`D43F50`, which dereferences the null borrowed Ubi facade to obtain
`matchmakingSandboxName`. No search RPC reached the local service.

The correction adds one guarded call replacement at `C8DCC5`, returning a
fresh native inline small string with the same empty sandbox used for local
login. It checks local state, thread and RV ownership; the search gate also
requires the helper at owner `+108`. Validation: 211 bootstrap, 88 platform,
18 connection-state, 38 network-guard checks, 17 original-byte checks and the
real configuration/fingerprint test pass. Build: `work/native-search-sandbox-build`.
It is deployed after host confirmation that S7 exited; previous candidate is
retained as `LocalData/adapter-ebd75de.dll`. Bundle hashes and no-game-launch
preflight passed. The user opened the session list and repeated native search
dispatch returned without the previous configuration access violation.
The correction is committed as `bb7a733`.

### Search SpaceId: live verified

The native search job remained pending on four observations over 20 seconds;
no search RPC reached the service. Static inspection established that the
search helper's `+0x20` is the length of the native small string at `+0x10`,
not a connection pointer. `D4A300` rejects its empty SpaceId before RPC creation.
The normal initializer obtains configuration key `SpaceId` through `EF3430`
and invokes native setter `D4A860` (helper virtual `+0x84`). That setter also
updates the dependent `default_session_` name.

An additional observer later crashed inside `frida-agent.dll` with Windows
exception `0xC0000409`. This was a separate diagnostic-library failure, not
the original Ubisoft configuration crash. The user restarted successfully
without that observer. Do not inject Frida for the next test. The workspace
script `work/read_search_state.py` uses only Windows process/module queries
and ReadProcessMemory, with no hooks, writes or remote calls. It confirmed
the empty helper string and an existing public SpaceId at backend `+0xE4`.

`EnsureLocalSearchSpace` now validates current local ownership and the known
helper layout, then passes a bounded borrowed small-string view of that
existing public namespace to `D4A860`. The native setter copies through the
game's allocator. The borrowed view is never destroyed; credentials are not
read. Existing nonempty namespaces must match exactly and are not overwritten.
Ownership and the resulting string are checked again after the native call.
The fixed status event is `local-session-search-space-ready`; no ID is logged.

Validation: 229 bootstrap, 88 platform, 18 connection-state and 38 network-guard
checks; 17 original-byte comparisons; real configuration and wrong-executable
fingerprint rejection all pass. Build: `work/native-search-space-build`.
After the user closed S7, the candidate was deployed with the previous adapter
retained as `LocalData/adapter-bb7a733.dll`. All bundle hashes and the
no-game-launch preflight passed. Committed and pushed as `8d3bc91`.

The user subsequently opened the session list and left the test copy running.
The read-only snapshot confirmed connected=true, pending=false, helper SpaceId
length 36 and capacity 47, owner attached, and no injected diagnostic library.
The adapter logged `local-session-search-space-ready`. New encrypted DATA
messages decoded successfully (231-byte messages in the observed tail), but
were rejected as `response-budget-exhausted`. Their protocol/method is still
unknown at that stage; no real search response or multiplayer was verified.

The next service candidate classifies at most eight complete post-budget
messages per peer into fixed labels, including the statically identified
`MatchmakingProtocol::SearchSessions_V1`. It validates bounded RPC header
structure without decoding arguments or emitting IDs or unknown wire strings.
It does not increase the response budget or change keepalive/transport policy.

Validation: 617 full configuration-server checks and 20,214 codec assertions
(including 10,000 random inputs exercised by both header readers) pass.
The service builds without warnings. The separate bundle now retains the old
service and selects a hash-verified copy in `Server-Search-Diagnostic` through
`Test-Lokale-Anmeldung.cmd`; its prior launcher is backed up in LocalData.
The deployed service passed a two-second loopback startup/shutdown check on
ephemeral ports. The game EXE, adapter and UI hashes remain unchanged. A new
user-started game run is needed because the running launcher owns the old
service instance. That following run confirmed six exact
`matchmaking-search-sessions-v1` observations. The request is now identified.

The new service candidate validates the complete search argument shape and
returns an 82-byte response with an empty session list and empty result map.
Only the keepalive probe enables it, after both login responses are acknowledged.
Its separate 32-response cap and two-outstanding-packet window preserve the
baseline login budget, retry policy and session lifetime. Static anchors and
the 1,924-check validation are documented in `LOCAL-SESSION-SEARCH.md`.
Build: `work/empty-search-server`. Live game acceptance is still pending.
The candidate is deployed in the separate bundle's `Server-Empty-Search`
directory. The test launcher selects it, with the prior launcher retained as
`LocalData/Test-Lokale-Anmeldung-before-empty-search.cmd`. Service file hashes
match the build; all three game-bundle hashes are unchanged. A two-second
loopback startup/shutdown smoke check passed. The user has been asked to
restart through the test launcher and leave the session list open for a minute.

## Local workspace (not portable paths)

The containing output directory holds `S7-Local.code-workspace` and the separate
`S7-Local-Test` bundle. User launcher: `Test-Lokale-Anmeldung.cmd` inside that
bundle. The launcher creates fresh local service/configuration state each run.
Its active keepalive peer has a 20-minute hard limit and a two-minute idle limit.
Do not assume an old game process still has a usable service session.

The chat workspace's `work/` contains the private static analysis scripts,
bounded observers, SDK and compiler outputs. It is outside this repository.
Latest adapter with live startup verification: `work/native-startup-build`.
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
