# Local S7 development handoff

Updated 2026-10-26. Baseline implementation commit: `b94c978`.

## Verified

The separate History Edition test copy reaches the main menu directly without
Ubisoft Connect, startup movies or a click gate. The user confirmed this.
The native adapter establishes a genuine local Login/Register exchange and
the service acknowledges keepalives beyond three minutes. The real connected
state now enables the multiplayer menu. The user opened an empty session list.
With `95603b5`, the user also reached the created lobby with player slots.
Login, Register, search, create and update each received an acknowledged reply;
there were no rejected requests in that observed run. Match startup is not yet
verified, and no second-client LAN join has been implemented or tested.

The current native candidate passed 354 adapter checks, 38 network-guard checks
and 18 original-byte comparisons, plus configuration validation. The
current session-leave candidate passes 3,069 service checks; the unchanged
RPC codec previously passed 20,288 isolated assertions. Its UI archive verifies
all 284 entries and parses.
These are separate results, not evidence of a playable LAN match.

## Current step: nonempty catalogue and second-client join

### Current LAN transport candidate

See `TWO-PEER-LAN-TRANSPORT.md`. Explicit paired IPv4 service/native/launcher
support is implemented. Both roles are in `outputs/S7-LAN-Verbindungstest.zip`;
this is a catalogue experiment, not a playable join release. Build source:
`work/installer-package-lan-catalogue`, adapter `work/native-lan-build`, service
`work/server-two-peer-lan`. ZIP SHA256:
`07434eced4c9c884d19a8ea1dc376cd6d5fbc8f1c98ecf23e84fb05feff69c83`.
Adapter SHA256 `441dcb75fe925a44de302859dcaef3bedff5ad49f8831a73b6fb0d1c49d5ae9f`.

User closed S7; deployed into the separate copy with backups under
LocalData/Before-two-peer-lan. Portable Server/Launcher/Runtime now align with
the installer; compatibility.json describes the complete Base/Server/Launcher
inventory. No-game LAN preflight passed. User started Test-LAN-Host.cmd and
confirmed a public four-player lobby; live PID 46740, exact test path, native
LAN mode and connected, five responses acknowledged through Create/Update.
The runtime addresses remain private local configuration, never repository data.
Windows already has user-created Allow rules for this copy and its bundled
runtime; no firewall settings were changed by the agent.

The second PC still needs installation/discovery testing. Host's current
connection has the inherited 20-minute test lifetime. New launcher performs
cooperative pre-start content-ID comparison, not authenticated RPC admission.
Join and live match semantics are still missing. Keep progressing after testing.

### Real catalogue candidate (not yet selected by the game launcher)

`--local-catalogue-probe` enables public other-owner searches and GetSession
against live registry entries. Default mode and the display-only probe remain
separate. Search excludes self, applies space/limit and exact typed filters;
search_score is explicitly a ranking hint under this local policy. Missing or
true private metadata is hidden. GetSession requires the two versioned classes,
space and live ID and returns one native-layout record. No join is implemented.
The shared bounded writer preserves actual creation station URLs and member
metadata. Route ownership still needs validation before LAN game admission.

4,577 service checks passed, including encrypted independent participants in
both host directions, acknowledged search/Get replies, non-owner update
rejection and disappearance after owner leave. These are synthetic peers, not
Windows game clients. Candidate build: work/server-live-catalogue. Existing
launchers still select Server-Session-Leave. The confirmed campaign/CPU package
is outputs/S7-Patch-Installer-Freischaltungen.zip (local preview, no LAN).

### Content / four physical cores milestone

The user also requested all unlocks and the upstream patches, including four
cores without SMT. See `CONTENT-CPU-PATCHES.md` for the variant-specific audit.
The guarded adapter now includes the exact upstream HE development-mode edit,
two native content-lock call replacements and topology-aware process/thread
affinity. Campaign selection uses the native full-list argument. All 284 archive
entries verify, three Lua files parse, 392 adapter/CPU/state checks and 38 network
checks pass, plus 21 original-byte guards and ten installer tests.

After confirmed closure, both files were deployed with backup in
`LocalData/Before-content-cpu`; no-game preflight passed. User confirmed campaign
missions selectable. Exact test process PID 60344 (15:58:55 local) has affinity
0x55 on the 8-core/16-thread Ryzen: four physical cores, one thread each. Local
connection completed. Original EXE unchanged. Other reward paths, LAN and desync
behavior are not established by these checks. Current package source is
`work/installer-package-unlocks`; adapter/archive hashes are in the audit.

### Current user target: transferable installer, both host directions, sync validation

The user explicitly wants a patch installer for a second Windows PC, with either
PC able to host and the other to join, and synchronization quality treated as a
release requirement. `docs/TWO-PC-DELIVERY.md` records implemented delivery,
current capability limits and unrun acceptance gates. Do not promise no desyncs
from a content hash or successful lobby alone.

The preparation installer is implemented under `tools/installer/`, with 10
synthetic tests passing. A real run copied all 54 supported game files and
produced a separate working-copy manifest; comparison with the original found
exactly the intended adapter and Interface.bba replacements. Its bundled
CPython/.NET runtimes passed a no-game-launch startup check. The final portable
ZIP has 246 entries and contains no game executable/archive or player data.
It remains a **local-test preparation preview**, with LAN host/join false.
Future network admission must integrate the implemented content comparison;
the current comparison is local/offline, not a completed admission gate.

Workspace artifact: `outputs/S7-Patch-Installer-Vorbereitung.zip` (49,827,595
bytes), SHA-256 `628d6c6fd35ea31d9e2b32b0539135f75ce8c400d5688af5a2017f622bd24ac0`.
Final unzipped build: `work/installer-package-final`. Real installation check:
`work/installer-real-test` (never game-launched). Runtime source and licenses
are in the package. Native adapter and C# service code are unchanged this step.

### Display probe: delivered, but list remains empty

`work/server-session-display` passes **4,373 service checks**, including an
independent native-layout reader and encrypted create/leave/nonempty-search
round trip. Build has zero warnings/errors. The new opt-in mode retains an
owned in-memory copy only after Leave and echoes it to the same owner/Space as
`Anzeigetest - kein Beitritt`. It does not restore a real session or enable join.
Unresolved scalars use verified native constructor defaults as an explicit
display-test policy, not claimed server semantics. See
`LOCAL-SESSION-DISPLAY-PROBE.md` for evidence, filter bypass and boundaries.

Deployed/hash-verified in the separate bundle as `Server-Session-Display` with
its own `Launcher-Session-Display/launch_local.py` and
**`Test-Sitzungsanzeige.cmd`**. The new starter selects this opt-in mode.
The ordinary `Test-Lokale-Anmeldung.cmd` still selects `Server-Session-Leave`.
All game/adapter/archive fingerprints remain unchanged. The deployed service
passed a two-second startup/shutdown on ephemeral loopback ports. No game was
launched by the agent and no loaded file was replaced. The original test game
was still PID 48064, started at 13:48, before staging.

The user completed this test and reported an **empty session list**. Fresh
run `20261026-151636-f088d28a-server.jsonl`, game PID 56896 (15:16 local), showed
six nonempty display replies, 20 DATA sends/ACKs including fragmented replies,
one create/update/leave and no rejection in the inspected sample. Delivery is
verified; native parsing/callback completion and UI display are not.

A guarded read-only snapshot showed connected=true, pending=false, helper
0x109CB58, manager 0x10934EC, one pending manager item, NAT flag false and no
Frida library. Helper+6C points to callback type 0x1093C4C, dispatcher CA8DB0,
bound function C9E8E0 and the same manager. C9E8E0 rejects duplicate session
descriptors and compares the connection descriptor's +54 byte-vector (getter
CDC9D0) with manager+24..+28 before returning false at C9EBBB when equal. This
is a candidate reason a same-owner preview is hidden, not proof that this
branch actually ran. Pending request type 0x113FE90 has a session descriptor
type 0x1140150. Do not call these functions or inject a diagnostic library.
Private observer: `work/read_search_callback.py`; static evidence stays outside
git. No new restart has been requested after this result.

### Prior verified state and research

The created lobby is confirmed. The user's screenshot shows LocalPlayer in the
host slot and one free slot on a two-slot map. Original `hostLobby.lua` disables
Against computer exactly when the slot count is two. Separately, Start demands
another human outside slot 1; AI does not satisfy that check. Earlier advice to
start multiplayer using only AI was incorrect. No UI restriction was patched.

The same run later exposed unsupported `LeaveSession_V1`, followed by nonempty
catalogue search rejections and an already-hosting create rejection. The new
host-only leave handler removes the exact owned record and returns the native
void reply. See `LOCAL-SESSION-LEAVE.md` for layout, limits and test evidence.
Build `work/server-session-leave` is staged/hash-verified as `Server-Session-Leave`
and selected for the successful test launch. Bundle fingerprints pass; archive
and adapter are unchanged.

With `48f7b2a`, the user confirmed AI selection on a four-slot map and a second
lobby without restarting. The fresh run recorded 14 replies/ACKs: Login/Register,
three searches, two creates, six updates and one leave, with zero rejections.
Leave/recreate and AI selection are now live-verified. A second Windows PC with
HE is available for a later LAN test; no changes were requested there yet.

The host-binding milestone `1c014a5` binds create records to the completed
registration's owned profile/connection ID/observed endpoint and rejects a
different registration on replay. Its 3,100 service checks and 477 isolated
login-engine checks pass. The follow-up candidate `work/server-session-routing`
passes 3,142 service checks and additionally preserves creation-only game
StationURLs, identifier bytes, opaque scalar and flag through update/snapshot
and cleanup. Neither candidate is selected in the launcher; the active
live-verified service remains `48f7b2a`.

The outgoing-response candidate `work/server-response-fragments` builds cleanly
and passes 4,152 service checks. It supports 64 KiB logical responses using
947-byte fragments, a two-slot sequence window that cannot slide past an ACK
gap, exact ciphertext retries, native echoed-part ACK matching and bounded
cleanup. Login/Register ACK gating now counts completed logical responses.
See `LOCAL-RESPONSE-FRAGMENTATION.md`. This is synthetic transport validation;
no nonempty catalogue handler or new game-facing behavior is deployed.

The second search output is proven to map session IDs to pipe-separated
StationURLs. Create's second qString supplies the game's serialized StationURL
list with Storm routing data; it must not be replaced by the login transport's
observed endpoint. The packed session DateTime encoding is known, but its event
meaning and other scalar semantics remain unresolved. See `LOCAL-SESSION-CATALOGUE.md`
for anchors, implementation and next requirements. These observations predate
the separate display-probe test above.

Full match startup, `GetSession`, live catalogue policy and joining remain
outstanding. The display-only serializer is now implemented but not yet
live-verified. The next step is mapping the session-record fields to real registry
and transport state; see `LOCAL-SESSION-CATALOGUE.md`. Do not fabricate unknown
scalar values or request another game restart merely to repeat the verified test.
The diagnostic retains at most eight distinct fixed operation labels.

The SpaceId transfer and real `SearchSessions_V1` exchange are live-verified
at transport level: 16 empty search replies, 18 acknowledgements including
Login/Register, no rejection or expiry in the recorded sample. The user
opened game settings. The scoped create gate is now live-verified: two
`CreateSession_V1` requests reached the service, which had no handler yet.
A bounded shared session registry and native-shaped create response are now
deployed and both a create reply and an idempotent retry were acknowledged.
In the preceding create-only run, the user confirmed the create button was
immediately active, but creation still loaded or errored. One subsequent Matchmaking operation was unclassified; it was
not `GetSession_V1`, whose classifier was already present. `GetSession`, nonempty search results,
joining, match startup and LAN remain absent. See `LOCAL-SESSION-CREATION.md`.

The user's first-visit disabled create button is a separate Lua transition bug:
the original screen disables create when NATReady changes true to false but
retains that false state across screen recreation. The prepared archive refreshes
create from actual login each update, retaining quickmatch/join NAT rules.
The candidate is `work/offline-ui-create-ready`, with service build
`work/server-create-records` staged as `Server-Create-Records` in the test bundle.
After the user closed S7, the host process check confirmed no remaining game.
`work/deploy_create_records.py` installed the archive from commit `d100dab`
under the launcher lock and switched the test launcher to `Server-Create-Records`.
All staged service files and bundle fingerprints matched. The previous archive
and launcher remain in `LocalData/Interface-before-create-ready.bba` and
`LocalData/Test-Lokale-Anmeldung-before-create-records.cmd`. The native adapter
is unchanged. The no-game-launch preflight passed. The user has been asked to
check create on the first session-list visit, attempt one creation and leave S7
open. Do not rerun the completed deployment transaction.

Latest diagnostic: `work/server-create-followup`, staged and hash-verified as
`Server-Create-Followup`. The test launcher now selects it for the next run; its
previous version is retained in `LocalData/Test-Lokale-Anmeldung-before-create-followup.cmd`.
It adds fixed labels for all 40 Matchmaking method names from the supported EXE
and separates unsupported operations from nonempty-search rejections. No new
handler, native change or archive change is included. The current game remains
on the old service until the user restarts. Request one create attempt with the
new diagnostic, then inspect its fixed follow-up label.

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

That run succeeded at transport level: the server queued 16 empty search
replies and received 18 response ACKs including Login/Register, with zero
rejections or expirations. The game stayed connected and open. ACKs establish
delivery; there is still no direct observation of its internal completion
callback. The user then opened game settings and tried creating a session.

### Create Session gate: deployed and request live-verified

The user supplied a screenshot of `SERVER-FEHLER / KANN KEINE NEUE SITZUNG
ANLEGEN!` on map selection. No create RPC reached the endpoint. In the exact
executable, `ED62D0` passes the already-replaced login check at `ED62FC`, then
calls `ED7270` at `ED630B`. Failure takes `ED6317 -> ED20A0` before creating
the asynchronous `Create Session` job at `ED634C`. A read-only live snapshot
confirmed owner `+0x3A` false while actual connection, helper SpaceId, master
startup and owner attachment remained ready.

The new candidate replaces only that five-byte call with
`QueryLocalSessionCreate`. It requires the same exact local ownership,
bootstrap thread, explicit probe, started/attached network and native SpaceId
transfer used for search. It does not alter the NAT flag or claim lobby/match
success; the original asynchronous job still owns the result. Native patch
guards increase to 18. Build `work/native-create-build`: 248 bootstrap, 88
platform, 18 connection-state and 38 network checks pass, as do all 18 original
guards and real configuration/wrong-executable rejection.

The service classifier now recognizes fixed `CreateSession_V1` and
`CreateSession2_V1` labels. Neither receives a fabricated success response;
the search handler rejects both. Codec checks pass (20,215 assertions), and
the full server suite passes 1,926 checks. The separate launcher selects the
hash-verified `Server-Create-Diagnostic` service; the previous service and
launcher are retained. After the user closed S7, a host process check confirmed
no remaining game process. `work/deploy_create_adapter.py` deployed the tested
adapter from commit `7b5bbd9`, retaining the previous adapter in
`LocalData/adapter-8d3bc91.dll`. All bundle hashes and the no-game-launch
preflight passed with `Server-Create-Diagnostic`. The user has been asked to
launch the test copy and try creating one session. A create error remains
possible because the handler is not yet implemented. Do not inject diagnostic
libraries or rerun the successful deployment transaction.

The subsequent user run sent two recognized `CreateSession_V1` requests, both
rejected by the old search-only handler. This confirms the native create gate
works. The read-only snapshot retained actual connected state, helper SpaceId
and owner attachment with the global NAT-ready flag false. No native adapter
change is required for the next create-record service/UI test.

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
Omit `graph_root` when this repository is already served; use its absolute root
only from a server serving another project. `tokensave sync` refreshes local
changes; the index is ignored by Git. No global settings or Git hooks were
installed. No Cairn journal was initialized.

The existing workspace file opens the repository. Registering its folder in
the Codex project sidebar is a separate UI step; this chat can already work
on the repository and query its TokenSave index.
