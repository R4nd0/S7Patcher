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
verified. A second PC now discovers the lobby and sends a join request, but
the native join fails after the service response; no successful join is verified.

The current native candidate passed 354 adapter checks, 38 network-guard checks
and 18 original-byte comparisons, plus configuration validation. The
current session-leave candidate passes 3,069 service checks; the unchanged
RPC codec previously passed 20,288 isolated assertions. Its UI archive verifies
all 284 entries and parses.
These are separate results, not evidence of a playable LAN match.

## Current step: nonempty catalogue and second-client join

### Current: autonomous two-client laboratory; native link failure reproduced

The user explicitly authorized operating this local computer. Two independent
real game copies now exist under `rec/work/pair-A` and `pair-B`, with separate
mutex names, profiles, identities and loopback addresses. See LOCAL-PAIR-LAB.md
for exact build boundaries, local artifacts and observations. No original game
files or system network/security settings were changed.

With a shared loopback address and lab-only descriptor projection, A hosted a
public Turminsel lobby, B discovered it and attempted a native join. The corrected
report parser observed `link-reach-failed`, kind 0, text length 71. The visible
error remained Sitzungsfehler (0). This is a real-game result, not a synthetic
fixture. It is not yet proof of the cause of the earlier two-PC failure.

The next build assigns 127.0.0.2 / 127.0.0.3 by full EXE hash. Both real clients
authenticated and each owned UDP 3074, 6200 and 9103 independently. The next
join could not be operated because Computer Use screen capture failed repeatedly
with `FrameArrived timed out`, including after a session reset. Games and service
were stopped; do not treat this as successful joining or ask for PC 2 updates.
Resume local UI testing only with a valid fresh observation.

Normal PC 1 test copy received the corrected diagnostic service 21a0be26...;
PC 2 remains Gateway as last user-confirmed. Laboratory EXEs/adapters/services
are separate from both. Laboratory checks: 361 bootstrap, 69 network, 88 platform,
18 state, 14 CPU; 5,763 service checks. Default build: 359 bootstrap, 61 network,
5,753 service checks. Real original: 13 read-only derivation/immutability checks.
No completed native membership, reverse hosting, match start or sync exists.

### Previous: independent investigation; corrected report layout, no new live test

User: "mach alleine weiter, ich kann nicht mehr helfen". Do not repeat restart,
update or two-PC test questions now. No new games launched, no injections and
no installed test-copy changes in this milestone. PC 1 later had no game process
or UDP 3074 listener; its existing test-game inbound TCP/UDP allow rules were
present. PC 2 is not remotely accessible. Do not infer its state or a firewall
cause from this. Both copies remain on the Gateway service as last verified.

Last real run 20261026-194159-fb0b0eb4 sends a join reply, receives transport ACKs,
then ReportJoinFailure_V1. UI: "Sitzungsfehler 0 ... kann der gewaehlten Sitzung
nicht beitreten". No completed native membership, reverse hosting or match exists.

Static caller tracing found an error in the prior undeployed diagnostic:
ReportJoinFailure fields are class map, Space, kind, session ID, result text.
D3F9BE..D3F9D6 passes object+4 by value and object+8 by address; E4E2A0 forwards
these to E52F70. The same object+8 is JoinSession's ID at D3FC05. Kind is initialized
to zero at D48A00 on this RendezVous path. The prior parser incorrectly treated
kind as a nonzero ID and ID as an error code. Corrected the parser and renamed
reported_error_code to reported_session_kind. This is not a numeric error code.

CC5700 -> CC5640 constructs group:description (System error: decimal) plus a fixed
suffix. A bounded whitelist now emits reported_failure_category (or unclassified)
without exposing any raw text. Existing ownership/registration/space checks,
one-observation cap, no RPC response and no membership mutation remain intact.

The first join response string is now traced through D476F2 -> E4DD30 (pipe-split
StationURL list) -> D47779/D4D170 (Storm descriptor and RoutingOption) -> D4781C /
D49B10 / BABBD0 (native request join).
This supports the URL-list meaning. It does not prove the exact projected route,
member state or native connection is accepted. Details in LOCAL-SESSION-JOIN.md.

5,746 service checks pass, including a manually specified native-layout fixture,
zero kind / distinct session ID, fixed-category parsing and encrypted two-peer
reports in both directions. No real games are used by these tests.
Build work/server-join-report-layout; tests work/join-report-layout-tests.
Service SHA256: 21a0be26d73a39d163fe348793d481aeedd5ea6788bbacce69c062de927283ac.
outputs/S7-LAN-Beitrittsbericht.zip now replaces the undeployed earlier diagnostic.
Nine-file ZIP SHA256: 045a5c2d45c026b24877e3230b986ce25b9dd6b51d237bee3bd0d4f42953df9b.
CRC, source equality, old/new payload hashes and wrong-source rejection pass.
Requires Gateway bc73ef4e...; backup Before-join-failure-diagnostic-v2. Not deployed.

Remaining blocker: actual native failure category is unavailable in the old log.
When live testing becomes possible, both closed copies need the same version;
read its bounded report rather than requesting another blind format adjustment.
Independent static work can follow BABBD0 -> session/peer setup and native result
propagation. Report acceptance/cleanup and success notifications are still absent.
Neither simulated checks nor static tracing establish working LAN or no desyncs.

### Current: second native gateway sentinel; deployed, real join pending

User confirms both games closed and Gateway-Update installed on PC 2.
PC 1 had no game but orphan service PID 63676; exact path/command and absent
parent 63520 verified before stopping it. Ports 9110/9111 then free. Verified
nine-entry ZIP extracted with exclusive writes; transactional updater succeeded.
Installed service SHA256 bc73ef4e... matches candidate; content ID:
5a22ca288510dfd3689f5997f80c03eec95d31ade40fa6f9832418f048faf7db.
Host --check-only passed for .125 / .85; no game launched by agent. User asked
for exactly one public four-slot join from PC 2, leaving both games/starters open.
Await actual result/logs. User also asked about one-computer testing: existing
automated tests use simulated clients; two real isolated game instances have
not been configured. No VM or other system setup was performed.

Run 20261026-193235-63c78150 still rejects one JoinSession_V1 with
local-join-storm-descriptor-values. Installed service hash da48ed8c... confirmed.
Guarded read-only test PID 51500 snapshot finds ProfileID length 36 but gateway
shape v(d)wk(-), unlike earlier v(d)t(-)g(). Original hash-checked code B7B017
passes exact literal v(0)wk(-) (10883B0) via CED160 at B7B043. It contains no
endpoint. Added only that literal, retaining the previous gateway form and all
identity/IP checks; arbitrary keys/gateways remain rejected. Descriptor value
failures now have fixed per-field reasons (peer-guid/version/platform/gateway/
base-end/profile/routing-option), never raw content.

Encrypted tests cover both gateway forms and empty/nonempty profile across both
host directions, including negative IDs. Read-only live-shape validation accepts
the current descriptor and retains only expected host endpoint; synthetic ID
substitution means this is not a real admission test. Build server-gateway-sentinel,
tests gateway-sentinel-tests. Service SHA256:
bc73ef4e21c4056f591d0fd210081be2cf73d0374f00671dde69a9eb9f29a297.
outputs/S7-LAN-Gateway-Update.zip (nine entries), SHA256:
3557c931937502cd0d126353181ee8c1ad2a24bf857404a19a379bf892f520d4.
CRC, source/updater equality, old/new payload hashes and wrong-source rejection
pass. Requires Profilfeld service da48ed8c...; backup Before-gateway-sentinel-v1.
Both installed copies now have Gateway-Update (PC 2 user-confirmed, PC 1 verified).
Full suite passes 5,546 checks. Inspect next public four-slot join for its
response/ACK/follow-up.
Real join, reverse hosting, match startup and synchronization still unverified.

### Current: empty native ProfileID supported; deployed, real join pending

User confirms both games closed and Profilfeld-Update installed on PC 2.
Host inspection found no game/launcher/service and ports 9110/9111 free.
Verified nine-entry ZIP extracted with exclusive writes on PC 1; transactional
update completed. Installed service SHA256 da48ed8c... matches the candidate.
Content ID: 990d2fd3b364eccedc82d3e256cc848dab678fe8aeed6fea5153d41adf0c8a9f.
LAN host --check-only passed for .125 / .85; no game launched by the agent.
User asked for one public four-slot join attempt from PC 2, leaving both games
and starter windows open. Await result/logs; real join and gameplay unverified.

Latest user join failure: 20261026-192411-de939fec-lan-server.jsonl, two registered
peers and one JoinSession_V1 rejection local-join-storm-descriptor-values.
RVCID comparison now passes. Guarded read-only snapshot of test PID 33568 finds
empty ProfileID in the expected Storm blocks. Native writer C96F64..C96F96 and
reader C8FB60 (zero-length substring allowed; returns true C8FC03) confirm it is
a supported spelling. Original EXE hash checked, no raw IDs/routes saved.
LocalStormRoute accepts empty or D-format GUID here, preserving it and keeping
registered identity and endpoint ownership checks. See LOCAL-SESSION-JOIN.md.

5,463 service checks pass, including encrypted empty-profile joins in both
host directions and identity/address rejection. Paired update and PC 1 preflight
are now complete as recorded above. Inspect the next real join's response,
acknowledgement and follow-up requests. Real LAN join,
reverse hosting, match startup and synchronization remain unverified.

Read-only live-shape harness passes current descriptor/host-only projection
with synthetic registration, not live admission. Build work/server-empty-profile,
tests work/empty-profile-tests. Service SHA256:
da48ed8c0751c482b6b85fb37a084336f2a19665792f0e515b5365c9665d478d.
outputs/S7-LAN-Profilfeld-Update.zip has nine files; SHA256:
4c714ee6a816d112a3379696c431f95e0be22bfa8b79442e6c8bddbb3b4cc8fb.
ZIP CRC, packaged/source updater equality, old/new payload hashes and wrong-source
rejection pass. Requires 7d61a238...; backup LocalData/Before-empty-profile-v1.
Transactional updater unchanged; no native/archive edits. Both installations
now have Profilfeld-Update (PC 2 user-confirmed, PC 1 locally verified).

### Current: signed native RVCID representation; deployed, real join pending

User confirms Kennung-Update installed on PC 2. Initial PC 1 check still found
game PID 19428 plus launcher/service; no loaded files were changed. After a
second closure confirmation, game/service were gone and ports 9110/9111 free.
Verified nine-entry ZIP extracted with exclusive writes; bundled transactional
updater completed and installed service hash 7d61a238... matches the candidate.
Content ID: aff2af7d7629615553ed5beeb964ecc374ca51778f358e9b4d5c99538cdb9e00.
Host --check-only passed for .125 / .85 without launching the game. User asked
to create public four-slot lobby on PC 1, attempt exactly one PC 2 join, and
leave both games and starter windows open. Await actual result and logs.

User reports join failure. Host run 20261026-191237-fe39c5e9 has two registrations,
create/update/search and one JoinSession_V1 rejected as
local-join-storm-connection-mismatch. Read-only guarded inspection of test game
PID 19428's known creation URL vector shows RVCID is a negative decimal fitting
int32 (not a uint32 decimal). No raw route or identity values emitted or saved.
Static hash-checked original confirms D43437 -> E5EAE0 -> E5EA00 stores the same
32-bit value in the numeric StationURL map (E5EA6E); E5DB89..E5DBAA serializes it
with format %s%s%d at E5DB9B. The previous unsigned-only parser rejects high-bit
connection IDs despite their valid native representation.

LocalStormRoute now accepts canonical negative int32 or nonzero uint32 decimal,
compares the identical uint32 bits to registered host.ConnectionId, and retains
the original route spelling. Zero, plus sign, whitespace, leading zeros,
overflow and mismatched identities fail. Endpoint ownership is unchanged.
5,394 service checks pass, with deterministic boundary IDs and encrypted joins
using int.MinValue and -1 spellings in opposite host directions. This verifies
the parser correction, not a successful real-client join or live identity match.

Build work/server-signed-route, tests work/signed-route-tests. Service SHA256:
7d61a238e8af9355a9054fdf22debf6ca1c5777ebed154aba90a35d40568bafe.
outputs/S7-LAN-Kennung-Update.zip (nine files) SHA256:
a18671a58632182ec55b039b2c971f8253e3a04f6e8556f901a6887422035f14.
Packaged updater matches source; exact old/new payload hashes, ZIP CRC and
wrong-source rejection checked. Requires service 044931d8..., creates backup
LocalData/Before-signed-route-v1. Uses unchanged transactional updater; no native
adapter/archive changes. Starter checks all extraction siblings before Python.

Both installations and PC 1 no-game preflight now completed as recorded above.
Next inspect the requested public four-slot join attempt for reply ACK/follow-up.
Real join, reverse hosting, match startup and synchronization remain unverified.

### Current: embedded Storm endpoint identified; candidate projection ready

Subsequent PC 1 launcher failure was a local port collision, not a join result.
19:09:39 log records local-bind-key-or-io-failure. Updated service PID 25752
(started 19:07:17) still owned TCP 9110 and UDP 9111; no Settlers7R or parent
PID 15364 remained. Exact executable/command line and absent parent/game were
rechecked before stopping only that orphan. Host --check-only then passed again.
No game launched, no files/service payload changed. User asked to retry public
four-slot host and one PC 2 join, keeping the launcher window open throughout.
Underlying launcher lacks protection against child service surviving abrupt
launcher termination; this cleanup does not constitute a lifecycle code fix.

Deployment completed: user confirms successful Spieladresse update on PC 2
and both games closed. Host inspection found no Settlers7R; the remaining old
test service PID 55396 was identified by exact executable/command line and
stopped. Ports 9110/9111 were then free. Verified revised ZIP extracted to PC 1
with exclusive writes; transactional update succeeded. Installed service SHA256
044931d88c501a11a792067af97935ba1a3920cb85c54fbf140f0c4948c2f787;
content ID 1b925c935b7d06c102aaa0bbb7aa354d4b5af0754fc00c9e0995c9ad354f7516.
LAN host --check-only passed for .125 / .85; no game launched by the agent.
User asked to launch PC 1 public four-slot lobby and PC 2 role 2, attempt one
join and leave both games open. Await actual result/logs; successful native
join, match start, reverse hosting and synchronization remain unverified.

PC 2 update attempt failed before Python could open
C:\Spiele\Settlers\S7LANTest\S7-Spieladresse-Update\update_storm_route.py
(Errno 2). This establishes a missing expected extracted script, not a parser
or service failure; repeated backslashes in the error representation are not
the cause. The original nine-entry ZIP contains that script and passes CRC.
The revised tracked tools/installer/Spieladresse-Update.cmd checks the runtime
and every payload sibling before invoking Python and explains full extraction.
Verified in an isolated directory with spaces: missing runtime/script both
exit 2; a fixture script receives the correct bundle path and exit 17 propagates.
No installed updater or game was launched. Same service/updater bytes; revised
ZIP SHA256: 648c5ad23f1dba4c83b501db22f4f1a796877ed01f57555828ffe182f0c049f3.
User instructed to copy BOTH the CMD and complete S7-Spieladresse-Update folder
into S7LANTest and report completion with both games closed. That confirmation
has now arrived and PC 1 deployment is recorded above.

User reports another error. Run 18:40:40 (20261026-184040-1bd3bcc7-lan-server.jsonl)
records one JoinSession_V1 rejected as local-join-host-route-section-invalid.
The previous section support still required address/port in the URL prefix.
Static producer D433D0 actually creates only prudp:/RVCID=...#Storm=..., with
the game endpoint list embedded inside the Storm descriptor.

Read-only inspection of game PID 12704 used the known network/owner/helper chain,
helper table 109CB58, helper+1D8 -> URL vector +08, and cached StationURL text
at each 0x34-byte object's +2C. EXE hash/module path/object tables/vector bounds
were checked. No injection, game calls or raw route files. The single 288-byte
route has prefix RVCID and one Storm section with PeerGUID, Version, Platform,
Gw, Address, PeerDescriptorBaseEnd, ProfileID, RoutingOption. Address contains
four IPv4 endpoints on port 3074, one matching 192.168.178.125; the game really
has UDP 3074 bound on that address. Gw shape is v(d)t(-)g(). Other endpoint
addresses/identities were not emitted. Working helpers: read_host_route_shape.py
and validate_host_route_shape.py, both outside Git.

LocalStormRoute accepts only this bounded descriptor shape, ties RVCID to the
registered host's connection ID, and projects Address to endpoints matching
that host's observed address. It keeps actual game ports and all other supported
descriptor fields. Unknown/ambiguous formats, active gateway text and foreign-only
routes fail closed. TryJoin applies the projection only to its response snapshot;
the host's original stored route and existing catalogue/Get outputs stay intact.
Simple address/port routes and prior custom-section support remain available.

5,314 service checks pass, including Storm joins through independent encrypted
peers in both host directions, truncation/malformed/foreign-route rejection,
exact projected reply, original-record immutability and replay. A separate
managed shape harness accepted the live descriptor in memory and retained only
192.168.178.125:3074. That harness used a synthetic registration identity: it
validates syntax/projection, NOT real RVCID admission or native reply acceptance.
The packaged updater source/payload/old hash and wrong-source rejection pass;
transaction engine unchanged. Build work/server-storm-route; tests storm-route-tests.
Service SHA256:
044931d88c501a11a792067af97935ba1a3920cb85c54fbf140f0c4948c2f787.
Deliverable outputs/S7-LAN-Spieladresse-Update.zip (nine entries), SHA256:
648c5ad23f1dba4c83b501db22f4f1a796877ed01f57555828ffe182f0c049f3
(repackaged with extraction checks; service and updater unchanged).
Requires preceding service f199c8da..., backup Before-storm-route-v1.

Both updates and PC 1 no-game preflight are now complete as recorded above.
The requested next run is exactly one public four-slot join attempt; inspect
fixed reason/queued reply/ACK and follow-ups. Real join/P2P/match/sync unverified.

### Current: native URL custom section identified and supported

User reports join error after the diagnostic update. Host run 18:30:21
(20261026-183021-6bbcc395-lan-server.jsonl) confirms two registrations, live
catalogue/create/update and exactly one JoinSession_V1 rejected with
local-join-host-route-section. No successful join reply yet.

Static original-hash-checked inspection confirms '#' separates a custom string
map from the routing parameters (details in LOCAL-SESSION-JOIN.md). The new
TryReadGameRoute accepts a bounded single section, rejects ambiguous/duplicate
keys and routing aliases in that section, retains the original complete URL
in the reply and keeps registered-host address checks. Login/Register parsing
is unchanged. No native files changed; game route acceptance remains untested.

4,986 freshly built service checks pass, including encrypted joins with the
custom section in one host direction, exact section preservation and malformed/
redirect/foreign-address rejection. The packaged updater's source, payload,
required prior hash and wrong-source rejection are independently checked.
The transaction engine is unchanged (16 tests passed in the preceding task).
Build work/server-join-url-section; tests work/join-section-tests.
Service SHA256:
f199c8da7bfe01d4729b7043ec9431dcdc365e3c13799039c26a81cca87cf4a0.
Package outputs/S7-LAN-Adress-Update.zip (nine entries), SHA256:
a118ba3639575c1db27ee3f63517154d0ade75840744f9faa9be805763b2872f.
It requires the prior diagnostic service (067eb993...), current adapter/menu,
and uses backup LocalData/Before-join-url-section-v1.

User confirmed both games closed and Adress-Update.cmd installed on PC 2.
PC 1 process/port checks found no running game or service. The verified ZIP was
installed with bundled Python, and the installed service hash matches above.
The no-game LAN host preflight passed. Updated content ID:
14730d8906f15ec363c630347cfca90ad579eb87929b9a8b4e1801e763fd84e7.
User has been asked to create a public four-slot lobby on PC 1, start PC 2,
attempt exactly one join and leave both games open. Runtime result pending.
Inspect whether further route checks fail or a reply is queued/ACKed; native
membership/P2P/match start/synchronization remain unverified.

### Current: real join rejected by host-route validation

Both PCs installed the first pending-reply service. User reports another join
error. Host run 18:15:08 (20261026-181508-65219410-lan-server.jsonl) confirms
two registered peers, host create/update, catalogue replies, one actual
JoinSession_V1 and rejection local-join-host-route-invalid. No join response
was queued; native reply acceptance/member status cannot yet be evaluated.
Host game PID 15552 and service PID 26316 were left open for inspection.

The next service changes diagnostics only, preserving route acceptance policy.
It distinguishes missing/empty/oversized/non-ASCII routes, list count/empty
items, scheme/section/escaping/syntax, mismatched/loopback/unspecified addresses,
redirects and invalid registration. All reasons are fixed strings; no raw
routes or identifiers are logged. Do not infer which condition failed until
the next real run. No fallback to the login port or blanket route acceptance.

Build work/server-join-route-diagnostic, service SHA256:
067eb993e745745dec01701ca6ccc589edfcde4ae42aae850fa106136f86fdfe.
4,952 freshly built service checks and 16 updater checks pass. The test build
was moved to work/join-route-tests after a concurrent old test process locked
the default output; only the subsequent fresh build verifies the new tests.
Package outputs/S7-LAN-Routen-Diagnose.zip (nine entries), SHA256:
6c8b607d2ebad4ac73e770b20a4ae510a9c768d37b4e7de9a7d6a3dfb4257715.
tools/installer/update_join_routes.py requires service 8ccac3f... and retains
the current menu/adapter, using backup Before-join-route-diagnostic-v1.

User confirmed both games closed and Routen-Diagnose.cmd installed on PC 2.
Host process/port checks found no running game or service. PC 1 then installed
the verified ZIP with bundled Python; the service hash matches the candidate.
The no-game LAN host preflight passed. New content ID:
640b0ef37afc7aba18955aac14aa0e9d717f388ec2b6433fa1110cc1e21ef847.
User has been asked to create a public four-slot lobby on PC 1, start PC 2,
attempt exactly one join and leave both games open. The error is still expected;
inspect the next run's fixed host-route rejection reason before changing policy.

### Current: real JoinSession received; first pending reply prepared

Run 17:52:43 confirms an actual JoinSession_V1 from PC 2, rejected by the old
service as unsupported-session-operation. User saw a join error. Native
dispatch is now confirmed; both games were left open. The next candidate
implements a bounded pending reservation and qString + session reply with
registered identity, ownership, public/space, route and capacity checks.
See LOCAL-SESSION-JOIN.md for deliberately unconfirmed native semantics.

4,934 service checks and 16 updater tests pass, including encrypted requests
in both host directions. The never-launched full installation fixture was
updated, independently inventoried and passed the no-game service preflight.
Build work/server-join-reservation; package work/join-service-update-package.
Deliverable outputs/S7-LAN-Dienst-Update.zip (nine entries), SHA256:
6a0818d2d90dbd7791b800cad8a1d921245540d6c015175af7dd3bc9ed834be4.
Expected content ID after updating:
5ca87dd0e322d9666bc001d680440a3e2896ad1133a1009a1f628f5c54cf014f.

User confirmed both games closed and Dienst-Update.cmd installed on PC 2.
PC 1 was then updated from the verified ZIP with the transactional updater.
Host process/port checks found no running game or service before deployment.
The installed service hash is
8ccac3f143a3a205cb2bc0cc877cea9085fd255c0cef37822d1c666c8c56fc20;
the content ID matches the expected value above. The LAN host preflight on
192.168.178.125 with peer 192.168.178.85 passed without launching a game.
User has been asked to create a public four-slot lobby on PC 1, start PC 2,
attempt exactly one join, and leave both games open. Runtime result pending.
No completed membership, host notification, match startup or desync-free
gameplay has been established. Inspect the next run's join result/reason.

### Current: menu gate confirmed, native join dispatch update ready

Both PCs applied the menu update. The user confirms the join button is active,
but the attempt errors/waits. Host PID 20236/run 17:39:46 shows both real peers
registered, 10 catalogue replies plus host create/update, and no Join/Get RPC.
The newly located native gate ED673B precedes the named Join Session job and
still checks global NAT. The guarded replacement preserves native job/results;
see LOCAL-SESSION-JOIN.md for static evidence and validation.

outputs/S7-LAN-Beitritt-Update.zip is prepared (nine entries, no original game
files), SHA256 13d3315699159142758bfd2c4f9c5ac3e40a7a1743dd0c98f8b3f0edaa8cd94e.
Source package work/join-adapter-update-package; built DLL work/native-join-build.
User confirmed both games closed and the adapter update installed on PC 2.
PC 1's updater then completed with backup; its content ID matches the validated
fixture (2b018d9cd23e066adc243d941c61e4cb1066c4825ab0445e16039d7f77565c1f).
The first no-game preflight found ports occupied by the prior 17:39 test service
PID 39668. Its exact executable, service arguments and old content ID matched;
parent PID 42264 and all S7 processes were absent. Only that orphan was stopped,
then the LAN preflight passed. No game was launched by the agent. User has been
asked to start a public host lobby, start PC 2, attempt one join and leave both
games open. Runtime result is pending. Existing menu ZIP is unchanged. Service
remains unchanged and still has no successful join handler; this is the first
native join dispatch test, not a playable LAN claim.

### Two real PCs: catalogue confirmed; join menu update

The user confirmed PC 2 sees PC 1's public lobby. The host log records two
Login/Register peers and acknowledged catalogue replies. The earlier standalone
diagnostic reported no error; its original startup failure cause remains unknown.
The selected lobby still has a disabled join button, explicitly confirmed by
the user after selecting its row. No actual JoinSession RPC has been observed.

Original sessionList.lua gates the join button on Network.IsNATReady even when
the row is selected. The guarded incremental delta in
`tools/offline-ui/join-menu-update.json` changes only that condition to actual
IsLoggedIn; row count/selection and the native SessionJoin result remain intact.
Quickmatch NAT checks and the global native NAT state are unchanged.

`tools/installer/update_join_menu.py` applies this to the known two-peer test
copy, updates exactly the archive hash in both manifests, holds the launcher's
session lock, checks for running S7, and retains a recovery journal/backup.
An interrupted partial commit is restored on the next invocation; unexpected
external changes are rejected. Ten tests cover success/idempotence, manifest
and content mismatches, running-game/launcher rejection, rollback, interruption,
and backup tampering. Real archive validation checked all 284 files and parsed
the changed Lua. The never-launched full installer fixture passed the update,
complete inventory validation and an idempotent second run.

Portable supplement: `outputs/S7-LAN-Menue-Update.zip`, eight files, contains
only our updater, a bounded delta, MIT archive tooling and instructions. Extract
beside Test-LAN-Verbindung.cmd in BOTH installed copies, close S7, and run
Menue-Update.cmd. No reinstall/new test directory is needed. Backup directory:
LocalData/Before-join-menu-v1. The embedded Python requires explicit script
directory insertion; the updater includes it. The original installer stays at
the previous archive version, so new installations need this supplement too.

Old archive: `ebee0ff593cdb9c38442d03875041f8c1825c0fc3e2414291098e08f3517ced5`.
New archive: `2b1ad77ab1afda98e9d9aab8bbc91279607e1bbbac506d2b52de675550de08ad`.
Expected updated content ID:
`0e92dd7136170171d31f361c86c2c825862cf0fc97588617ae25cb6ae9047674`.
PC 1 deployment completed with the bundled Python; the no-game LAN preflight
passed. User has been asked to close PC 2 and apply the supplement, without
starting either game yet. This only
unblocks testing the native join path: membership/reply and match behavior are
still incomplete, so a subsequent join error is possible and must be diagnosed.

### Pending second-PC startup diagnosis

User installed the two-peer package but reports the generic LAN-start error,
with no Windows firewall prompt. Read-only host inspection at 17:08 local on
2026-10-26 confirmed the newly user-started test process PID 12084, service PID
57196 listening on selected LAN TCP 9110/UDP 9111, and host Login/Register/Create/
Update acknowledged. Only its own configuration HTTP request was logged.
This does not determine whether PC 2 fails file verification, local-address bind
or TCP access; no second-PC cause is established yet.

A read-only diagnostic supplement is delivered as outputs/S7-LAN-Fehlerdiagnose.zip
(two files). Extract beside Test-LAN-Verbindung.cmd on PC 2 and run
LAN-Fehler-pruefen.cmd. It imports the installed launcher but does not change
fingerprinted files, launch a game, write runtime/identity files or alter firewall
settings. It names the failed stage, maps Windows socket errors and never echoes
raw server configuration/exception payloads. Nine synthetic tests pass. An actual
Windows test with a deliberately unassigned local address correctly stopped at
Eigene Adresse with code 10049; that is NOT a diagnosis of the remote PC.
User has been asked for its final FEHLER line; response pending. The existing
installer ZIP and live game's content fingerprint remain unchanged.

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

The independent installer output (work/installer-lan-real-test) fully matches
the active copy's compatibility inventory. Portable ZIP verified: 247 entries,
no game binaries or user identity. User has been asked to install it on PC 2,
select client and inspect the public session list without joining. Response
is pending. No second-PC connectivity has yet been observed.

JoinSession_V1 static wire evidence and a bounded request parser are now in
LOCAL-SESSION-JOIN.md / LocalSessionMetadata.TryReadJoinBody. 4,756 checks pass
including 143 new join-shape checks. The parser is not wired to successful
membership mutation/reply; the already delivered package remains unchanged.

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
