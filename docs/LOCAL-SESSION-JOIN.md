# JoinSession_V1 wire evidence and remaining work

Original HE fingerprint remains the one guarded by the adapter. Static reads
only; no game function was manually invoked and no diagnostic library injected.

## Native dispatch gate (2026-10-26)

After the menu update, the user confirms the selected lobby's join button is
active, but the attempt errors/waits. Host run 17:39 has two registered peers,
acknowledged public catalogue searches and host create/update, without any
JoinSession/GetSession RPC. This identifies a failure before the known service
join parser; it does not by itself prove a particular PC 2 instruction executed.

Static inspection of the hash-locked original finds the named `Join Session`
job at ED6700. Its already-scoped login call is ED672C. Next, ED673B calls
ED7270 (bytes E8 30 0B 00 00); false takes ED6747 -> ED2090 and exits before
job construction. True continues through C8DCA0, ED68F0 and the asynchronous
job construction at ED6780/ED678A. The neighboring ED652C gate is QuickMatch
and is deliberately unchanged.

`QueryLocalSessionJoin` replaces only ED673B in the explicit connection-probe
table. It requires the bootstrap thread, actual local login, owned network/core,
started/attached owner, valid helper and confirmed Space transfer, exactly as
the independently verified search/create dispatch gates. It preserves the
global NAT flag and all native RPC/result/session state transitions. It emits
fixed local-session-join-ready/not-ready diagnostics. A successful dispatch
check does not mean successful membership, P2P connection or match startup.

Build work/native-join-build passes 291 bootstrap, 61 network, 18 connection and
14 CPU checks, 21 original callsite guards, and exact 84-export matching. Adapter
SHA256: f40d6aa17da87876abac5e8523ca6505b16c1ffb067d133956001882440bf71d.
Portable outputs/S7-LAN-Beitritt-Update.zip uses the same transactional updater
with an explicit adapter target; it requires the preceding menu update. Fourteen
update tests include adapter rollback/interruption and mismatched menu/payload
rejection. A full never-launched installation fixture passes application,
idempotence and inventory comparison with bundled Python. Expected content ID:
2b018d9cd23e066adc243d941c61e4cb1066c4825ab0445e16039d7f77565c1f.
The ZIP contains our built DLL, no original game files. Both PCs must update
while closed. Runtime JoinSession transmission remains pending.

## Wire evidence

The E52010 client serializer is called by facade wrapper E4DFD7. It serializes
MatchmakingSession and MatchmakingSessionMember at version 1 (E52143/E52152),
then Space qString (E5215E), session ID u32 (E52170), and member attributes
(E5217C -> E4EA40). The last field is a qString-keyed map of GUID16-keyed Variant
maps, not an ordinary flat session-attribute map. Class order is map order and
both known classes must occur once. The parser retains bounded opaque values.

The reply dispatch at E54FDE/E54FE2 calls E55EF0. Output slot zero is read by
EB0630 as qString (E55F1F or discard path E55F4F); output slot one is read by
E4F100 as a single MatchmakingSession (E55F80 or discard path E55FBA). Therefore
a candidate reply must contain a string before the session. It cannot reuse the
GetSession body unmodified. Field meaning/valid route serialization and member
status must be established from callers and a real client exchange before a
successful join is reported.

TryReadJoinBody validates this request shape with bounded copied metadata,
class/version uniqueness, duplicate-map rejection, exact end and ID policy.
Tests cover both class orders, every truncation, copies surviving input disposal,
empty metadata, duplicate classes/groups/members, invalid version/ID/count,
trailing data and aggregate size. No host/guest identity is logged.

## First actual request and pending-response candidate

After both PCs applied the native adapter update, user reports a join error.
Host run 17:52:43 logs exactly one matchmaking-join-session-v1 followed by
unsupported-session-operation. Two real peers are registered; search and host
create/update still succeed. Native request dispatch is now runtime-confirmed.

LocalSessionJoinCodec is enabled only by the live catalogue probe and the
existing registered/ACKed transport gate. It binds all claimed member GUIDs to
the caller's registered profile, rejects self-join/other hosting/another pending
session and identity collisions, requires a public live record in the same
space, and reserves only a free slot (local policy: at most four total). A
byte-identical repeat reuses the reservation; a changed repeat is rejected.
Each advertised PRUDP game URL must have the registered host's observed IPv4
address and a valid port; URL lists are bounded to four. Auth port substitution,
external addresses and redirected routes are not accepted.

The candidate reply writes the original host game URL list as the first qString
and the current session plus a pending caller as the second output. Member state
0 is the native E4E520 constructor default, used as explicit LOCAL pending policy;
2 is the existing host and 3 remains unasserted. Neither this policy nor the first
string's precise semantic use is runtime-confirmed yet. Static D3FBFD passes
session data +1C as the string output; D48A1C initializes that same field before
RequestRendezVousSessionJoin. The candidate route interpretation must be checked
in the next real exchange, not presented as established Ubisoft server semantics.

Serialization completes before reservation publication. Projections merge only
owned pending metadata and reduce displayed free slots. Leave/disconnect removes
the caller's reservation; host teardown disposes the entire record. Guests still
cannot modify host settings. A pending caller cannot host concurrently. Existing
reliable ACK/retry/fragment/lifetime caps remain in effect. No success reports,
host notifications, match start or persistent state are fabricated.

Validation: 4,934 service checks, including independent wire parsing, every
truncation, identity/space/private/route/capacity rejection, rollback on failed
serialization, repeated requests, leave/disconnect/rejoin, and encrypted peers
in both host directions. Sixteen updater tests pass. The full installation
fixture passes update, idempotence, complete content verification and no-game
service preflight. Build: work/server-join-reservation. DLL SHA256:
8ccac3f143a3a205cb2bc0cc877cea9085fd255c0cef37822d1c666c8c56fc20.

outputs/S7-LAN-Dienst-Update.zip updates only Server/S7Patcher.dll and manifests,
retaining a backup under LocalData/Before-join-service-v1. It requires both
preceding menu and native adapter updates. Updated content ID:
5ca87dd0e322d9666bc001d680440a3e2896ad1133a1009a1f628f5c54cf014f.
Live deployment is pending both games closing; user was asked to apply the
service update on PC 2 and not restart yet. Original game files remain untouched.

Still needed: real client acceptance of the candidate reply, observed
JoinSuccess/HostSuccess semantics, native notifications, P2P connection and
real two-PC match startup/synchronization. JoinSession2_V1 is a distinct named
method; this parser must not be used for it by assumption.

## Paired service run: host route rejected

Both copies applied the pending-reply candidate. Run 18:15:08 confirms one
JoinSession_V1 rejected as local-join-host-route-invalid before serialization
or reservation. The client reports a join error. This does not test the
candidate response layout or member status. The retained creation route may
have an unsupported format or address; the existing event cannot distinguish
these causes, and neither is established yet.

The diagnostic follow-up preserves all acceptance conditions but emits fixed
sub-reasons for route length/ASCII, list structure, scheme/section/escaping,
syntax, address ownership and redirected routing. It discloses no raw route,
identity or payload. Tests verify reason propagation through TryJoin and no
encoder invocation or pending membership on rejection. Full fresh suite:
4,952 checks. Transactional updater tests: 16. Deliverable:
S7-LAN-Routen-Diagnose.zip, installed via Routen-Diagnose.cmd on both closed
test copies. This is a diagnostic update, not a claimed join fix.

## Native custom section support

Run 18:30:21 (20261026-183021-6bbcc395-lan-server.jsonl) confirms two registered
peers and one JoinSession_V1 rejected as local-join-host-route-section. The
real creation URL contains '#'; its exact custom keys/values remain unlogged.

Static inspection of the original hash-verified HE executable establishes:
E5E465..E5E488 finds '#' and rejects a second one. E5E48F..E5E4AE parses the
prefix with flag 0, then the suffix with flag 1. E5E500 splits ';', E5E53E finds
'=', and E5E572 selects the section. Prefix address and port are handled at
E5E583/E5E5BF; suffix key/value strings enter the separate map at object+0x20
(E5E665..E5E6A9). Serialization E5DC03..E5DC26 emits '#' when that map is nonempty.
The delimiter constants at 107182C, 113425C and 105AD74 are '#', ';' and '='.
No native execution, injection or game mutation was needed for this evidence.

TryReadGameRoute supports this single custom section only for game routes.
It validates bounded printable ASCII key/value pairs, rejects duplicates across
both sections and rejects routing names/redirect markers in the suffix as a
conservative local policy. Login/Register parsing remains unchanged. Host
ownership uses the parsed prefix; the original full string is retained in
metadata and the reply, including custom data. This fixes the unconditional
section rejection, but the next real run must still establish whether all
remaining route and capacity checks pass and whether the client accepts the
pending reply. No completed LAN membership or gameplay is claimed.

Validation: 4,986 fresh service checks, including an encrypted two-peer join
with a custom section, independent reply-string preservation, unchanged login
parser restrictions, malformed/duplicate/oversized section cases, and foreign
host rejection. The packaged updater verifies both service hashes and rejects
the wrong prior binary. Build work/server-join-url-section, service SHA256
f199c8da7bfe01d4729b7043ec9431dcdc365e3c13799039c26a81cca87cf4a0.
S7-LAN-Adress-Update.zip requires the preceding route diagnostic and changes
only the service/manifests, using the existing transactional updater. Deployment
and real-client acceptance are pending both games closing.

## Actual Storm descriptor instead of a prefix endpoint

The 18:40:40 run rejects section-invalid. Read-only inspection of the known
host helper's creation URL vector establishes that the prefix has RVCID only,
not address/port. The actual endpoint list is an Address block inside #Storm.
The targeted inspection emitted structure and endpoint categories, never the
complete route or identity values. One advertised endpoint matches the actual
UDP socket 192.168.178.125:3074; three other interface addresses are present.

Static D433D0 constructs the RVCID prefix and #Storm from CEBC60, then appends
RoutingOption. CEBC60 calls CEBD50 for the base descriptor and virtual+18 for
the derived fields. CEBD50 emits PeerGUID/Version and optional data; CEC1CA..
CEC242 emits Address with comma-separated endpoint strings via CB5840, then
PeerDescriptorBaseEnd. Consumer D4D170 reads Storm from the custom map with flag
1, sends the descriptor to CDEEE0 and separately parses RoutingOption as decimal.
This disproves the earlier assumption that every game URL has prefix address/port.

LocalStormRoute supports the observed ordered blocks PeerGUID, Version, Platform,
Gw, Address, PeerDescriptorBaseEnd, ProfileID, RoutingOption. This is an explicit
narrow local policy, not the complete native descriptor grammar. RVCID must match
the registered host. Gateway data is limited to the observed empty-gateway shape.
IPv4 endpoints must be canonical, bounded and unique; the projected join response
contains only endpoints whose IP matches the registered host, preserving the real
game port. Other descriptor fields are retained without treating their claimed
identities as authorization. Unknown forms fail with fixed reasons.

Projection changes only the owned join-response snapshot. Original registry
metadata and catalogue/Get output are unchanged. No invented authentication
endpoint, success notification or completed member state is substituted.
5,314 checks cover both encrypted host directions, original-record immutability,
reply filtering and replay, malformed/truncated descriptors and identity/address
rejection. A managed in-memory shape test accepts the actual live descriptor,
with synthetic registration identity, and retains only the bound host endpoint;
it is not evidence of real RVCID admission or a successful game join.

Build work/server-storm-route, service SHA256:
044931d88c501a11a792067af97935ba1a3920cb85c54fbf140f0c4948c2f787.
S7-LAN-Spieladresse-Update.zip requires the preceding Adress-Update. Both test
copies must be closed before applying; real-client acceptance remains pending.

## Signed native connection identifier

Run 19:12:37 rejects one real join as local-join-storm-connection-mismatch.
Guarded read-only inspection finds a negative int32 decimal in the host's
creation URL. Original EXE hash is unchanged. Setter E5EAE0 calls E5EA00,
which stores the 32-bit value in the numeric map at E5EA6E. Serializer
E5DB89..E5DBAA uses %s%s%d at E5DB9B: values with the high bit set become negative.
The previous uint.TryParse rejected that representation before comparing IDs.

The parser now recognizes canonical negative int32 and positive uint32 decimal,
reinterprets negative values as the same 32 bits, and still requires equality
with the registered host. It preserves the supplied spelling in the projected
reply and retains all endpoint checks. It rejects zero, negative zero, explicit
plus, leading zeros, whitespace, overflow and foreign connection IDs.
Deterministic checks cover 1, int.MaxValue, int.MinValue, 0xc0000001 and uint.MaxValue;
encrypted two-peer joins use int.MinValue and -1 in opposite host directions.
Full suite: 5,394 checks. S7-LAN-Kennung-Update.zip requires Spieladresse-Update.
This correction has not yet been tested with a real client; the observed error
alone does not establish equality between live registration and route ID bits.

## Empty descriptor profile field

Run 19:24:11 reaches local-join-storm-descriptor-values, so the preceding
registered RVCID comparison passed. Guarded read-only inspection of PID 33568
shows the expected ordered descriptor blocks, with ProfileID empty. Other
observed shapes match the supported format. Original-hash-checked native
C96F64..C96F96 writes ProfileID{ plus its string plus } without a length check.
C8FB60 finds both delimiters, copies their substring (including zero length)
at C8FBB4..C8FBE4, and returns true at C8FC03. This empty spelling is supported
by the game; our GUID-only validation incorrectly rejected it.

LocalStormRoute now accepts empty or valid D-format GUID ProfileID, preserves
the field exactly and does not use it for authorization. Nonempty malformed
values, foreign registered RVCIDs and foreign endpoints remain rejected.
Encrypted fixtures cover empty/nonempty profiles in both host directions,
including signed connection IDs. A read-only live-shape harness accepts the
current descriptor and retains only the expected host LAN endpoint. The harness
substitutes a synthetic registration ID; it is not a live admission test.
The real client still needs to test the candidate join response. Full service
suite: 5,463 checks pass.

Candidate service SHA256:
da48ed8c0751c482b6b85fb37a084336f2a19665792f0e515b5365c9665d478d.
S7-LAN-Profilfeld-Update.zip requires Kennung-Update. No adapter or archive changes.

## Second native gateway placeholder

Run 19:32:35 rejects descriptor-values despite installed Profilfeld-Update.
Read-only bounded snapshot of PID 51500 shows another gateway spelling and a
nonempty UUID profile. Static original-hash-checked B7B017 loads the literal
v(0)wk(-) at 10883B0, then passes it through CED160 at B7B043. The parser now
supports that exact no-endpoint sentinel alongside the prior empty gateway
shape. It does not admit arbitrary wk payloads, keys, versions or endpoints.
Fixed per-field rejection reasons replace the coarse descriptor-values reason.

Encrypted fixtures cover both host directions for all combinations of these
two gateway forms and empty/nonempty ProfileID, using signed RVCIDs. The live
shape harness accepts the current descriptor, with a synthetic registration
ID and projection to the expected host endpoint; actual join remains untested.
Build work/server-gateway-sentinel; service SHA256:
bc73ef4e21c4056f591d0fd210081be2cf73d0374f00671dde69a9eb9f29a297.
S7-LAN-Gateway-Update.zip requires Profilfeld-Update and changes only the service
and manifests via the existing transactional updater.
Full service suite: 5,546 checks pass; real-client acceptance pending deployment.

## First native reply followed by ReportJoinFailure

Run 19:41:59 passes route and reservation checks, queues a join response and
sends DATA. Transport acknowledgements follow; the client then sends
ReportJoinFailure_V1. UI reports session error 0. This establishes progress
beyond our previous validation rejections, not completed native join/P2P.

### Corrected report field meaning from the native caller (2026-10-26)

The first diagnostic inferred the two integers incorrectly from serialization
alone. Full caller tracing shows D3F9BE..D3F9D6 passes request-data +4 by value and
+8 by address through E4E2A0 to E52F70. E530BA..C4 emits the first; E530C9..D3 the
second. The same +8 supplies JoinSession_V1's session ID at D3FC05; D48A00 sets
+4 to zero on the RendezVous join path. The wire order is therefore Space,
kind/context selector, session ID, auxiliary result description. "Kind" is our
local name for that selector; its complete value domain is not established.
It is not an error code. ID ownership checks apply to the second integer.

The bounded parser now accepts kind zero and reads the correct session ID.
The original diagnostic had not been installed; its package is superseded.
One redacted observation per registered transport, matching pending owner,
registration, Space and ID; no mutation or RPC reply. Existing packet ACKs remain.

D3F98E invokes CC5700 on the result, which calls CC5640. That formatter emits
error group, colon, description, " (System error: " plus decimal value, and the
fixed suffix ") - No eresult string available.". CC4F20 selects a fixed group;
CC45F0 selects fixed descriptions. LocalJoinFailureDescription validates the
bounded format and maps selected known descriptions to constant categories.
Unknown/malformed text becomes unclassified. Raw text, identity, number spelling
and client-supplied strings never become event labels. The event records only
reported_session_kind, report_text_length, reported_failure_category and the
existing fixed observation reason. Numeric system codes are not logged.

5,746 checks pass. An independent literal-byte fixture places kind zero before
ID 0x11223344, catching the former reversal. Tests cover null/truncated qStrings,
format truncation and suffix/prefix injection, integer bounds, owner isolation,
encrypted reports in both directions, redaction, cap and no state/reply mutation.
Build server-join-report-layout; service SHA256:
21a0be26d73a39d163fe348793d481aeedd5ea6788bbacce69c062de927283ac.
Updated S7-LAN-Beitrittsbericht.zip still requires Gateway-Update, not the older
undeployed diagnostic. This is diagnostic preparation, not a native join fix.

### First response string: native consumer now identified

In D47080's continuation, D4752D saves request-data +18; D47606 restores that
pointer into EDI. D476F2 reads EDI+1C, the output string passed at D3FBFD.
E598E0 copies it; E4DD30 splits on the literal pipe at 10F826C and constructs
StationURL entries through E5D2D0. D47779 passes that list to D4D170, which reads
Storm, loads the descriptor via CDEEE0, and parses RoutingOption. D4781C then
calls D49B10 -> BABBD0 for the native join request. This confirms the output is
a game route list, rather than just an unexplained qString. It does not establish
that our exact descriptor projection or pending member state is accepted.

BABBD0 also has an earlier native engine gate: C0A000 must return an object,
and its +8 object's +4 state must equal 3 (BABBF0..BABC04). Otherwise it returns
the generic failure 0xFFF0BDC0 at BABCB6 without queuing the native request.
On success B7AED0 builds the request and BABC73 submits it to the engine.
This is a candidate boundary to inspect, not evidence that PC 2 failed it.

The failure report is sent only on the non-positive result branch at
D3F92D..D3F984; the positive branch uses the neighboring report wrapper E4E2C0.
Both branches use the same kind/ID fields. The actual failure description from
PC 2 remains unknown because the installed old service discarded the body.
No memory injection, native function invocation or new game launch was used.
