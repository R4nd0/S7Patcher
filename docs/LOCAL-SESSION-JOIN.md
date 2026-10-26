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
