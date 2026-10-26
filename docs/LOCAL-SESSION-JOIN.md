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

TryReadJoinBody now validates this request shape with bounded copied metadata,
class/version uniqueness, duplicate-map rejection, exact end and ID policy.
It is deliberately not wired to a successful reply or registry mutation yet.
Tests cover both class orders, every truncation, copies surviving input disposal,
empty metadata, duplicate classes/groups/members, invalid version/ID/count,
trailing data and aggregate size. No host/guest identity is logged.

Still needed: bind claimed member keys to the registered caller, public-session
and capacity/space rules, atomic pending member lifecycle, disconnect/leave and
replays, host-route ownership validation, observed JoinSuccess/HostSuccess
semantics, native notifications and real two-PC match startup. JoinSession2_V1
is a distinct named method; this parser must not be used for it by assumption.
