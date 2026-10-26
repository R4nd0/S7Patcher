# JoinSession_V1 wire evidence and remaining work

Original HE fingerprint remains the one guarded by the adapter. Static reads
only; no game function was manually invoked and no diagnostic library injected.

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
