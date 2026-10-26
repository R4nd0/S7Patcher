# Nonempty catalogue: native layout and remaining mappings

This is a static investigation, not an enabled response handler. It follows the
live-verified create/update/leave/recreate implementation. All addresses refer to
the original HE executable hash documented in `LOCAL-SESSION-SEARCH.md`, using
preferred base `0x400000`. No game code or packet bodies are included here.

## Confirmed outer shapes

`SearchSessions_V1*` consumes a session list followed by a map. Its list reader
`E53DB0` reads a u32 count, constructs each native session at `E53DFB`, and calls
`E4F100` at `E53E0C` for each element. The second collection (`E54960`) contains
u32 keys (`E54A20`) and qString values (`E54A2A`). The map carries session ID -> pipe-separated StationURLs: the consumer looks
up the session ID at D48170/D4817B, copies its qString at D4818D and passes it
to E4DD30 at D48792. E4DD30 splits on `|` (E4DD76/E4DD8B) and constructs each
StationURL at E4DDB8 via E5D2D0. That constructor's StationURL.cpp allocation
anchor is E5D356 and it parses its input at E5D39E. Do not omit this map or use
it for arbitrary reason strings. Individual supported URLs now reject `|`.

`GetSession_V1*` dispatches through `E55D40`. It obtains output slot zero and
passes the existing or temporary session object to `E4F100` (`E55D6D`/`E55DA8`).
There is no extra list count in the GetSession return body.

## Session body reader

The native session object occupies 0x50 bytes, including non-wire implementation
fields. `E4F100` reads the following wire fields in order. Object offsets are
labels for the investigation, not invented application semantics.

| Native offset | Wire shape | Reader anchor | Established meaning |
| --- | --- | --- | --- |
| +08 | u32 | E4F118 | Session ID, copied into internal session state at D48729..D4872C |
| +0C | u32 | E4F127 | Unresolved |
| +10 | qString | E4F131 | Unresolved |
| +18 | packed DateTime u64 | E4F143 / E66CF0 | Representation verified below; event semantics unresolved |
| +20 | u32 | E4F16A | Unresolved |
| +24 | u32 | E4F179 | Unresolved |
| +28 | boolean | E4F184 | Unresolved |
| +29 | boolean | E4F18F | Unresolved |
| +2C | member list | E4F199 / E4EB80 | Member records described below |
| +38 | map qString -> Variant | E4F1A3 / E4EF90 | Session attributes used by game |
| +44 | map qString -> map GUID16 -> Variant | E4F1AD / E4EDC0 / E4EC50 | Member metadata shape |

The attributes reader calls `EB0630` for each key and `EB0810` for the Variant
at `E4F060`/`E4F06A`. The nested map reader reads its outer key at `E4EEA1` and
invokes the GUID-keyed inner reader at `E4EEAB`. These mirror the metadata maps
already accepted in create/update requests.

A member record (`E57D50`) reads GUID16 into member +04 (`EB04F0`, `E57D5E`)
and a u32 into member +14 (`E57D71`). Two native predicates compare that scalar
with exactly 2 (`E4E560`) and exactly 3 (`E4E570`); it is not a boolean or a
proven bitmask. `E4D800` selects the first member satisfying the value-2 predicate
and returns its GUID. `E4D860` collects GUIDs satisfying the value-3 predicate.
The exact role/status names and transitions still need confirmation.

## Actual search-result consumption

`D48120` walks the returned list. Its current list node is EDI and the embedded
session begins at EDI+08. Consequently EDI+10 is session +08, and EDI+40 is its
attribute map (+38), not member data.

The consumer explicitly looks up these attribute keys:

- `echo_session_guid` at D48192/D48247; absence takes a skip path.
- `session_descriptor_type` at D482D8.
- `settlers_session_name` at D48525.
- `settlers_map_name` at D485B9.
- `settlers_max_slots` at D48627.
- `settlers_free_slots` at D4867C.
- `settlers_extra_version_number` at D486D1.

It copies the returned session ID into an internal session object at
`D48729..D4872C` and obtains a member GUID through `E4D800` at `D48763` and
`D487F4`. A response containing only a fabricated ID/title is insufficient.
The stored and updated metadata therefore matters to actual list display.

## Packed date representation

E66CF0 copies the u64 without conversion. E66D70 reads GetLocalTime at E66D7C
and packs year (14 bits) at bit 26, month (4) at bit 22, day (5) at bit 17,
hour (5) at bit 12, minute (6) at bit 6 and second (6) at bit 0.
Getters E66D20/E66D30/E66D40/E66D50/E66D60/E66E40 corroborate these fields.
This establishes encoding, not whether session +18 is creation or update time.

## Registered host state implemented

LocalLoginRpcEngine now retains its selected, observed-endpoint registration
URL after successfully encoding Register. TryCopyRegisteredPeer exports an
independently owned profile GUID, generated connection ID and selected URL only
after registration, never from request-supplied session/member metadata.
The transport's existing Register ACK gate still applies to create operations.
Create requires that engine and stores its host snapshot with the record. An
identical replay cannot substitute a different registration. Metadata updates
leave the host unchanged; leave, owner teardown and shutdown dispose it.
Caller-owned snapshots survive registry removal and must be disposed separately.
Profile buffers are zeroed; managed URL references are released (immutable
strings cannot be guaranteed overwritten). No identity or address is logged.
The observed authentication transport endpoint is NOT a replacement for the
game StationURLs. The game's Create second string supplies those separately;
see the verified producer chain below.

The candidate builds without warnings/errors and passes 3,100 service checks,
including 31 new host-binding checks across direct and encrypted transport
paths. The separate login-engine suite passes 477 checks. The new tests cover
registration gates, response/profile consistency, observed address replacement,
URL separator rejection, mismatched registration on replay, unchanged host on
update, independent snapshot lifetime, zeroing and removal. These are synthetic
results, not a live nonempty-catalogue or LAN result.

## Creation StationURL producer and retained inputs

The Create second qString is a serialized StationURL list, not a session title.
At D3E9CF, D433D0 builds the list; E4DE00 serializes it at D3E9E5, the text is
stored in request state +1c at D3E9F4/D3E9FB, and D3EA80/D3EA83 passes that
string to Create via E4DD10 at D3EA92. Its scalar comes from an internal object
+7c (D3EA1C), and its flag is literal true (D3EA5E). The second create path also
serializes the list at D3F460 and passes it at D3F4EC/D3F4EF, but uses scalar
32 at D3F4C7. This does not yet prove the scalar's semantic name.

D433D0 constructs `prudp:/` at D43413/D4341B, sets a connection value through
E5EAE0 at D43437 (that routine references `RVCID` at E5EB02), and adds the
`Storm` field at D434E3/D43505. Its content includes the game's `RoutingOption{`
serialization (D4344A). E4DE00 joins multiple URLs with `|` at E4DE7D..E4DE88.
The consumer uses the same format (E4DD30). Merely advertising the authentication
socket's observed endpoint would therefore lose the game's routing information.

Creation-only fields are now preserved in LocalSessionMetadata.Creation:
the original StationURL bytes, raw identifier-list bytes, the still-opaque u32
scalar and boolean flag. The parser copies them only after full validation;
updates preserve them, snapshots clone them and disposal clears their buffers.
The existing 65,536-byte input and 256-identifier limits apply. These bytes do
not authorize a host or trigger outbound traffic. No StationURL routing/filter
policy is implemented by their preservation, and no claim is made that the
login URL parser accepts the game's separate Storm format.

Build `work/server-session-routing` passes 3,142 service checks, including 42
new checks for creation-field retention, input/snapshot isolation, empty/null
inputs, maximum identifier count, update/replay and cleanup. It is not selected
in the launcher. The active live-verified service remains the leave/recreate
build; neither native adapter nor UI archive changed.

## Next implementation requirements

1. Trace the unresolved scalar fields to their state sources; distinguish native facts from an explicit local server policy.
2. Use the registered host snapshot for member identity and the creation
   StationURL list for game routing. Validate route ownership and supported local
   routing separately before advertising it. Never infer ownership from metadata
   GUIDs or substitute the authentication socket for the game route.
3. Serialize a bounded registry snapshot with the latest attributes and member
   metadata. Respect Space, the request's selector/filter semantics and result
   limit. The current empty-only parser deliberately does not implement filtering.
4. Check response size against the existing single-packet transport limit; do
   not truncate records or claim successful catalogue delivery on overflow.
5. Validate the actual client consuming a nonempty response before implementing
   join/status transitions and broadening loopback-only binding to a deliberate
   LAN configuration. A second Windows PC with HE is available for that later test.

The host-binding and game-routing-storage candidates are built but not selected
in the game launcher. The active tested
service remains `48f7b2a`, with successful lobby lifecycle and AI selection but
without a nonempty catalogue, second-client join or verified match startup.
