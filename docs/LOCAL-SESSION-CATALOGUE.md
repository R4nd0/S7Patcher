# Nonempty catalogue: native layout and remaining mappings

This is a static investigation, not an enabled response handler. It follows the
live-verified create/update/leave/recreate implementation. All addresses refer to
the original HE executable hash documented in `LOCAL-SESSION-SEARCH.md`, using
preferred base `0x400000`. No game code or packet bodies are included here.

## Confirmed outer shapes

`SearchSessions_V1*` consumes a session list followed by a map. Its list reader
`E53DB0` reads a u32 count, constructs each native session at `E53DFB`, and calls
`E4F100` at `E53E0C` for each element. The second collection (`E54960`) contains
u32 keys (`E54A20`) and qString values (`E54A2A`). The semantic purpose of that
map is not yet proven; it must not simply be dropped from nonempty results.

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
| +18 | eight bytes, then native conversion | E4F143 / E66CF0 | Unresolved representation/meaning |
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

## Next implementation requirements

1. Trace the unresolved scalar fields and the second search-output map to their
   state sources; distinguish native facts from an explicit local server policy.
2. Preserve the registered peer's generated profile identity and selected
   endpoint in bounded transport-owned state before projecting member records.
   Never infer ownership from supplied metadata GUIDs.
3. Serialize a bounded registry snapshot with the latest attributes and member
   metadata. Respect Space, the request's selector/filter semantics and result
   limit. The current empty-only parser deliberately does not implement filtering.
4. Check response size against the existing single-packet transport limit; do
   not truncate records or claim successful catalogue delivery on overflow.
5. Validate the actual client consuming a nonempty response before implementing
   join/status transitions and broadening loopback-only binding to a deliberate
   LAN configuration. A second Windows PC with HE is available for that later test.

No service or game change is deployed by this investigation. The active tested
service remains `48f7b2a`, with successful lobby lifecycle and AI selection but
without a nonempty catalogue, second-client join or verified match startup.
