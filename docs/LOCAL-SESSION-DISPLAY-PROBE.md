# One-client session display probe

This opt-in experiment exercises a nonempty SearchSessions_V1 response in the
real client. It is **not a live catalogue, join handler or LAN implementation**.
Normal `--local-keepalive-probe` behavior remains unchanged. Enable only with
`--local-session-display-probe` (which includes keepalive/login support).

## Test procedure

Use the separate test-copy starter `Test-Sitzungsanzeige.cmd`. Create a lobby
on a four-slot map, then leave it and return to the session list. Look for
`Anzeigetest - kein Beitritt`. Leave that screen open; do not try to join the
diagnostic row. Report whether the row appears, the list stays empty, or an
error occurs. A response ACK is delivery evidence, not proof of UI display.

The user starts/stops the game. No new native adapter or UI archive is involved.
The ordinary starter still selects the live-verified leave/recreate service.

## Explicit diagnostic policy

Only a successful, exact-owner Leave captures the most recent metadata and
registered-host snapshot. It still deletes the real session. The diagnostic
copy is separate from active records, cannot be updated/left/joined, and is
visible only to the **same transport owner and exact Space**. Recreating a
session, disconnecting, expiring or shutting down clears it. Maximum eight
copies, one per owner; no persistence, body/address/profile logging or outbound
lookups. Independent caller-owned snapshots are disposed after serialization.

The query must fully validate, have selector `default_query` and limit > 0.
Group searches (`string4` string `Group`) receive no diagnostic row. All other
filters are intentionally bypassed **only in this explicit display experiment**;
this is not a claim about Ubisoft's default_query filtering/ranking semantics.
Duplicate filter keys are rejected by the shared typed query reader. Empty
catalogue responses retain their existing wire layout.

The single row copies the client's actual descriptor type, session GUID text,
map, slots, version and nested metadata. Its title alone becomes the diagnostic
label. It uses the completed registration's profile with native member scalar
2, whose predicate selects the GUID consumed by the search-result handler.
The ID-to-StationURL map copies that owner's creation-time game route. It never
substitutes the authentication endpoint or another owner's supplied identity.
Echoing a route back to its creator is not cross-client route validation; that
remains necessary before a live catalogue/LAN mode can be enabled.

The unresolved session scalars use **verified native constructor defaults** as
an explicit display-test policy, not guessed production server semantics:
E4D5B0 initializes +0c/+20/+24 to zero and +28/+29 false; +10 is an empty
qString. Its +18 constructor call at E4D5F8 goes to 4C7B10, which clears both
u32 halves. Native search consumption D48120..D48ABE directly uses the ID,
metadata maps and member selector; this bounded observation does not establish
that join/GetSession or other consumers ignore the unresolved scalars.

The response is built in a fixed 65,536-byte buffer. Overflow rejects the
whole response, never a truncated success. Buffer contents and serialized
temporary replies are zeroed. The existing reliable fragment queue transports
the reply, with unchanged registration ACK gate, response budget and lifetime.

## Additional static evidence

- D3C660 constructs helper strings `default_session` (+00) and `default_query`
  (+04), at D3C67E/D3C68B. D4A860 sets the first to `default_session_<SpaceId>`
  through D4A8C6/D4A8CE. The second request string is a query selector, not a
  session name.
- D400E0 inserts `search_score` into a game search; D3E6B0 also inserts `string4`
  with string `Group` for group search. Ranking/filter semantics remain open.
- D41E7C uses the qString Variant constructor E5A960 for `echo_session_guid`.
  D4827E reads it through E5B330 before parsing the text. Do not encode this
  metadata key as the member-record GUID16 field.
- D41EFC uses E5AA10 for `session_descriptor_type`; that constructor sets
  Variant tag **6**, stores the uint and clears its upper u32. Max slots at
  D41D23 and extra version at D41DDD use the same constructor. E5A9F0 uses tag
  1 for a sign-extended integer. No arbitrary descriptor type is invented:
  the search consumer passes the supplied type to factory BA29B0 at D483EA.

## Validation

Build `work/server-session-display`: zero warnings/errors; **4,373 service
checks pass**. Deployed service files and separate launcher match source/build
hashes; game EXE/adapter/archive fingerprints are unchanged. A two-second
ephemeral-loopback startup/shutdown of the deployed service passes. Live user
test is pending; the ordinary launcher still selects the previous service.

Tests independently walk the native response layout with BinaryReader, check
the registered identity and exact game-route map, preserve the original title,
exercise updated/nested metadata, owner/Space isolation, Group/zero-limit and
selector handling, malformed/truncated queries, duplicate filters, missing
required fields/routes, response overflow and snapshot cleanup. Encrypted
create -> leave -> search tests check ciphertext retry, ACK clearing and
transport-teardown removal. CLI tests cover the opt-in switch and disclosure.

The first live run delivered six nonempty responses, with all 20 emitted DATA
packets acknowledged in the inspected sample. The user reported that the list
remained empty. A read-only snapshot identified the active result callback as
C9E8E0 (delegate type 1093C4C via CA8DB0). It has duplicate/connection-identity
rejection paths; these need investigation before treating a same-owner row as
a valid display test. No callback execution or successful deserialization has
been established by the snapshot or transport ACKs.

Live display, GetSession/join, a real nonempty catalogue, filter semantics and
match startup remain unverified. Constructor defaults are not authorization to
enable them in the ordinary service.
