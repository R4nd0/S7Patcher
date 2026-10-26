# Local host leaving a session

## Observed failure

After the successful lobby run, the service observed `LeaveSession_V1` and
rejected it as unsupported. Subsequent searches were rejected because the
catalogue still contained the record, and another create attempt was rejected
as already hosting. Leaving the UI did not remove the server-side record.

The new handler removes only a record matching the registered transport owner,
Space bytes and session ID. No joined-client or host-migration behavior is
implemented; this is explicitly the current host-only prototype. The flag and
trailing string are validated opaque fields, not authority to remove other
records. Future participant support must extend this policy before enabling join.

## Native layout

Addresses refer to the existing hash-guarded History Edition EXE at preferred
image base `0x400000`. The writer names the method at `E52565`.

| Request field | Encoding | Writer evidence |
| --- | --- | --- |
| Class-version map | u32 zero | `E52592..E525B6` |
| Space | qString | `E525C2`, `EAFCB0` |
| Session ID | u32 | `E525CD..E525D4`, `E673B0` |
| Opaque flag | normalized boolean byte | `E525DF`, `E672C0` |
| Opaque trailing field | qString | `E525EB`, `EAFCB0` |

`E672C0` normalizes its input to 0/1 and writes one byte. The response dispatcher
matches the suffixed method at `E54D16..E54D2A`, then jumps at `E54D4A` straight
to `E558AE`. It consumes no output fields. The reply is therefore the named
success envelope with echoed call ID and `LeaveSession_V1*`, without a body.

The bounded parser consumes all fields and rejects truncation, extra bytes,
nonzero class versions, invalid booleans and reserved IDs. Removal clears the
record's creation data, Space and metadata buffers. A later create receives a
new ID, so a delayed leave cannot delete a replacement record. Transport retries
use the existing reliable assembler and cached ciphertext; a new application
request targeting an already absent record is rejected, not treated as a fresh
successful leave. No unbounded tombstone cache is introduced.

Leave shares registration acknowledgement, opt-in, pending-window, retry,
lifetime and 32-response limits with create/update/search. Budget checks precede
state mutation. Logs contain fixed operation/event/reason labels only.

## Validation and next live check

All 3,069 service checks pass; the service build has zero warnings/errors.
New cases cover exact void response layout, malformed input, foreign owners,
wrong Space/ID, disposal, stale leave after recreation, encrypted retransmission,
ACK clearing, search/recreate on the same transport and exhausted response budget.

`work/server-session-leave` is staged as `Server-Session-Leave`. All ten staged
files match the tested build. The test launcher now selects it; its previous
contents remain in `LocalData/Test-Lokale-Anmeldung-before-session-leave.cmd`.
Bundle fingerprints pass. No native adapter or game archive changed. The active
game, if any, continues on its old service until the user restarts.

Live leave/return/search/recreate is still unverified. Request a fresh test run,
creation on a four-slot map, leaving the lobby and creating again without
restarting. Inspect the leave reply/ACK and resulting subsequent operations.

## Separate original UI restrictions

The decoded original `hostLobby.lua` explicitly enables its third slot-choice
button (Against computer) only when `Network.GetNbPlayerSlots() ~= 2`.
The user's screenshot shows a local named host and one free slot on a two-slot
map, matching that disabled-button rule. This is not evidence of a missing local
human identity or a server-side AI failure. Test AI selection on a four-slot map.

Separately, the Start callback requires `otherHumanInSession`; the slot refresh
sets it only for a named human outside slot 1. AI does not satisfy it. The
original message directs single-human AI matches to skirmish. Earlier advice to
test multiplayer startup with only AI was incorrect. Neither rule is patched;
successful AI selection would still not establish playable multiplayer. Joining,
nonempty search, session-detail serialization and a real second-client match
remain outstanding.
