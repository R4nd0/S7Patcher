# Local session creation experiment

## Live evidence and limits

On 2026-10-26, the native create gate from `7b5bbd9` sent two real
`MatchmakingProtocol::CreateSession_V1` requests to the loopback service.
The previous service rejected both because it only answered empty searches.
The user also reported that the create button is disabled/missing on the first
session-list visit and enabled on the second.

The new service allocates a bounded, memory-only session record before sending
the native u32 session-ID response. This is not yet a functional lobby or LAN:
session detail serialization, updates, membership, joining and match startup
remain unimplemented. `GetSession_V1` has a fixed diagnostic label, not a reply.
The live game acknowledged the new create response at transport level; complete
lobby creation remains unverified.

## Verified wire layout

Addresses refer to the original fingerprinted HE executable in
`NATIVE-LOCAL-START.md`, preferred base `0x400000`. No binary data is distributed.
The named request envelope contains the protocol, request discriminator,
opaque call ID and method name. After `CreateSession_V1`, writer `E51940`
emits the following fields:

| Field | Wire representation | Writer evidence |
| --- | --- | --- |
| Class-version map | u32 count zero | `E51A63..E51A76`, `EB0D00` |
| First string | qString: u16 byte length including trailing zero; zero is null | `E51A82`, `EAFCB0` |
| Attributes | u32 count; qString key and Variant value | `E51A8E`, `E4EAD0` |
| Second string | qString | `E51A9A`, `EAFCB0` |
| Identifier list | u32 count, 16 bytes each | `E51AA6`, `E51480` |
| Scalar | u32 | `E51AB8`, `E673B0` |
| Nested maps | u32 count; qString key; u32 count; 16-byte key and Variant | `E51AC4`, `E4EA40`, `E4E9B0` |
| Flag | one-byte bool | `E51AD2`, `E672C0` |

Variant tags follow the search codec: 0 has no payload; 1, 2, 5 and 6 have
eight bytes; 3 has one byte; 4 has a qString; 7 has sixteen bytes.
The original response dispatcher matches the method with a literal `*` suffix
at `E54AE9` and decodes exactly one four-byte output at `E54B24..E54B34`.
The reply uses response=0, success=1 and the original call ID.

Field contents remain opaque; names, claimed identities and speculative field
semantics do not grant ownership. `CreateSession2_V1` remains unsupported.

## Bounded state and cleanup

- One registry is shared by the service's registered transport peers. The
  existing single UDP loop provides serialization; no background registry work.
- At most eight records, at most one per transport owner. The complete validated
  body is copied to owned memory. No raw bodies, IDs or field text are logged.
- Limits: 64 top-level attribute/map entries, 256 GUID/member-map entries,
  at most 65,536 bytes per body and full consumption. These are experiment
  bounds, not claims about the game's player limits.
- IDs are nonzero, monotonically increasing for the service lifetime, excluding
  `0xffffffff`. An identical application retry returns the same stored ID with
  the new call ID; changed arguments from the same owner are rejected.
- Records are removed and buffers cleared when the owning transport is disposed
  or expires. Service shutdown clears the entire registry. Records are not saved.
- Create and search share the existing 32-response budget and two-packet pending
  window; opt-in keepalive and acknowledged registration remain prerequisites.
  The existing retransmission, idle and hard-lifetime limits remain intact.
- Once any peer has created a record, searches are explicitly unsupported until
  real session serialization is implemented. They must not report a false empty
  catalogue. An unsupported request currently receives no application reply and
  can still time out in the client.

## First-visit create button

The original `sessionList.lua` initializes `NATReady=true`, then disables create
and quickmatch only on the transition to false. Reopening the screen recreates
enabled buttons but retains false readiness, so the disabling branch does not
run again. The second-visit behavior was accidental.

Three fingerprinted archive deltas remove create from those NAT transitions and
refresh it from the existing `Network.IsLoggedIn()` query on every menu update.
Quickmatch and join retain their original NAT checks. This does not alter the
native create gate or force a login/readiness flag. Existing fast-start and
promotion deltas remain. The two changed Lua files and all 284 archive files
are checked against the expected contents; the patched Lua parses successfully.

## Validation / next live check

Synthetic tests cover malformed/truncated bodies, supported Variant shapes,
capacity, independent owners, idempotence, exact reply bytes, encrypted transport
retransmission and ACK clearing, registration gates, shared-catalogue consistency,
owner expiry and redacted events. These do not establish game compatibility.

The candidate from `d100dab` was deployed after the user closed S7 and a host
process check confirmed it was no longer running. The launcher lock, expected
previous archive hash, all staged service files and updated bundle fingerprints
were checked. The previous archive and launcher are retained for rollback.
The test launcher selects `Server-Create-Records`; the native adapter is unchanged.
The no-game-launch preflight passed. The user has been asked to check the first
session-list visit, attempt creation once and leave S7 open. Inspect response
acknowledgements and subsequent fixed RPC labels before claiming live success.

### Live create response and subsequent blocker

The subsequent run confirmed the first-visit button is immediately active.
The service received three create requests: one allocated a record, an identical
retry returned the same ID, and changed arguments were rejected because that
transport already owned a record. Both create replies were acknowledged. Two
searches and Login/Register also received replies and acknowledgements.

After the first create response, the client sent one previously unclassified
Matchmaking request. It was not `GetSession_V1`, which already had a fixed label.
The old dispatcher misleadingly reported it as an unsupported nonempty search.
The current diagnostic classifies all 40 method names present in the supported
executable using fixed labels, never arbitrary method text or arguments. It
rejects unsupported operations explicitly before checking search catalogue state.
It does not implement any additional operation or alter the eight-observation cap.

Validation: 2,499 service checks and 20,288 isolated RPC codec assertions pass;
the build has no warnings. `Server-Create-Followup` is staged and its files match
the build. The test launcher selects it on the next start, retaining the previous
launcher as `LocalData/Test-Lokale-Anmeldung-before-create-followup.cmd`. The
running game, adapter and archive remain unchanged. The next run must identify
the exact follow-up operation after a single create attempt; do not infer it from
the generic old rejection reason.
