# Local session metadata updates

## Evidence

The 2026-10-26 run using the follow-up diagnostic (`cb9c032`) completed local
Login/Register, one empty search and one create response, all acknowledged.
It then issued two `MatchmakingProtocol::UpdateSession_V1` requests, rejected
because that operation was missing. The create button was already live-verified
as immediately available on the first session-list visit.

This implementation addresses those updates. The user has now reached a local
lobby with player slots. Session detail serialization, joining and a playable
LAN match remain unimplemented or unverified.

## Native wire shape

Addresses use the guarded original HE executable and preferred base `0x400000`.
The writer labels `UpdateSession_V1` at `E53B25`. After the named RPC header:

| Field | Encoding | Evidence |
| --- | --- | --- |
| Class-version map | u32 zero | `E53B52..E53B76` |
| Space | qString | `E53B82`, `EAFCB0` |
| Session ID | u32 | `E53B8D..E53B94`, `E673B0` |
| Attributes | map of qString to Variant | `E53BA0`, `E4EAD0` |
| Member metadata | map of qString to map of GUID16 to Variant | `E53BAC`, `E4EA40` |

There are no additional request fields. The response dispatcher at `E54C1C`
compares the method with the literal `*` suffix, then jumps at `E54C50` directly
to the common epilogue `E558AE`. Unlike CreateSession it decodes no return
parameters. The success response therefore contains only the named envelope,
response/success discriminators, echoed call ID and suffixed method name.

## State policy

The shared registry now parses the initial create metadata and updates through
one bounded reader. The original create body remains available for idempotent
create retries. Updates must match all three: session ID, exact transport owner
and Space bytes. Null and empty qStrings normalize to the same empty key/value.
No supplied GUID, player name or attribute grants ownership.

The prototype applies updates as per-key replacements, retaining unspecified
attributes and unspecified member entries. Variant values remain opaque encoded
bytes, including explicit tag 0. This is the local service's state policy; full
compatibility with later GetSession serialization and every Variant's semantic
meaning remains to be established. Empty maps make no changes.

Updates use a copied candidate state and commit only after aggregate validation.
A rejected update cannot partially modify the old state. Repeating an identical
update is idempotent. Snapshots are independent owned copies, available only to
the owner, for a future GetSession serializer; no network getter is added here.

Limits apply both to input and accumulated metadata: at most 64 attribute keys,
64 member-map groups, 256 GUID entries per group, and 65,536 bytes of encoded
metadata. Duplicate keys in one request, malformed variants, truncated fields,
extra bytes and unknown class versions are rejected. IDs, names and values stay
in process memory and are never logged or persisted. Value buffers are cleared
on replacement, rejected merge and disposal; key strings are released when their
containers are cleared. Owner expiry/removal clears creation and metadata state.

Updates share the existing 32-response budget, two-response pending window,
registration ACK gate and retry/lifetime policy. Successful replies have the
fixed event `local-session-update-response-queued`. Unsupported operations still
receive no application reply; the game can still show an error at a later step.

Diagnostic observations are now capped at eight **distinct fixed operation
labels** per transport, rather than the first eight messages. Repeated searches
or updates cannot exhaust the labels before the next operation arrives. No raw
method names or arguments are introduced into logs.

## Verification and deployment

Tests cover malformed input, all supported Variant encodings, exact void reply
layout, foreign owners, wrong space/ID, initial create metadata, independent
snapshots, nested merges, repeat calls, aggregate count/byte limits, atomic
rejection, teardown, encrypted DATA retries/ACK clearing and the shared response
cap. The live game subsequently acknowledged an update response from this build.
All 2,834 service checks pass; the build has no warnings or errors.

Build: `work/server-session-update`. The separate test service is staged in
`Server-Session-Update`; the launcher selected it for the successful lobby run.
The previous launcher remains in
`LocalData/Test-Lokale-Anmeldung-before-session-update.cmd`. No native adapter,
game archive or original installation changes were needed.

Live result with `95603b5`: the user reported a lobby with player slots. The
service sent five replies (Login, Register, search, create and update), all
acknowledged, with no rejection in the observed sample. This establishes lobby
creation, not a playable match or second-client join. The next user test is to
start a match from that open lobby, using AI/closed slots if required. Inspect
the next operations and actual game behavior before extending the service.
