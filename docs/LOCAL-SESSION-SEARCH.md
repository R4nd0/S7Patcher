# Local empty session search

The 2026-10-26 separate-copy test confirmed six exact
`MatchmakingProtocol::SearchSessions_V1` request headers after Login/Register.
The diagnostic service rejected them under its two-response policy. This
proves the real search reaches the local endpoint; it does not prove a working
response, hosting, joining or LAN gameplay.

## Native wire layout

Static anchors below apply only to HE 1.12.1395, original executable SHA-256
`4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`,
preferred x86 image base `0x400000`. No binary or disassembly is distributed.

The request uses the established length-prefixed named RPC envelope. After
protocol, request flag, opaque call ID and method name, `E53703..E53758` emits:

1. A class-version map. `E4EB60` inserts `MatchmakingSession`, version 1;
   its tail call to `E57D30` inserts `MatchmakingSessionMember`, version 1.
   Both entries are emitted by `EB0D00` (u32 count, DDL string/u16 pairs).
2. Two qStrings, via `EAFCB0` at `E5372E` and `E5373A`.
3. A string/Variant map, via `E4EAD0` at `E53746`: u32 count, DDL key,
   `EB0230` tagged value per entry.
4. A four-byte scalar requested limit, via `E673B0` at `E53758`.

The implementation checks this complete shape without decoding or retaining
argument values. It requires each known version entry once, supports the
already traced variant tags 0..7 and caps filters at 64. Those bounds are
local test policy, not a universal claim about the game's protocol. Unknown
extensions, unsupported tags, truncated fields and trailing bytes are rejected.

Response dispatch at `E55713..E55767` compares the exact method name with a
literal `*` suffix, then invokes `E56170`. That reader consumes two output slots:

- Slot 0: `E53DB0` clears a session list, reads a u32 count at `E53DEC`,
  and skips its element loop when count is zero (`E53DF6 -> E53E5C`).
- Slot 1: `E54960` clears a map and reads its u32 count at `E549FB`;
  zero skips all entries (`E54A05 -> E54A82`).

The response uses the same generic success envelope as Login/Register:
u32 payload length, DDL protocol, byte 0 (response), byte 1 (success), echoed
opaque u32 call ID, DDL `MatchmakingProtocol::SearchSessions_V1*`, followed by
two zero u32 counts. The complete empty response is 82 bytes. There is no
server-side session catalogue yet, so both empty collections are accurate.

## Bounded service behavior

Only the opt-in `--local-keepalive-probe` service enables this handler. It
requires successful Login/Register responses and acknowledgement of both.
Baseline `--local-login-probe` still permits only its two login responses.
Search has a separate cap of 32 responses per peer, at most two outstanding
DATA responses, and the existing four-transmission retry policy. Duplicate
transport fragments do not repeat application replies. Unknown services and
invalid request bodies receive no fabricated success.

The existing two-minute idle and twenty-minute hard limits remain. Search
responses do not increase the login-response counter or disable keepalive.
Plaintext requests/responses and acknowledged ciphertext are cleared; fixed
status categories contain no call IDs, namespaces, filters or packet bodies.

## Validation and remaining work

The service builds without warnings. The full suite passes 1,924 checks,
including a fixed empty-response wire vector, truncated/invalid requests,
1,000 random bodies, all supported variants, baseline/registration gates,
the response and pending limits, retransmission/ACK cleanup, and a real
encrypted loopback Login/Register/Search exchange. Synthetic success is not
evidence that the game consumed the response.

The following live test recorded 16 search replies and 18 response ACKs
including Login/Register, with zero rejections/expirations. The game stayed
connected and open. This establishes transport delivery; its internal search
completion callback has not been directly observed. Attempting to create a
session then failed at the game's separate readiness gate before any new RPC.
The subsequent classifier additions pass 1,926 server checks and explicitly
reject create requests in the empty-search handler.

Hosting, catalogue state, join semantics, match startup and transport between
two computers are still absent. All current endpoints remain loopback-only.
