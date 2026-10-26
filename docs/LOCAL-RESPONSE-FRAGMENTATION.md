# Bounded outgoing response fragmentation

The next catalogue must not be constrained to the previous one-fragment response
cap. ReliableResponseQueue now supports up to 65,536 plaintext bytes per logical
response while preserving the conservative 947-byte per-fragment bound.

## Native evidence and local policy

The wire format follows the already inspected reliable sender EBA7B0:
EBA8D1..EBA8EA assigns nonfinal parts 1, 2, ... and final part 0. Unfragmented
messages use part 0. EBA5C0 concatenates independently transformed plaintext
fragments; see RPC-FRAMING-PROTOCOL.md and DATA-CRYPTO-PROTOCOL.md.
DATA ACK construction echoes sequence at EBBD04..EBBD12 and part at
EBBD16..EBBD1A. ACKs must match the queued part as well as sequence and the
existing context/checksum checks. The native ACK lookup uses sequence only;
matching the echoed part is our additional conservative restriction.

The 64 KiB message bound, two pending logical responses, two-slot sequence
window, one-second retry interval and four transmissions are local experiment
policy, not claims about native limits. At most 70 fragments form a response.
The 32 post-login-response budget still counts logical responses, not fragments.
Login/Register acknowledgement gating counts complete responses rather than
assuming that reliable sequences 1 and 2 will always be the two final packets.

## Queue lifecycle

Each complete response is encoded before publication or sequence advancement.
Every slice receives its own reliable sequence, compression/encryption and IV.
Only ciphertext is retained; caller-owned plaintext is still cleared in the
session's finally block. Encoding failures clear the newly allocated packets and
leave the existing queue/next sequence intact. Responses over 64 KiB are rejected
without truncation; the session's existing failure path clears its state.

TakeDue sends only the first two positions after the oldest outstanding sequence.
An ACK for position two clears its ciphertext but cannot move the window past a
missing ACK for position one. Once the gap closes, acknowledged positions are
removed and the next window opens. This bounds receiver sequence distance even
when later packets arrive before the earliest one. u16 sequence wrap is supported.
Retries reuse identical ciphertext. Unsent, wrong-part and duplicate ACKs do not
advance the queue. A logical response completes only when every fragment is ACKed.

Timeout is checked before handing packet references to the sending loop. Timeout,
peer teardown and shutdown clear both sent and unsent ciphertext. Existing idle
and hard lifetime limits remain enforced by PrudpLocalLoginSession; its disposal
also removes the owner's lobby. The existing single UDP loop owns this queue.

## Verification and deployment state

`work/server-response-fragments` builds with zero warnings/errors. The complete
service suite passes 4,152 checks (1,010 more than the 3,142-check routing-storage
baseline). New cases cover fragment boundaries through 64 KiB, native CNG
per-fragment decoding, reversed delivery and reassembly, sequence wrap, missing
ACKs, exact retry bytes, later ACKs behind a gap, unsent ACK rejection, logical
response capacity, rollback on encoding failure, oversize rejection and zeroing.

A managed test fixture also places an invented multipart response in the real
session queue and tests CONNECT-derived packet fields, incoming ACK checksum,
peer/session/cookie guards, nonzero echoed parts, explicit-length ACKs and resumed
keepalive. This fixture does not add a production RPC or debug endpoint.
Existing real loopback HTTP/UDP and lobby lifecycle regression tests also pass.

These are synthetic transport results. No nonempty search handler is enabled;
unknown session-field semantics, query/filter semantics, game-route validation,
GetSession, joining and LAN play remain outstanding. The live launcher still
uses the previously verified session-leave build, not this candidate. No game
restart is pending. Native adapter and UI archive are unchanged.
