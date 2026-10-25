# S7 HE DATA ACK: native evidence and conservative probe specification

Static scope: the original local History Edition executable, build 1.12.1395, SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`. No runtime actions, account reads, packet captures, payload inspection, or code changes in this pass. This is a transport ACK specification, not a login or application response.

## Native ACK construction

`PRUDPEndPoint::ServiceIncomingPacket` has already passed the normal endpoint/cookie and session checks when it reaches `EBBC75`. It tests incoming packet flag `0x20` at `EBBC78`; if clear it skips ACK construction. This check does **not** require `0x10` (reliable), and does not inspect the payload length. Thus reliable alone is not sufficient, while ACK-request with reliable clear still takes the ACK path.

For type 1 CONNECT it constructs a special ACK with the decoded request payload. **For DATA/type 2 it takes the other branch:**

- `EBBCD8–EBBCEB`: constructs PacketOut with the same low-three-bit type, flags initially zero, and a NULL payload argument.
- `EBBCF6`: ORs `0x08` (ACK) into the new packet flags. It does not copy request flags `0x10`, `0x20`, `0x40`, or `0x80`.
- `EBBD04–EBBD12`: gets incoming u16 sequence and copies it into the reply.
- `EBBD16–EBBD1A`: copies incoming raw one-byte PartNumber into the reply.
- `EBBD1D`: sends through normal endpoint function `EBB110`.

The PacketOut constructor `E81AA0` retains the NULL payload through the base constructor (`E84461–E8446B`). Ordinary send setup writes stored peer cookie endpoint+0xbc into the header signature (`EBB12C–EBB132`) and the endpoint's own session endpoint+0xc1 into the outgoing session (`EBB135–EBB13B`). Because this ACK has neither reliable nor ACK-request flags, it does not enter the reliable-send queue; the non-ACK DATA sequence allocation at `EBB189–EBB1C2` is also bypassed, preserving the copied sequence.

ACK generation here occurs **before** the deferred DATA decryption block (`EBBD47–EBBD65`) and before later reliable receive processing (`EBBD72–EBBD7C`). Consequently this ACK is not evidence that application bytes were understood, accepted, or authenticated.

## Empty ACK wire layout

Define S = server cookie supplied in SYN ACK; C = client cookie from the CONNECT request's connection-signature field. The existing probe's outgoing DATA ACK must carry C in the header, while the incoming DATA request is checked against S.

The minimal reply is exactly **15 bytes**:

| Offset | Size | Value |
|---:|---:|---|
| 0 | 1 | `0x31`, the server VPort / incoming destination |
| 1 | 1 | Saved client VPort / incoming source |
| 2 | 1 | `0x0A` = DATA type 2 + ACK flag `0x08` |
| 3 | 1 | The same nonzero server session already sent in CONNECT ACK |
| 4 | 4 | C, u32LE; **not S** |
| 8 | 2 | Current DATA request sequence, echoed u16LE |
| 10 | 1 | Current DATA request PartNumber, echoed exactly |
| 11 | 4 | Checksum over bytes 0..10 with supplied stream seed 0, u32LE |

There is no connection-signature extension, public key, ECDSA signature, IV, encrypted empty block, plaintext sequence suffix, padding, or payload in this ACK. DATA serialization writes PartNumber at `E82550–E82562`. NULL payload branches directly from `E82584–E82586` to `E8271E`, bypassing payload transforms. If bit `0x40` is absent it immediately appends checksum at `E82740–E82769`.

The native serializer can add `0x40` from a **stream setting**, independently of the request (`E823D1–E823F0`). That representation would be 17 bytes, wire type/flags `0x4A`, u16 zero payload length at offset 11, checksum at offset 13. The input parser supports either; mirroring the request's `0x40` is not required. Use the minimal 15-byte form for this narrow probe.

Empty ACK payload is both natively generated and accepted by the parser's empty-payload path: `E87C66–E87C70` skips decryption when payload length is zero. Do not encrypt an artificial empty payload or echo any incoming DATA bytes.

## How the client stops packet retries

The receive dispatch table at `EBC680` maps DATA/type 2 to `EBBD94`. Its ACK test at `EBBD97` calls `EBADE0` when bit `0x08` is set; a normal ACK without reliable bit bypasses the reliable receive queue first.

`EBADE0` reads only the ACK's u16 sequence through `E846F0` (the getter for Packet+0x18), then looks it up in the endpoint's outgoing window via `EC0EF0`. That lookup works with the 16-bit sequence; `EC100C–EC1020` explicitly compares the queued packet sequence with the requested sequence. No incoming PartNumber is passed into this lookup, and the ACK handler contains no PartNumber comparison. Nevertheless echo PartNumber, because that is the native construction rule; do not invent part-number constraints.

For a found queued packet, `EBAECA–EBAED3` calls `EBE5A0` on the timeout manager. `EBE660–EBE6DE` locates/removes the timeout entry for that exact queued PacketOut. `EBAED8–EBAEE5` then removes the sequence from the outgoing window through `EBFDA0`; `EBFF3E–EBFF88` decrements its pending-DATA count and `EBFF98` labels the event `Acknowledged`. Finally `EBAEEC` calls the send-queue service routine. A sequence with no queued match does not remove a packet. This proves the relevant retry-completion mechanism, not that every future network timeout or application request will complete.

There is no cumulative ACK range in this path. Echo **each received packet's** sequence. Do not use CONNECT's sequence, an incremented server sequence, a highest-seen sequence, or a synthetic fragment index. Allow all u16 sequence and u8 PartNumber values, including zero and wraparound. Repeated requests should receive the same deterministic ACK again; dropping duplicates would prevent recovery from a lost ACK. No per-payload retention or hash is necessary for constructing this transport ACK.

## Conservative opt-in probe gates

These gates deliberately restrict a local experiment and do not claim to reproduce every native routing/recovery case:

1. ACK replies require an explicit DATA-ACK opt-in. Bind/send through the existing IPv4 loopback socket and only process loopback senders.
2. Require the same stored `IPEndPoint`, a successfully sent SYN ACK, a validated CONNECT context, and a successfully sent CONNECT ACK. A created CONNECT object before a failed send is insufficient; retain an explicit `ConnectReplySent` flag.
3. Structurally parse type 2 using the DATA 15-byte minimum, PartNumber, optional `0x40` payload length, and selected-packet checksum. Require the entire datagram to be exactly one packet, with no trailing bytes, and checksum matching supplied seed 0.
4. Require source VPort equal to the stored client VPort (stream high nibble 3), destination `0x31`, session equal to the stored **client** CONNECT session, and header signature equal to stored S. These comparisons concern context, not authentication.
5. Accept flags **exactly `0x20`, `0x30`, `0x60`, or `0x70`**, i.e. wire type/flags `0x22`, `0x32`, `0x62`, or `0x72`. These are ACK-request with optional reliable and optional explicit payload length. Reject ACK packets, packets without ACK-request, and bit `0x80` for this probe. Native ACK triggering itself is broader and does not test `0x80`; excluding it is an explicit conservative scope choice, not a claimed native rejection rule.
6. Incoming payload may be empty or nonempty; do not read, decrypt, copy into a reply, log, or infer its contents. The native ACK condition has no payload-size minimum. Bounds and checksum are checked over serialized bytes; do not invent AES block-size or application-framing requirements here.
7. Generate the 15-byte ACK above using the saved C and **unchanged server session from the cached CONNECT ACK**. Echo the current DATA sequence and PartNumber. Do not mutate SYN/CONNECT cookies, handshake keys, sessions, or CONNECT retry tuple.
8. Emit only fixed event names/counts and existing metadata/context booleans. State that transport bytes were acknowledged, with authentication and application protocol still unimplemented. No DATA/RPC answer, decryption, token handling, disconnect response, or unsolicited packets are included.

A stricter reliable-only policy (`0x30`/`0x70`) would also be a possible experiment limit, but would omit the natively supported ACK-request-without-reliable branch for no demonstrated protocol requirement. `0x10` alone never requests this ACK. Never answer an ACK with an ACK in the probe.

## Independent synthetic checksum fixture

All values below are invented test data, not observed client values. For client VPort `0x3A`, server session `0x56`, C=`0x12345678`, DATA sequence `0x9ABC`, and PartNumber `0x7F`, the full 15-byte minimal ACK is:

`31 3A 0A 56 78 56 34 12 BC 9A 7F 65 2B BE 68`

The checksum is `0x560A3A31 + 0x12345678 + 0x007F9ABC = 0x68BE2B65` with seed 0. Use distinct S and C in tests to catch accidental cookie swapping. This fixture validates header/length/checksum arithmetic only; it is not a packet to send to the game.

## Limits and reproducibility

ACK acceptance and reduced retransmission remain live-test questions. The static path supports this narrow response, but it does not establish login completion, application response formats, successful payload decryption, or multiplayer compatibility. Even fewer DATA retries after ACK would only establish transport progress. Invalid payloads could still pass this probe's structural/context checks, just as the native deferred-decryption path sends ACK before that later check.

Focused disassembly remains local and is not redistributed. The executable fingerprint and addresses above support reproducing the static findings. Common routing/session/checksum evidence is documented in [DATA metadata](DATA-METADATA-PROTOCOL.md) and [CONNECT ACK](CONNECT-ACK-PROTOCOL.md). Synthetic implementation checks and separate live observations are recorded in [LAN research](LAN-RESEARCH.md).
