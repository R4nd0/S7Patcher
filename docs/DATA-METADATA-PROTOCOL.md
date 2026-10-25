# S7 HE DATA metadata: bounded static findings

Scope: original local `Settlers7R.exe`, build 1.12.1395, SHA-256 rechecked as `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`. Static file inspection only. No runtime actions, packet inspection, process reads, account data, decryption, or responses. These notes support a passive structural classifier, not a DATA implementation or login claim.

## Wire layout

The same `PacketIn::Unpack` function at `E86CE0` parses the common 10-byte header. Native type-name dispatch identifies low three bits `2` as DATA. Integer fields here are little-endian.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Source virtual port |
| 1 | 1 | Destination virtual port |
| 2 | 1 | Low 3 bits packet type; high 5 bits flags |
| 3 | 1 | Sender's session ID |
| 4 | 4 | Header signature/cookie field, u32LE |
| 8 | 2 | Sequence ID, u16LE |
| 10 | 1 | DATA PartNumber |
| 11 | 2, conditional | PayloadSize, u16LE, only if flag `0x40` is set |
| 11 or 13 | variable | Opaque serialized payload |
| selected packet end minus 4 | 4 | Additive checksum, u32LE |

Evidence: `E8783F–E87851` checks type 2 and reads exactly one byte into PacketIn+0x20, with native error text `PartNumber`. The output serializer agrees at `E82550–E82562`. The preceding connection-signature read/write is conditional on type 0 or 1; DATA has **no four-byte connection signature** after the fixed header. The key/signature-extension input branch at `E8727D–E8728E` first requires type 1, so even a DATA byte with bit `0x80` set has no CONNECT key extension in this parser.

Minimum structurally possible sizes are 15 bytes without `0x40`, or 17 with it and zero declared payload. This does not establish that an empty DATA payload is useful or accepted by later processing. PartNumber is an observed raw byte; this pass did not derive fragmentation/reassembly semantics, last-part markers, or allowed part-number sequences. Do not equate it to a fragment count or require it to be zero.

## Packet boundary and checksum

With `0x40`, read `payloadLength = u16LE(packet[11..13])`, use payload offset 13, checksum offset `13 + payloadLength`, and consumed size `17 + payloadLength`. The native bounds check is consumed size **at most** available buffer length (`E8793E–E87954`), not equality. It selects that extent at `E87A46–E87A49`. Trailing bytes may exist in the supplied buffer; their transport handling remains outside this pass. A narrow single-packet observer can report `BytesConsumed` and `TrailingBytes`, or explicitly reject a trailing frame as its own scope limit.

Without `0x40`, payload offset is 11, payload length is supplied size minus 15, and consumed size is the whole supplied buffer (`E87A33–E87A43`). Never use the SYN/CONNECT minimum length of 18 for DATA.

The same `E6C8A0` wrapping u32 sum of LE32 words, zero-padded final partial word, and stream seed applies. Input validates the selected packet's last four bytes at `E87B71–E87B96`; output appends checksum at `E82740–E82769`. The calculation covers the serialized header, optional size, and opaque payload before the final checksum. It requires no payload decryption. The stream setting is selected by the high nibble of source VPort (`E87A54–E87A5F`). A seed-zero match can be reported as exactly that; checksum is not authentication, and an unspecified seed remains unverified. Earlier handshake observations do not justify accepting a different stream's checksum settings.

## Direction, session and cookie context

Define S as the server cookie supplied in SYN ACK, C as the client's cookie from CONNECT's connection-signature field. The normal endpoint send path `EBB110` writes stored peer cookie endpoint+0xbc into packet header+0x14 (`EBB12C–EBB132`) and its **own** session endpoint+0xc1 into packet+0x13 (`EBB135–EBB13B`), without restricting this assignment to CONNECT.

For the existing narrow probe's same endpoint and stream:

| Direction | VPorts | Header signature | Session |
|---|---|---|---|
| Client to local server | Same client source VPort; destination `0x31` | S, the server SYN cookie | Client session from CONNECT request |
| Server to client | Source `0x31`; destination client VPort | C, the client's CONNECT cookie | Server session from CONNECT ACK |

These are context expectations, not enough to certify a packet. Native receiving transport computes its own cookie and compares the incoming header signature at `EB4C3E–EB4C92`. Only SYN and PING bypass this specific comparison at `EB4C98–EB4CA5`; DATA does not. Other endpoint-lookup/recovery branches exist, so a passive probe should report match/mismatch against its known context rather than claim to reproduce the complete native routing state machine.

Native endpoint receive compares packet session against the previously adopted peer session at `EBB984–EBB997`. If no peer session has yet been adopted, only CONNECT may establish it (`EBBB7A–EBBBFC`); DATA then follows the invalid-packet path. DATA is not exempt from session comparison as SYN is. The metadata observer can compare against its saved client CONNECT session, not the generated server session.

Do **not** require DATA sequence to equal CONNECT sequence. Unreliable, non-ACK DATA receives its own incrementing endpoint counter at `EBB1AE–EBB1C2`. Reliable sends use a separate queued path; ordering and reassembly were not fully derived. Generic ACK construction echoes sequence and PartNumber (`EBBD04–EBBD1D`). The subsequent [DATA ACK analysis](DATA-ACK-PROTOCOL.md) separately establishes the conditions for an opt-in acknowledgement; passive classification alone does not enable replies.

## What is justified without decryption

Header, PartNumber, size and checksum are parsed before payload transformation. `E87C44–E87C7F` either marks a nonempty payload for deferred decryption or calls `E86350`; zero length skips this operation. Deferred DATA processing at `EBBD47–EBBD65` attaches endpoint+0x850 shared-secret material and then invokes `E86350`. Normal serialization writes the clear header/part first, transforms the payload through stream settings (`E825EE–E82696`), then writes the transformed payload length and bytes (`E82699–E826E7`) and checksum.

Thus a passive classifier may truthfully report **structurally decoded DATA with opaque payload**, even without decrypting it. It may additionally report header-context and checksum matches independently. It cannot report payload integrity, native transport acceptance, successful decryption, a particular RPC, or login completion. `ConnectReplySent` is local server state, not proof that the client accepted the reply.

There is no demonstrated DATA-specific on-wire encryption flag here: `0x80` controls the CONNECT handshake extension, while payload transformations depend on stream settings and endpoint state. Do not label arbitrary type-2 bytes as verified encrypted data solely from type or flags. Nonempty DATA on the established AES probe context is consistent with a protected payload, but remains opaque and unverified by this observer. PayloadSize is the **serialized** byte count, not a plaintext/application-message length. This pass establishes no AES block-size, padding, RPC framing, or post-handshake authentication format, and a metadata decoder should impose none of those invented constraints.

Recommended limited observation fields: structural packet type, ACK/reliable/ACK-request bits, PartNumber, serialized payload length, bytes consumed, trailing-byte count, checksum status, and booleans for known endpoint/routing/session/header-cookie matches. Keep cookie values, endpoints, key bytes and payload bytes out of logs, consistent with the current probe. Decode type 2 before applying the handshake-only 18-byte minimum; do not add any reply path.

## Saved static evidence

Focused disassembly remains local and is not redistributed. The [handshake findings](HANDSHAKE-PROTOCOL.md) and [CONNECT ACK findings](CONNECT-ACK-PROTOCOL.md) supply the common header, cookie origin and prior key context. The executable fingerprint, addresses and original findings above allow this pass to be reproduced without publishing game sources or runtime values.
