# S7 HE minimal SYN ACK: bounded static evidence

Executable SHA-256: `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.

Scope: static executable inspection only. No packets, process memory, credentials or personal values were inspected. No original or output files were changed by this research pass. This covers a SYN-only local probe, not CONNECT completion, authentication, login, matchmaking or multiplayer.

## Reply fields supported by the native server path

`PRUDPStream::ReceiveIncomingPacket` starts at `EB4AD0`. Type 0 without ACK reaches the native SYN response path through `EB4C17 → EB510F`.

At `EB52F3–EB52FD`, the native server creates `PacketOut(NULL, 0, 0, NULL)`. `E81AA0 → E84420` initializes the four bytes at Packet+0x10 (both VPorts, flags/type, session ID) and the packet signature at +0x14 to zero. `EB5306` sets ACK bit 0x08. `EB531A/EB5329` copies the incoming sequence ID; `EB5330` sets the generated server connection cookie. It copies the request's source network address at `EB5333–EB5336` and sends through `EB5B20`.

The minimum response is consequently 18 bytes:

| Offset | Width | Value |
|---|---:|---|
| 0 | 1 | request destination VPort, for matching source/destination stream types |
| 1 | 1 | request source VPort |
| 2 | 1 | 0x08: SYN type 0 + ACK |
| 3 | 1 | 0: native constructor session default |
| 4 | 4 | 0 u32LE: native constructor packet-signature default |
| 8 | 2 | request sequence ID, u16LE |
| 10 | 4 | server-owned connection cookie, u32LE |
| 14 | 4 | wrapping LE32 word-sum checksum of bytes 0..13 plus stream seed, u32LE |

There is no payload or public-key extension in this reply. The native serializer can additionally set 0x40 according to its own stream setting (`E823E9–E823F0`), producing a zero payload-length u16 and a 20-byte packet. The receiver accepts the 18-byte form without that optional field; 18-byte output is therefore the narrower probe format. Do not copy arbitrary input flags into the response.

## VPort and UDP routing proof

`UDPTransport` constructor `E7A5F0` installs vtable `10FE4BC`. Its +0x1c entry is `E7C250`, confirming the virtual call made by `EB5B20`.

- `E7C2B0–E7C2C3` builds the source VPort as `(streamType << 4) | sourceSid`.
- `E7C410` writes the source VPort; `E7C413–E7C419` builds/writes destination `(streamType << 4) | destinationSid`.
- `E7FC90` delivers incoming packets: `E7FCCE → E7FF70` reads destination VPort from Packet+0x11 and `E7FCD8 → E7FF90` selects the registered stream. `E7FCF5 → E7FF80` reads source VPort from +0x10 and `E7FCFD–E7FD09` passes its low nibble as the source SID to the stream receiver.
- The SYN response passes that incoming source SID as its destination SID at `EB533C`; its source stream/SID are those selected by the incoming destination VPort. Thus swapping the two input VPort bytes is the native relationship when both stream-type high nibbles match.
- `EB4C20–EB4C2C → EB4510` looks up a received SYN ACK by its source network address and source SID. A local responder must reply from the same bound UDP socket/port advertised by its configuration, to the request's actual sender endpoint.

The config connect path constructs stream=3 and sid=1 (see [configuration findings](CONFIGURATION-PROTOCOL.md)), so a local probe may restrict both VPort high nibbles to 3. Additionally requiring destination VPort 0x31 is a narrower policy matching that locally configured target. These restrictions define the probe's scope; they are not claims that every native stream must use these values.

## What the client accepts before sending CONNECT

After a SYN ACK is routed to an existing endpoint:

1. `EB4C72` computes the client's own expected packet signature, but `EB4C98–EB4C9D` explicitly skips mismatch rejection for type 0. Thus the native reply's zero header-signature value is usable without reproducing the client's private cookie generator.
2. `EBB7AA–EBB7B7` requires ACK and the endpoint's connecting predicate (virtual +4). `EBB7DA–EBB7DD` then copies the received connection signature directly to endpoint+0xbc. There is no server-cookie recomputation or comparison on this path.
3. `EBB97C–EBB97E` jumps past session validation for type 0. A SYN reply does not need to echo the client's session ID. The native constructor's zero session is appropriate.
4. Type dispatch table `EBC680[0]` selects `EBBF6E`. `EBBF6E–EBBF8D` again requires the connecting predicate, ACK, and endpoint+0x70 == 0 (CONNECT not yet initiated).
5. `EBBFBB` constructs CONNECT. `EBC256–EBC259 → EBB110` sends it; `EBB12C–EBB132` copies the adopted server cookie from endpoint+0xbc into this outgoing packet's header-signature field. `EBC273` marks CONNECT initiated.

The native SYN reply echoes sequence ID. This static branch does not demonstrate a separate SYN sequence equality check before CONNECT initiation; echoing is nevertheless the native behavior and is the appropriate reply relationship. No input session/header-signature value should be forced to zero by the SYN metadata gate: the client creates its local session independently (`EB9E9F–EB9ECC`).

## Why a new server may choose its own cookie

The native server uses `EB9BC0` to produce its cookie from its own `TransportSignatureGenerator` and the peer address plus connection time:

- `EB9C0C → E6D950` packs the peer IPv4/port into an 8-byte value; `EB9C22` writes it into a bitstream, followed by the 8-byte connection-time value at `EB9C32`.
- `EB9C55` invokes the generator's keyed-checksum operation, and `EB9C64–EB9C78` reads its first four output bytes as the returned cookie.
- The generator constructor `EB9A00` creates the HMAC-MD5 implementation (`EC3360`, vtable `110F580`; `EC34A0` prepares 0x36/0x5c pads and `EC33F0` performs inner/outer MD5). The constructor derives its own key material from a local time value through `EB9AA7–EB9B12`. It does not read a configuration signing key, authentication token or server-provided secret in this chain.

The client treats the resulting u32 as opaque at the SYN stage, as shown above. Therefore a new local server may generate its own random nonzero u32 cookie and retain it for that local peer; this does not require reproducing Ubisoft's generator. **Nonzero is a local probe policy, not a proven native requirement.** A later server implementation must validate the returned cookie consistently when handling CONNECT; this pass does not authorize or implement that next step.

## Narrow proposed probe gate

The native initial SYN construction uses flags 0x20 (`EB9E71`). With the serializer's optional 0x40 addition, a deliberately narrow probe may accept only flags 0x20 or 0x60. This implies type SYN, ACK request present, ACK absent, and no speculative reliable/AES flag combinations.

Before replying, require all of:

- loopback sender and the configured loopback UDP listener;
- type SYN and flags exactly 0x20 or 0x60;
- both VPort stream-type nibbles equal 3, with destination 0x31 if enforcing the advertised SID;
- no payload and BytesConsumed equal the entire datagram length;
- a checksum that matches the explicitly supplied seed 0.

Seed 0 remains a hypothesis until it matches an actual controlled request. It is not promoted to verified merely because the executable's access-key buffer starts empty. The incoming and outgoing source stream types are both 3 under this gate, so the same client stream checksum setting applies to request and reply. A mismatch means no response, not guessed alternative keys.

Reply only with the native 18-byte SYN ACK layout above. A fresh server-owned random nonzero cookie is the one field the local implementation selects. Do not respond to CONNECT or later packet types, do not claim cryptographic authentication from the additive checksum, and do not infer successful login from receiving CONNECT.

## Remaining boundaries

The static evidence now supports the SYN-only reply relationships. Actual client acceptance still needs a controlled local test. The separate [CONNECT ACK findings](CONNECT-ACK-PROTOCOL.md) now derive the next response for empty requests and distinguish the server cookie from the client cookie. Payload encryption, token RPC and authenticated service implementation remain separate work. The exact native cookie byte-for-byte derivation is unnecessary for the opaque SYN handoff and was not fully reimplemented; the local CONNECT probe checks its own issued cookie consistently.
