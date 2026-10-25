# S7 HE CONNECT ACK: bounded static evidence

Executable SHA-256: `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.

Scope: static executable and public Microsoft API documentation only. No runtime packet/account values, process memory, captures or game actions were used. This establishes a narrow transport-level response for an **empty-payload CONNECT request after the local SYN exchange**, not an authenticated login response or a functioning game server.

## The two cookies must not be confused

Let S be the local server cookie sent in SYN ACK, and C be the client's own connection cookie.

- The client adopts S into endpoint+0xbc at `EBB7DA–EBB7DD`.
- When constructing CONNECT, `EBC013–EBC046` generates C from its peer address and endpoint connection timestamp; `EBC20E` writes C to CONNECT's connection-signature field at packet+0x1c.
- `EBB12C–EBB132` writes S into that outgoing CONNECT's ordinary header signature at packet+0x14.
- On receiving CONNECT ACK, `EB4C3E–EB4C72` computes the client's expected C using the same peer address and endpoint timestamp. `EBAA30` is confirmed to copy endpoint+0xa8/+0xac, which is also the timestamp used at `EBC028–EBC046`.
- `EB4C8C–EB4C92` compares the reply's **header signature** to C. The type-0/type-5 exceptions at `EB4C98–EB4CA5` do not apply to CONNECT.

Thus an ACK must put **the incoming CONNECT's connection signature C into its header-signature field**. Repeating S there would fail. On the server, incoming CONNECT should first be bound to the stored SYN context and its header signature checked against S.

The ACK's own connection-signature field is zero in the native generic ACK construction. It is not a new cookie: `EBB7B9–EBB7CB` only adopts a CONNECT connection signature when ACK is absent. A scan of the endpoint receive body found no other incoming connection-signature read on the ACK branch.

## Session, sequence, type and routing

`EBBC75–EBBD1D` is the native generic ACK construction:

- Incoming 0x20 triggers the ACK path; for CONNECT it constructs `PacketOut(endpoint, type=1, flags=8, incomingPayload)` at `EBBCB5`.
- The packet base constructor zeroes the connection-signature field. This ACK path does not overwrite it.
- `EBBD07/EBBD12` copies the incoming sequence ID into the reply.
- `EBB110` supplies endpoint+0xbc as header signature and endpoint+0xc1 as local session ID. On a server endpoint, the client's CONNECT connection signature has just been adopted into +0xbc, giving C as required above.

Session is **server-owned**, not an echo of the client's session. Native construction selects a nonzero local session byte at `EB9E9F–EB9ECC` and advances the next value with zero skipped at `EB9ED7–EB9EE4`. The incoming peer-session field +0xc0 starts zero at `EB9F5B`. At `EBB984–EBB98C`, zero takes the adoption path; `EBBB7A` permits CONNECT and `EBBBF9–EBBBFC` copies the received session byte. Once nonzero, `EBB992–EBB997` requires subsequent packets to match it. A new server can select its own nonzero byte and keep it stable for that connection and its retries; it need not reproduce the client's local session counter.

Sequence must echo the request. After crypto succeeds, `EBC575 → EBADE0` uses the received sequence to find the outstanding sent packet through `EC0EF0`, removes it from retry/sliding-window bookkeeping, and advances pending sends. The caller does not test a Boolean result before its state change; this is not a reason to send a wrong sequence.

VPorts and UDP endpoints follow [the SYN ACK findings](SYN-ACK-PROTOCOL.md): swap the input VPort bytes for the restricted same-stream-type path and reply from the same bound UDP socket to the same peer endpoint. The local config creates stream 3 / server SID 1, so the current probe can restrict destination VPort to 0x31 and source high nibble to 3.

The client-generated AES CONNECT uses flags 0x30 at `EBBFB6`, then adds 0x80 at `EBC24C`. With packet type 1, the combined byte is **0xB1**, or **0xF1** if the serializer adds optional payload length 0x40. A reply with required AES key extension uses combined byte **0x89** (CONNECT + ACK + AES), or **0xC9** with optional payload length. It should not request another ACK or mark itself reliable merely because the request did.

The generic peer ACK code shows the ACK header/echo relationships. The external service's AES extension is established from this client's parser and verification path; the generic ACK constructor by itself does not attach that extension.

## Exact signed key extension

For CONNECT + ACK + 0x80, `E8727D–E8783F` parses:

1. u16LE signature length, then those signature bytes (packet+0xcc);
2. u16LE key-blob length, then those key bytes (packet+0xc0);
3. optional u16LE payload length only if 0x40 is present;
4. payload, then u32LE additive checksum.

Both extension lengths must be nonzero. The parser does not itself fix a signature to 64 bytes or a key to 72 bytes; the following crypto-provider requirements determine those sizes for the supported P-256 response.

Use two distinct key pairs:

- **Configuration signing key:** the locally created ECDSA P-256 key whose ECS1 public blob was returned by the configuration HTTP endpoint. Keep its private half in process and sign with that same key, not a new signing key per reply.
- **Handshake agreement key:** a separate ECDH P-256 key pair for the connection. Its public blob is CNG `ECCPUBLICBLOB`: bytes `45 43 4B 31 20 00 00 00` (ECK1 + cbKey32LE), then X32 and Y32, each big-endian. Total 72 bytes. Client `EBAAAC–EBAB69` generates/exports this same public-key format, and `EBD05E–EBD083` imports the server blob into its ECDH_P256 provider.

`EBC408–EBC41E` calls `E79910(configurationKey, handshakePublicKey, signature)`. `E79E17–E79E2E` hashes the **entire 72-byte server handshake public blob**, including ECK1/cbKey, using SHA-256. No packet header, cookie, session byte, sequence, extension-length prefix, client public key or payload is included in this particular signature. `E79FFB–E7A118` opens ECDSA_P256 and imports the configuration public key; `E7A22E–E7A24B` passes the signature bytes directly to `BCryptVerifySignature`, with flags 0 and no DER conversion.

For the local .NET implementation, the explicit signing operation is `ECDsa.SignData(serverEck1Blob, SHA256, IeeeP1363FixedFieldConcatenation)`. With P-256 this is a 64-byte r||s signature. Check that the produced signature length is 64, rather than silently accepting another encoding. A separate offline interoperability test with native CNG is appropriate before connecting this response to the live client; this static pass is not such a test.

Primary API references:

- [BCRYPT_ECCKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob): ECK1/ECS1 and coordinate layout.
- [BCryptSignHash](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash): ECDSA takes a hash as input and verification requires the same data/key pair.
- [.NET ECDsa API source documentation](https://github.com/dotnet/dotnet-api-docs/blob/main/xml/System.Security.Cryptography/ECDsa.xml): SignData's P1363 format contract.
- [.NET signature-format API design](https://github.com/dotnet/runtime/issues/31548): current API output is fixed concatenation of R and S, distinguished from DER encoding.

After signature verification, `EBC4C8 → EBD030` imports the public key, performs BCryptSecretAgreement with the client's retained local private key, and derives a 16-byte key via `BCryptDeriveKey(secret, L"HASH", NULL, out, 16, &length, 0)`. The native API default is SHA-1 with output truncated to 16 bytes. Retain the server ECDH private key and the peer public key/derived state in memory if later implementing actual encrypted transport; supplying a public key without retaining the corresponding private state cannot support later traffic.

## Minimal empty-payload wire shape

For a 64-byte P1363 signature and 72-byte ECK1 public blob, the no-payload response is 158 bytes:

| Offset | Width | Value |
|---|---:|---|
| 0 | 1 | request destination VPort |
| 1 | 1 | request source VPort |
| 2 | 1 | 0x89 |
| 3 | 1 | server-owned stable nonzero session |
| 4 | 4 | incoming CONNECT connection signature C, u32LE |
| 8 | 2 | incoming CONNECT sequence ID, u16LE |
| 10 | 4 | 0 u32LE (ACK connection signature) |
| 14 | 2 | 64, u16LE |
| 16 | 64 | P1363 signature over SHA256(server ECK1 blob) |
| 80 | 2 | 72, u16LE |
| 82 | 72 | ECK1 server public blob |
| 154 | 4 | additive checksum over bytes 0..153 plus confirmed stream seed, u32LE |

The alternative 160-byte form uses combined byte 0xC9, inserts u16LE zero payload length at offset 154, and places checksum at offset 156. The 0x89 form avoids that optional field. Request minimum is 92 bytes for ECK1/empty payload, or 94 with explicit payload length; these are derived lengths, not observed packets.

## Payload findings and limits

Endpoint construction initializes outgoing CONNECT payload pointer +0xc8 and optional return-buffer pointer +0xc4 to NULL at `EB9D57/EB9D5D`. CONNECT construction passes +0xc8 into PacketOut at `EBBFAE–EBBFBB`. The native generic ACK deliberately echoes the request's **decoded payload** (`EBBCA1`).

On the client, `EBC2E3–EBC2F5` copies the returned payload into an optional supplied buffer through `E6C0B0`, then clears that buffer pointer. `E6C0B0` is a buffer copy, not a content/length validator. No required payload value or minimum length is checked in the CONNECT ACK acceptance branch before the crypto and state transition.

When the received payload is empty, `E87C66–E87C70` bypasses payload decryption. Thus an empty CONNECT ACK is accepted by this transport path. This does **not** by itself prove that every higher-level connection caller expects empty data: a nonempty request's native ACK echo is evidence against discarding an arbitrary payload. A minimal local probe should initially support only CONNECT requests with PayloadLength == 0. Do not echo unknown encrypted wire bytes as though they were decoded payload, or invent a response for a nonempty request.

A bounded follow-up over endpoint code `EB9CB0–EBD690` found NULL initialization, reads and cleanup for +0xc8/+0xc4, but no direct non-NULL assignment. A direct register-to-memory write-pattern scan over `E70000–ED0000` likewise found only the endpoint's NULL initialization for +0xc8. This is not proof that no indirect setter exists elsewhere. It gives no basis for inventing a nonempty payload and does not weaken the empty-request gate.

## Acceptance and proposed narrow gates

Client acceptance requires an existing connecting endpoint (virtual +4 at `EBC2CC` resolves to `EBAD80`, state == 1), correct source endpoint/routing, correct C in the reply header, a session acceptable to +0xc0, valid checksum, present AES key/signature buffers, successful signature verification and ECDH public-key import/secret setup. `EBC575` acknowledges the pending sequence; `EBC580` calls virtual +0x4c (`EBC8A0`) with state 2. Native diagnostic strings at `EBC8EF/EBC92B` identify state 2 as Connected. This establishes transport connection only.

Before any implementation responds, a narrow local probe can require:

- an existing SYN context for the same loopback endpoint, source VPort and destination 0x31;
- incoming CONNECT byte 0xB1 or 0xF1, no signature buffer (it is a request), a structurally valid 72-byte ECK1 P-256 key, and nonzero/stable client session;
- packet header signature equals the stored server SYN cookie S;
- payload empty, full single-packet consumption, and checksum matches the already confirmed stream seed 0;
- a stable server session/key/blob/signature for retries of that connection, and the current local configuration signing key.

The reply must echo sequence and C from the accepted request. Do not substitute either with S, a guessed constant or the client's session. Do not respond to subsequent DATA/RPC traffic until its protocol is established. A local metadata observation of following traffic is not proof of authentication, successful LoginWithToken, or multiplayer readiness.

Remaining unproven items: live client acceptance of this exact response; higher-layer semantics for nonempty CONNECT payloads; later encrypted packet format, RPC/login requests/responses and retry lifecycle beyond the narrow probe. These are separate work, not reasons to fabricate fields in the established CONNECT ACK layout.
