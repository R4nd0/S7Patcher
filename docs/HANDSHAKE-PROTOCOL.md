# S7 HE first UDP handshake: static wire evidence

Client and scope: same SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f` as [CONFIGURATION-PROTOCOL.md](CONFIGURATION-PROTOCOL.md). Static file inspection only; no captures, process reads, credentials, actual server keys, or game launches. These findings do not yet constitute a working server handshake.

## Packet header and extensions

`PacketIn::Unpack` at `E86CE0` and `PacketOut` serializer at `E82380` agree on the following order. `E67600 → E6C9A0` copies bytes without endian conversion, so integer fields are little-endian on this x86 build. No version/magic prefix is read by this parser. A numerical protocol-version label has not been proven; do not select another game's PRUDP implementation solely by name.

| Offset | Width | Field | Read address |
|---|---:|---|---|
| 0 | 1 | source virtual port | E86D27 |
| 1 | 1 | destination virtual port | E86DE8 |
| 2 | 1 | packet type and flags | E86EA5 |
| 3 | 1 | session ID | E86F66 |
| 4 | 4 | packet `signature` field (distinct from ECDSA signature) | E87027 |
| 8 | 2 | sequence ID | E870EF |
| 10 | 4 | connection signature, only SYN/CONNECT | E871C6 |

Type is low three bits of byte 2. The native debug switch `E848A1 → E84A98` names 0 SYN, 1 CONNECT, 2 DATA, 3 ROUTE, 4 DISCONNECT, 5 PING, 6 USER, 7 RAW. Flag 0x08 is ACK; 0x10 is reliable; 0x20 requests acknowledgement; 0x40 adds a payload-length field; 0x80 selects the AES handshake extension. The last four flag interpretations are supported by native branching, not by borrowing a foreign packet layout.

For CONNECT (`type == 1`) with 0x80 set, `E8727D–E8783F` consumes these extensions directly after the connection signature:

1. Only if ACK 0x08 is also set: u16 signature length, then that many signature bytes. Zero length is rejected. The buffer is stored at PacketIn+0xcc.
2. For both requests and ACKs: u16 public-key length, then that many public-key bytes. Zero length is rejected. The buffer is stored at PacketIn+0xc0.
3. If flag 0x40 is set: u16 payload length. Otherwise payload size follows from the supplied buffer remainder minus its final four-byte checksum.
4. Payload bytes, if any, then u32 checksum.

DATA type 2 separately adds one-byte part number before the optional payload length. RAW type 7 bypasses the ordinary output serializer. These are outside the initial SYN/CONNECT scope.

`E823F7–E82499` writes the fixed header. `E8249E–E824FB` writes the optional server signature buffer; `E82505–E8254B` writes the public key buffer. `E82699` and `E8271E` govern the optional payload length; `E82740–E82769` appends checksum.

Initial SYN object construction `EB9E6F–EB9E78` sets type 0, flags 0x20, null payload. `E84420` initializes sequence ID and connection signature to zero, but later send setup can change fields. Predicted minimum serialized SYN size is 18 bytes, or 20 with optional payload-size field. This is a static prediction, not an observed packet. Actual VPorts, session values, cookie values, and active settings must be matched, not invented.

## Checksum

`E6C8A0` computes a wrapping u32 sum of successive little-endian 32-bit words; a final 1–3 byte remainder is zero padded in its high bytes. An input seed is added. There is no polynomial CRC in this function.

Output `E82740–E82769` seeds it with StreamSettings+0 and writes the result u32LE. Input `E87B71–E87B83 → E6CFB0` compares the same computation over the selected packet buffer excluding its last four bytes. Stream index comes from the high nibble of source VPort (`E87A54–E87A5F`).

`E5C2B0` sets StreamSettings+0 from a string: it copies the string's raw bytes, without NUL, computes the same LE32 word sum with seed 0, and stores it at `E5C31D`; empty string sets 0. Callers are `E9B8C9` and `E9B921`. The native failure text calls this an access key, but the exact string provenance matters; it must not be assumed to be a personal credential.

### Packet boundary clarification for a metadata decoder

With 0x40 set, `E8793E–E87954` computes checksum position = current reader position after the u16 length + declared payload length, and packet end = checksum position + 4. It requires packet end to be **at most** the available buffer size, not necessarily equal. `E87A49 → E6D080` selects that shorter buffer extent before checksum validation. Without 0x40, `E87A33–E87A43` uses the supplied buffer end. Therefore a decoder that rejects trailing bytes when 0x40 is present is deliberately limited to one packet per input; it must not claim that the native parser rejects those bytes. Multi-packet transport handling has not been derived here.

SYN with 0x80 does not enter the key-extension branch: `E8727D` first requires type 1 (CONNECT). An isolated decoder may show the flag without interpreting a key extension, or reject it as outside its supported scope, but the latter is not a demonstrated native validation rule.

### Access-key origin in this executable

The two setter calls are branches of `E9B880`, itself called by the StreamManager constructor at `E9B370`:

- At `E9B89B`, it tests the global DWORD at `0x1378748`.
- If zero, `E9B8A7–E9B8C9` constructs a string directly from the char buffer at `0x13786C8` and passes it to the settings for this stream type.
- If nonzero, `E9B8ED–E9B921` formats `"%s%d"` using that same char buffer and the global integer, then passes the result to the same setter. The only format literal is at `0x113EBF8`; no fixed product-key string literal is passed here.
- Both globals are in the zero-filled tail of the PE `.data` section. Section VA is `0x12FD000`, raw data length is `0x55800` (raw-backed end `0x1352800`), and virtual length is `0xB0E58`. Thus the PE loader's initial values are an empty string and integer 0. File offsets past that raw extent must not be treated as data from these globals; they belong to other sections.
- A whole-file search for the exact little-endian addresses found references to `0x13786C8` only at `E9B8A8/E9B8FE` and to `0x1378748` only at `E9B89D/E9B8EF` (operand addresses). These are the reads just described; no direct writer or pointer table entry was found. The searched surrounding globals belong to other subsystems and did not reveal an initializer for these two values.

**Bounded conclusion:** this path uses a global SDK setting with an empty/zero loader default, not a demonstrated user token or server-response field. The default yields checksum seed 0. No hardcoded nonempty product salt has been found in this exact build. This static trace does not prove that every possible indirect runtime writer is absent, so an active checksum seed is still unverified until checked against a controlled packet or the remaining configuration-initialization path. No process memory, account token, or personal value was inspected.

## Signed data and the two key pairs

The configuration `public_key` is the ECDSA signing trust anchor, encoded as ECS1 public blob (see [CONFIGURATION-PROTOCOL.md](CONFIGURATION-PROTOCOL.md)). The handshake public key is a **separate ECDH P-256 key**.

- `EBAA70` creates the local ephemeral key. `EBAAAC–EBAABD` opens `ECDH_P256` (UTF-16 constant `1099D94`), then generates 256-bit key pair, finalizes it, and exports `ECCPUBLICBLOB` at `EBAB17` and `EBAB69`. The resulting public blob is expected to be 72-byte ECK1 + cbKey32 + X32/Y32, per the native CNG provider contract.
- After SYN ACK, `EBBF6E–EBBFBB` constructs CONNECT with flags 0x30. `EBC233–EBC250` adds 0x80 and the local ephemeral public key when AES mode is active.
- On CONNECT ACK, `EBC2D9` checks ACK, `EBC2FF` checks AES mode, and `EBC316` requires the public-key signature buffer.
- `EBC408–EBC41E` calls `E79910(config_key, packet_public_key, packet_signature)`.
- `E79A55` opens SHA256; `E79E17–E79E2E` calls BCryptHashData on the **entire packet public-key buffer only**. It does not include header bytes or length prefixes in this particular ECDSA hash operation.
- `E7A0F1–E7A118` imports the configuration trust anchor using ECDSA_P256/ECCPUBLICBLOB. `E7A22E–E7A24B` passes the packet signature bytes and their supplied length directly to BCryptVerifySignature. There is no ASN.1 conversion here. A CNG-compatible ECDSA-P256 signature is required; the wire length is explicit, not a hardcoded 64-byte parser rule.
- Only after successful verification does `EBC4C5 → EBD030` import the ECK1 server ephemeral public key and derive a shared secret with the retained local private key (`EBD13A–EBD149`, BCryptSecretAgreement).
- `EBD17B–EBD1A3` calls BCryptDeriveKey(secret, L"HASH", NULL, output, 16, &length, 0). Per Microsoft's API contract, absent hash parameters select SHA1, and a 16-byte buffer truncates the result to its first 16 bytes. This is a documented API implication, not an observed secret value.

Microsoft primary references:

- [BCRYPT_ECCKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob) for ECK1/ECS1 public blob layout.
- [BCryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey) for HASH defaults and output truncation.
- [.NET ECDsa.SignData](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa.signdata) documents IEEE P1363 default formatting. This alone is not a live compatibility test with this client.

## State transitions and remaining work

The built-in server-side SYN response path `EB52D8–EB5344` constructs type 0 ACK, copies incoming sequence ID, writes its generated connection cookie, and reverses the send routing through `EB5B20`. Endpoint receive `EBB7AA–EBB7DD` stores the connection cookie from SYN ACK into endpoint+0xbc. Subsequent sends copy endpoint+0xbc into packet signature (`EBB12C–EBB132`). CONNECT with no established incoming session adopts the packet session ID at `EBBBF9`. Other session combinations have explicit drop/error paths.

The separate [SYN ACK findings](SYN-ACK-PROTOCOL.md) now establish the initial
reply relationships and explain why a local server can choose its own opaque
cookie. That supports a SYN-only experiment. Remaining questions for a full
handshake responder:

1. Active checksum seed: the global SDK setting and empty loader default are now identified above. Remaining question is whether any indirect initialization changes `0x13786C8` or `0x1378748` before `E9B370 → E9B880`; no direct writer was found. A controlled checksum observation can test seed 0 without accessing any account token.
2. CONNECT-specific session, sequence and cookie relationships are now derived
   in the separate [CONNECT ACK findings](CONNECT-ACK-PROTOCOL.md). The local
   probe implements only the empty-request case; live client acceptance is
   still unverified.
3. The CONNECT probe retains and validates its own issued SYN cookie and keeps
   connection keys/session stable for exact retries. Reproducing the native
   `EB9BC0` generator byte for byte is unnecessary for the opaque SYN handoff;
   a complete connection state machine is still needed.
4. Nonempty CONNECT payload semantics, including AES encryption and sequence
   binding (`E82584–E82717` / `E86350`), remain unresolved. Empty payloads bypass
   decryption on the verified receive path; the probe rejects nonempty requests.
5. Exact post-handshake login wire protocol remains outside this pass. No LoginWithToken responder has been derived.

This supports a bounded next static pass and, separately, a deliberately validated local handshake experiment once the remaining fields are established. It does not justify guessing packet bytes or claiming multiplayer compatibility.
