# S7 History Edition DATA crypto: bounded static evidence

Analyzed executable: `C:\Spiele\thesettlers7\Base\Bin\Settlers7R.exe`, PE32/x86, preferred base `0x400000`, SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.

Scope: static executable bytes, existing static disassembly and public Microsoft API documentation. No live game process, account files, runtime packet bodies, headers containing credentials, or plaintext payloads were accessed. These findings describe the transport transformation; they do not establish an authenticated login or working multiplayer service.

## Established transformation

For a nonempty DATA payload using the executable's default AES and Zlib stream settings, the send path is:

```
packet plaintext
  || sequence_id_u16le
  -> compression envelope
  -> AES-128-CBC with CNG block padding and a fresh random IV
  -> IV[16] || ciphertext[n * 16]
```

The receive path reverses those operations, then compares the trailing sequence copy with the header sequence and removes that copy. Outer PRUDP header fields, optional payload-length field and additive checksum are not part of the AES input in these functions. The observed sequence check is an integrity check inside the encrypted plaintext, not an authenticated-encryption tag or MAC.

Compression and encryption are configured per stream. The default values in this exact file select both AES and Zlib; that is a static configuration finding, not a claim that arbitrary other clients or every runtime stream necessarily have identical settings. A future decoder should explicitly bind itself to the established stream/mode instead of trying multiple transforms until a payload appears plausible.

## AES provider, key, padding and IV

`E78AA0` constructs the AES engine, with vtable `10FDF04`. Relevant entries are +8=`E79300` (encrypt to another buffer), +0x0c=`E7F960` (generic in-place decrypt wrapper), +0x10=`E79000` (decrypt to another buffer), and +0x18=`E79720` (set raw key bytes).

| VA | Static observation |
|---|---|
| `E78B4B–E78B5C` | Opens a BCrypt provider named UTF-16 `AES`; handle is engine+0x28. |
| `E78C20–E78C2A` | Opens the `RNG` provider; handle is engine+0x2c. |
| `E78D4A` | Reads the provider's `BlockLength` into engine+0x50. AES block length is 16. |
| `E78DCC–E78DDC` | Sets `ChainingMode` to `ChainingModeCBC`, with property length0x20 and flags0. |
| `E797D4–E797E7` | Imports the supplied raw bytes with `BCryptGenerateSymmetricKey`; no byte reversal is applied. |
| `E793D8–E793FF` | Sizes encryption using `BCryptEncrypt` with flags1 (`BCRYPT_BLOCK_PADDING`). |
| `E794C3–E794DA` | Allocates the required ciphertext length plus one IV block. |
| `E794DF–E794EF` | Fills the first block of the output buffer using `BCryptGenRandom`. |
| `E794F4–E79516` | Copies that IV to a temporary buffer because BCrypt may modify its IV argument. |
| `E7951B–E79552` | Encrypts into output+blockLength, using the temporary IV, NULL padding-info and flags1. |
| `E79602–E7960B` | Sets output length to blockLength + actual ciphertext bytes written. |
| `E791CA–E7921B` | Decrypts input+blockLength for inputLength−blockLength bytes, using the input prefix as IV and flags1. |
| `E79220–E79227` | Sets decrypted output length to the actual bytes returned by BCrypt. |

The wire body is therefore **16-byte random IV followed by CBC ciphertext**. The IV is not derived from a header sequence, part ID, session byte, cookie or prior packet. The CBC call has no AAD or authentication-tag structure. Each encryption generates its own IV; a receiver does not need previous packet ciphertext to initialize this call.

The exact padding contract established by the binary is **Windows CNG `BCRYPT_BLOCK_PADDING`**. CNG chooses the padding bytes. The official Microsoft sample notes that even block-aligned input receives a complete additional block. Before substituting a different crypto implementation, verify its PKCS#7-compatible behavior against CNG using synthetic offline vectors, including lengths0/1/15/16/17 and invalid padding. This static analysis has not performed that interoperability test and does not infer padding bytes from captured game data.

The decrypt implementation passes the IV prefix directly to BCrypt, which can mutate that buffer. An independent decoder should copy the IV into private temporary storage and avoid modifying the original datagram. A nonempty AES body must contain an IV plus at least one complete ciphertext block; a narrow decoder can reject lengths below32 or with `(bodyLength−16) % 16 != 0` before calling the provider. Native empty-payload handling is a separate bypass, not a zero-length AES message.

Relevant file offsets (for the exact hash above): `E78DDC→A781DC`, `E793FF→A787FF`, `E794EF→A788EF`, `E79552→A78952`, `E7921B→A7861B`, `E797E7→A78BE7`.

## Connection key derivation and installation

The [CONNECT acceptance path](CONNECT-ACK-PROTOCOL.md) imports the server ECK1 P-256 public blob at `EBD05E–EBD083`. At `EBD13A–EBD149`, `BCryptSecretAgreement` combines that public key with the retained client private key. At `EBD17B–EBD1A3`, the arguments are:

```
BCryptDeriveKey(secret, L"HASH", NULL, output, 16, &written, 0)
```

For this CNG KDF, absence of a hash-algorithm buffer selects SHA-1; a 16-byte requested output truncates its digest to the first 16 bytes. There is no prepend/append salt in this NULL-parameter-list call. The resulting buffer is stored at endpoint+0x850. Reimplementing the ECDH raw-secret byte order by assumption would be unnecessary and risky; use CNG-compatible ECDH `DeriveKeyFromHash(SHA1)` semantics and verify with synthetic keys.

`E82638–E8266B` installs the packet's shared-secret buffer through cipher virtual+0x18 before send encryption. On the deferred receive path, `E863B7–E863CD` likewise installs that packet's shared secret before decrypting. The key setter passes its bytes and length unchanged to `BCryptGenerateSymmetricKey`. Thus the connected DATA path uses the16-byte derived key, giving AES-128. The AES constructor's separate initial/default key is not a valid substitute when connection key material is missing.

## Compression envelope and exact ordering

Send serialization `E825A2–E825DA` appends packet+0x18, the header sequence ID, as two little-endian bytes when `E76EA0` is true. `E76EA0` returns global byte `1378630`; selecting the AES engine at `E770E0` sets it to1 at `E77179`. The original packet buffer length is restored after serialization at `E826EC–E82700`.

The endianness here is directly established: `E825A2–E825A6` copies the u16 into an x86 stack scalar; `E673B0–E673C3` simply multiplies its size/count arguments (2×1) and appends those raw bytes without a swap. The third argument1 is a count, not an endianness flag.

`E825EE–E82635` obtains the stream settings through `E5CB10`. If settings+4 has a compressor, `E7E9C0` compresses the already extended payload. `E8268C–E82693` subsequently encrypts that result. Therefore the sequence copy is inside the compression envelope and must be checked after decompression, not directly at the end of CBC plaintext in the Zlib case.

The network constructor passes the file-initialized DWORD at `13177D0` (value1) to `E76B90` at `E76462–E76468`. Value1 selects the diagnostic-labeled Zlib engine at `E76D6E`; value0 selects no compression. Settings for stream types2 and3 receive the compressor pointer at `E76E6A–E76E8D`. The separate AES default byte `13177D4` is also1 in this file and leads to `E770E0` at `E76478`.

The Zlib engine constructor `E77720` assigns vtable `10FDA4C`; virtual+4=`E779C0` compresses and virtual+8=`E77C90` decompresses. Its inflater initialization calls `EAD2C0`, which supplies windowBits15 at `EAD2C9`. This is the standard Zlib-wrapped stream, not raw DEFLATE or gzip.

The envelope has exactly one leading byte:

| First byte | Remaining bytes |
|---|---|
| 0 | Uncompressed input, including the final two sequence bytes. |
| Nonzero | Standard Zlib-compressed input, including the final two sequence bytes. |

`E779D3–E77A08` emits the zero envelope when `UseFlatCompression` is enabled. Otherwise `E77B63` calls deflate with `Z_FINISH`; if compression is not smaller than the input, `E77C45–E77C75` also emits zero plus the original bytes. For compressed output, `E77BB2–E77C3C` writes a capped ratio/capacity hint (approximately truncated `originalLength / compressedLength + 1`, capped at255). The byte is neither a fixed compression-type enum nor an encoded uncompressed length.

On receive, `E77C90–E77CAA` reads that byte. Zero copies the remainder directly at `E77DFF–E77E2F`. Nonzero sets an initial output capacity of hint × entire envelope length, skips the first input byte at `E77D86–E77D8E`, and inflates at `E77D97` with `Z_SYNC_FLUSH`, expecting `Z_STREAM_END`. The implementation can expand its output buffer on exhaustion; the hint does not guarantee an exact bound. A replacement decoder should enforce its own conservative plaintext and decompression limits rather than trust this byte or allocate without a limit.

## Deferred decryption and sequence validation

`E86350` obtains the source stream type through `E7FF80` and its stream settings through `E5CB10`. Settings+8 is the cipher. When the packet's internal +0xc8 boolean is true, a non-NULL shared-secret buffer at +0xc4 is required. The routine then calls the cipher's in-place decrypt wrapper at `E863D3–E863DA`. That wrapper (`E7F960`) calls AES decrypt virtual+0x10 at `E7F99D`, then copies successful plaintext back into the packet buffer.

`E865C5–E865DE` invokes the configured compressor's in-place decompression wrapper. Only afterward does `E867E5` check the AES sequence-copy gate. `E86810–E86836` reads and removes the final two plaintext bytes; `E8685B–E86868` compares the resulting u16 with packet+0x18. A mismatch returns failure. The diagnostic at `E868C8` explicitly describes a possible forged packet and prints header/data sequence IDs.

**Internal +0xc8 is not a DATA wire encryption flag.** Independently checked by the PRUDP research agent: `E87C50–E87C61` sets it for a nonempty payload when the third Unpack argument requests deferred decryption; `E87C78` clears it on the direct-decryption path. `EBBD47–EBBD65` checks it for DATA, supplies endpoint+0x850 as shared secret, and calls `E86350`. Wire bit0x80 is used at `E8727D` after a type==CONNECT check to parse the key extension; this provides no basis for treating that bit as a DATA-encrypted indicator.

No part/fragment ID check or binding was found in this crypto/compression routine. That does not prove other protocol layers omit fragment checks. The transport header/session/cookie/ACK logic remains a separate acceptance layer. Empty received payload bypasses crypto at `E87C66–E87C70`; the generic ACK is constructed before deferred DATA decryption at `EBBC75–EBBD1D` / `EBBD47`, so seeing an ACK alone would not prove that plaintext was accepted.

Relevant file offsets: `E825A2→A819A2`, `E8262B→A81A2B`, `E82693→A81A93`, `E863CD→A857CD`, `E863DA→A857DA`, `E865DE→A859DE`, `E8685F→A85C5F`, `E77C90→A77090`.

## Minimal next verification and limits

A future decoder can remain local and metadata-only: bind the exact accepted connection, derive the key from its retained local handshake key and client public key, validate the outer packet, split IV/ciphertext, perform CBC padding validation, decode the configured compression envelope with strict bounds, then require the plaintext sequence copy to match the header. Report only fixed categories and numeric lengths/status; do not print plaintext, ticket-like fields, strings, key bytes, raw packets, or exception messages that can include them. Key and decrypted buffers should remain ephemeral memory.

Before live use, test CNG↔replacement interoperability with generated keys and synthetic content, both compression branches, every CBC length boundary, incorrect sequence, corrupt padding, truncated bodies and bounded inflation. This report does not implement such a decoder. It has not inspected real decrypted RPC content, established application message structure, proven LoginWithToken success, or supplied any offline Ubisoft identity/session response.

Primary API sources used to interpret the imports:

- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt): block-padding flag, sizing call, IV mutation.
- [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt): matching padding mode and IV semantics.
- [BCryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey): HASH's default SHA-1 and output truncation.
- [Microsoft CNG encryption/decryption sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CipherEncryptionDecryption/cpp/CipherEncryptionDecryption.cpp): an additional padded block for block-aligned input.

Research completed 2026-10-25; all addresses above are static VAs for the exact executable hash, not runtime pointers.

## Decoder validation detail

The opt-in implementation subsequently passed the 419-check configuration-server suite, including independent Windows BCrypt HASH/NULL/16 agreement-key derivation and CBC/Flag1 interoperability in both directions. Synthetic tests cover both envelope branches, CBC boundaries, invalid padding, wrong sequence, incomplete compression, bounded expansion and actual local UDP dispatch. This validates the implementation against generated fixtures; live decryption and login remain separate unverified milestones.

The later metadata-only implementation must distinguish completed Zlib output from a truncated stream. In the [.NET 10 implementation](https://raw.githubusercontent.com/dotnet/runtime/v10.0.0/src/libraries/System.IO.Compression/src/System/IO/Compression/DeflateZLib/DeflateStream.cs), a nonempty synchronous read may return zero when underlying input ends even if inflation is unfinished, unless a global strict-validation switch was enabled before its cached initialization. An Adler checksum alone does not establish the final DEFLATE block.

Independent synthetic testing reproduced this with the invented Zlib bytes `78 01 00 02 00 FD FF 01 00 00 04 00 02`: a nonfinal stored block containing two bytes and a matching Adler trailer. A guarded memory input that throws on a nonempty read past its end rejects this case. A completed inflater returns zero without requesting more input, so valid completed streams still work. This avoids relying on a process-global switch or private runtime fields. The decoder retains a separate expansion cap and trailer check. These fixture bytes contain no game data.
