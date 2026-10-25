# S7 History Edition: statically verified rendezvous configuration

Scope: read-only inspection of `Settlers7R.exe`, build 1.12.1395. SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`. Addresses below are preferred-base x86 virtual addresses, not file offsets. No process launch, capture, credentials, private endpoint requests, or installation changes were used for these findings. Runtime compatibility remains untested here.

## Configuration request

- `E8A3DE–E8A3F0`: sandbox friendly name compared to `localhost` with `_mbsicmp` (case insensitive).
- Matching branch `E8A59E–E8A5B9`: mode 2, address `127.0.0.1`, port `0x2396` (9110).
- `E8FE09–E8FE46`: builds `http://%s%s/%s`, with port formatted as `:%i` when nonzero, and path `public/rendezvous/v1/configuration`.
- Thus this branch's intended local request URL is `http://127.0.0.1:9110/public/rendezvous/v1/configuration`.
- HTTP GET: constructor `A45200` installs vtable `106F87C`. Its clone at `A8FF30` explicitly references `.../http/request/httpGet.cpp`; method slot `4C59A0` returns enum 0.
- `E8FF5C–E8FF7B` adds the `Ubi-AppId` header. No actual AppId or credential value was read.
- `E909DD–E909E3`: only HTTP status 200 follows the response-parser branch. Other statuses are mapped to errors.
- `E90DE9–E90E0C`: gets the response body and constructs the UbiServices JSON wrapper. No content-type comparison appears in this handler; `application/json` is a conventional server choice, not an observed required branch.

## Response shape

The response is a JSON object with these top-level fields, not the old Quazal `[{Name,Values}]` shape:

| Field | Type consumed | Evidence and behavior |
|---|---|---|
| `public_key` | string | lookup `E90E99`, string getter `E90EBA`. Empty is rejected at `E90F04–E90F0B`, logging `Obtained a 0 length Public ECDSA key.` and failing with Core error 4. |
| `prudp_loadbalancer_url` | string | lookup `E91044`, string getter `E91065`, stored at job+0x2a4. A nonempty value takes precedence over `prudp_urls`. |
| `prudp_urls` | array of strings | lookup `E910AF`, array getter `E910D0`; each member goes through string getter `E9111C`, then StationURL construction `E91143`. |

JSON object lookup is `A62E80`. `AC1940` returns a string only when JSON node type is 4, otherwise an empty string. `AC1770` returns children only for node type 5 (array), otherwise an empty vector. Therefore a missing/nonstring balancer acts as empty, and a missing/nonarray URL list acts as empty. A missing/nonstring public key fails the nonempty check. The parser's ability to continue on wrongly typed fields is not a reason for a server to emit them.

When the balancer is empty, `E91293` invokes `E8EB40`: an empty URL vector returns false and `E913AE` enters RendezVous error 0x83. One entry is selected directly; multiple entries are randomly selected using `E6A6E0(count)`. The selected address and port are copied at `E912A0–E912D6`. There is no evidence of retry/fallback to another entry in this block.

When the balancer is nonempty, `E91239–E91260` schedules `E90470` (StartAsynchronousDNSLookup), which launches callback `E8CB80`. That callback parses the balancer as a StationURL, copies address and port into the same job fields, clears the balancer string, and signals completion. `E908A0` then schedules ConnectEndPoint. The balancer is a PRUDP StationURL, not an HTTP URL.

## StationURL and port semantics

For a deliberately local configuration, the evidenced minimal endpoint spelling is `prudp:/address=127.0.0.1;port=<actual-bound-UDP-port>`. The placeholder is documentation, not a runnable response.

- `E5E720–E5E7AB` accepts type strings `prudp` and `udp`; unrecognized types fail.
- `E5E350` finds `:/`, then passes the rest to `E5E4D0`. An optional `#` section is supported by the generic parser but is unnecessary here.
- `E5E4D0` splits parameters at `;` and each parameter at `=`. Empty names/values fail. `address` and `port` use case-sensitive `_mbscmp` at `E5E583` and `E5E5BF`.
- Port parsing uses `atoi` then takes the low 16 bits (`E5E5D5–E5E5E0`). A replacement service should validate 1–65535 itself instead of relying on this truncation.
- Address parsing `E6D990`: literal `localhost` is replaced with `127.0.0.1`; numeric IPv4 goes through `inet_addr` at `E6DA33` and branches directly to success if valid. DNS `gethostbyname` is reached only after numeric parsing fails. A numeric `127.0.0.1` cannot become a remote DNS result in this code path.
- `E5DF50 → E6D970` returns the StationURL port via `ntohs`. There is no HTTP-config-port fallback here: the selected URL's port overwrites job+0x16c, which previously held 9110.
- `E8DFC3–E8E052` constructs a fresh auth endpoint string from those address/port fields: `prudp:/address=<address>;port=<port>;stream=3;sid=1;type=2`.
- Consequently stream/sid/type supplied in config URL entries are not preserved in this initial auth connection branch; the client supplies 3/1/2 itself. The HTTP configuration port and actual PRUDP authentication port are independent.

A narrowly scoped local config component can therefore choose an empty balancer string and exactly one numeric-loopback PRUDP URL, with the actual port of its own authentication listener. This is a design implication of the branches, not a claim that the remaining server protocol exists.

## Public key encoding and purpose

- After the nonempty check, `E9100D` selects the AES encryption engine. `E91025`/the call to `E77190` stores the public key for network use.
- `E77190` calls `E6B230` twice to Base64-decode the string and stores the decoded bytes in Network+0x2ec. The decoder uses the standard alphabet and trailing `=` handling. This field is a Base64 binary blob, not a PEM text or DER wrapper.
- `E7993A` compares the first decoded DWORD with `0x31534345` (bytes `ECS1`), and `E7994D` also admits `0x314b4345` (bytes `ECK1`) through the preliminary check.
- The later provider opened at `E79FFB–E7A00F` is UTF-16 `ECDSA_P256` (constant at `1099CDC`).
- `E7A0F1–E7A118` imports the entire decoded buffer using UTF-16 `ECCPUBLICBLOB` (constant at `1099C88`). Thunk `E3EDBC` resolves to imported `bcrypt.dll:BCryptImportKeyPair` at IAT `1051D90`.
- The canonical ECDSA P-256 public blob is 72 bytes: little-endian DWORD magic ECS1, little-endian DWORD cbKey=32, 32-byte big-endian X, 32-byte big-endian Y. Header bytes: `45 43 53 31 20 00 00 00`. Standard Base64 gives 96 characters with no padding for 72 bytes. Use a real independently generated key pair; arbitrary public bytes will not establish a working handshake.
- ECK1 passing the preliminary magic check does **not** prove that every ECK1 blob is accepted by the ECDSA provider. ECS1 is the appropriate encoding for an ECDSA signing public key.

Microsoft primary documentation for the format and API:

- [BCRYPT_ECCKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob): header and big-endian public coordinates.
- [BCryptImportKeyPair](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair): ECCPUBLICBLOB input contract.

## Dependencies beyond configuration

Before retrieval, `E905B0` rejects an empty RendezVous token (`E90629–E90706`). `E8FC20` still requires the UbiServices facade to provide its HTTP client. The localhost selector changes config routing; it is not an offline identity provider or a completed login implementation.

The config key is an anchor for a later signed handshake: at `EBC408–EBC41E`, Network+0x2ec, packet+0xc0 (server handshake public key), and packet+0xcc (signature) are passed to `E79910`. That function hashes with SHA-256 and verifies using `BCryptVerifySignature` (`E7A24B → E3EDD4 → IAT1051D94`). Only after verification does `EBC4C5` call `EBD030` to set a shared secret. Failure logs explicitly distinguish missing packet public key, invalid public-key signature, and failed shared-secret setup.

Static RPC names include `LoginProtocol::LoginWithToken_V1`, `LoginWithS2SToken_V1`, `RedirectLogin_V1`, `Register_V1`, `RenewWithTicket_V1`, plus `SecureConnectionProtocol::Register_V1`, `RequestConnectionData_V1`, and `RequestURLs_V1`. Their wire format and required application semantics have not been derived here; names are not an implementation.

The HTTP component can be implemented from the verified schema. A successful HTTP response alone cannot demonstrate PRUDP authentication, lobby discovery, joining, or multiplayer. Runtime loopback routing and subsequent protocol stages require separate evidence.
