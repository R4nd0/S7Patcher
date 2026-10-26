# Bounded local Login/Register experiment

`--local-config-server --local-login-probe --seconds 960` explicitly enables this experiment. It includes the existing configuration, SYN, CONNECT, DATA ACK and crypto probes. Both listeners remain bound exclusively to IPv4 loopback, with at most eight peers. It does not modify or start the installed game. A connection to this service must already be directed locally by a separate authorized setup.

This implements two candidate application responses, not Ubisoft account authentication, a complete replacement server or playable LAN. Local identities are generated for the service run and are not derived from a token or real profile. Client acceptance remains a live verification requirement. The [UbiServices bootstrap](UBISERVICES-BOOTSTRAP.md), lobby, matchmaking, game exchange, connection maintenance and persistent local profiles remain unresolved.

## Input and memory boundaries

Reliable DATA must match the established loopback peer, virtual ports, session, server cookie and seed-zero checksum. The crypto layer checks padding, the flat/Zlib envelope and its sequence suffix. Only successfully verified plaintext enters a 32-slot reliable window, beginning immediately after the accepted reliable CONNECT sequence. Gaps prevent dispatch, old/duplicate sequences do not dispatch twice, and fragments follow parts 1..255,1.. with final part 0.

Assembly is limited to 64 KiB aggregate stored plaintext and 256 fragments. Invalid part order drops the incomplete message through its final fragment; resource exhaustion requires a new session. Plaintext copies and completed messages are zeroed after use, reset, expiry or shutdown. No plaintext, token, RPC call ID, URL, profile ID, cookie or key is written to events or files. The token is only skipped with length/bounds checks; it is never decoded or authenticated.

Only `LoginProtocol::LoginWithToken_V1` and `LoginProtocol::Register_V1` are recognized. The exact header/argument shapes are documented in [RPC framing](RPC-FRAMING-PROTOCOL.md) and [Login protocol](LOGIN-PROTOCOL.md). Unknown messages receive fixed diagnostic categories, not fabricated responses. Register requires a prior structurally accepted Login. At most two successful responses are queued per peer.

## Temporary local return values

Login returns a generated non-null, non-sentinel 16-byte local ProfileID, the current loopback authentication endpoint with a run-local DID and redirect=false. It never adds a redirected marker. These are explicit experimental identity choices, not known original-server allocation rules.

Register selects a supported PRUDP URL from the structurally valid request with matching client SID. An explicit stream must equal 3; absent stream remains absent. The narrow parser rejects unsupported forms, duplicate attributes, non-ASCII and excessive length. It preserves supported original attributes and only replaces address/port with the observed loopback sender, returning a stable run-local RVCID. No `type=2` is added to the client's public URL.

This preservation policy follows the inspected native path: `E782A0..E782EC` creates a PRUDP URL and address, `E7CC10..E7CC1B` adds its port, and `E8C367..E8C36F` adds SID. `E76A50` copies the full URL list. `E767E0` adds a full URL and deduplicates via full-string comparison (`E76150 → E5D700`). Missing type is read as 0 at `E5E030`; substituting type 2 would change a later CompleteLogin branch. Original-server selection/NAT policy has not been recovered.

## Response transport and expiry

Responses are limited to one fragment of at most 947 plaintext bytes, a conservative bound based on the observed client fragments rather than a claimed protocol MTU. The encoder appends u16LE sequence, optionally compresses only when smaller, encrypts with AES-128-CBC/PKCS7 and a fresh IV, then emits DATA/reliable/ACK-request with server session and client cookie. The first reliable server sequence is 1: native window constructor `EBF890` initializes it at `EBF8E1..EBF8E6`, and `EC15E1..EC15E8` assigns/increments it. Nonreliable SYN/CONNECT/DATA ACKs do not consume it.

Retries reuse identical encoded bytes. Probe policy is one-second spacing, at most four transmissions and a two-minute peer lifetime. These are deliberately finite local limits, not recovered native adaptive timeout settings. A complete empty DATA ACK with matching peer context, sequence and part removes its pending response and zeroes the owned packet. Native acknowledgement lookup `EBADE0 → EC0EF0` uses sequence; part matching is an additional conservative restriction for this single-fragment probe. Unsent, malformed and mismatched ACKs cannot clear a pending response. Exhaustion closes and clears the experimental session.

PING and DISCONNECT are classified passively and are not answered or consumed by the incoming reliable DATA assembler. A reliable control interleaved with DATA would therefore leave a sequence gap in this experiment. The decoder follows jump table `E84A98`: 3 DISCONNECT, 4 PING, 5 USER. Cookie comparison exceptions are SYN/USER, not PING (`EB4C98..EB4CA5`). These omissions may prevent a sustained connection even if Login/Register responses are accepted; that is a separate implementation step requiring observed evidence.

## Live result, 2026-10-25

The original HE client reassembled its Login request from four verified
plaintext fragments (947/947/947/48 bytes). After the local encrypted 191-byte
Login response it acknowledged DATA and sent `Register_V1`. This subsequent
method is evidence of application progress beyond Login, not just transport
delivery. The server then sent a 143-byte encrypted Register response, which
the client also acknowledged. A further encrypted DATA request decoded to
548 bytes, followed by repeated 14-byte PING packets. The probe deliberately
did not answer the additional request because its two-response budget was
exhausted. Its RPC method was not identified or logged.

This establishes Login-to-Register progress. It does not establish completed
game initialization, sustained connectivity, launcher independence, lobby
discovery or playable LAN. The peer expired at the configured two-minute
limit. Only fixed-category events and lengths were retained; no raw client
arguments, account tokens or identities are included in this repository.
