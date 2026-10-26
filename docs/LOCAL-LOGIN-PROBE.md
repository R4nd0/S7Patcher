# Bounded local Login/Register experiment

`--local-config-server --local-login-probe --seconds 960` explicitly enables this experiment. It includes the existing configuration, SYN, CONNECT, DATA ACK and crypto probes. Both listeners remain bound exclusively to IPv4 loopback, with at most eight peers. It does not modify or start the installed game. A connection to this service must already be directed locally by a separate authorized setup.

This implements two local application responses, not Ubisoft account authentication, a complete replacement server or playable LAN. Local identities are generated for the service run and are not derived from a token or real profile. The original client and the separate native-adapter copy have both acknowledged Login/Register; the separate copy also reported native connected state. Lobby, matchmaking, game exchange and persistent local profiles remain unresolved. See the [native local bootstrap](NATIVE-LOCAL-START.md).

## Input and memory boundaries

Reliable DATA must match the established loopback peer, virtual ports, session, server cookie and seed-zero checksum. The crypto layer checks padding, the flat/Zlib envelope and its sequence suffix. Only successfully verified plaintext enters a 32-slot reliable window, beginning immediately after the accepted reliable CONNECT sequence. Gaps prevent dispatch, old/duplicate sequences do not dispatch twice, and fragments follow parts 1..255,1.. with final part 0.

Assembly is limited to 64 KiB aggregate stored plaintext and 256 fragments. Invalid part order drops the incomplete message through its final fragment; resource exhaustion requires a new session. Plaintext copies and completed messages are zeroed after use, reset, expiry or shutdown. No plaintext, token, RPC call ID, URL, profile ID, cookie or key is written to events or files. The token is only skipped with length/bounds checks; it is never decoded or authenticated.

Only `LoginProtocol::LoginWithToken_V1` and `LoginProtocol::Register_V1` are recognized. The exact header/argument shapes are documented in [RPC framing](RPC-FRAMING-PROTOCOL.md) and [Login protocol](LOGIN-PROTOCOL.md). Unknown messages receive fixed diagnostic categories, not fabricated responses. Register requires a prior structurally accepted Login. At most two successful responses are queued per peer.

## Temporary local return values

Login returns a generated non-null, non-sentinel 16-byte local ProfileID, the current loopback authentication endpoint with a run-local DID and redirect=false. It never adds a redirected marker. These are explicit experimental identity choices, not known original-server allocation rules.

Register selects a supported PRUDP URL from the structurally valid request with matching client SID. An explicit stream must equal 3; absent stream remains absent. The narrow parser rejects unsupported forms, duplicate attributes, non-ASCII and excessive length. It preserves supported original attributes and only replaces address/port with the observed loopback sender, returning a stable run-local RVCID. No `type=2` is added to the client's public URL.

This preservation policy follows the inspected native path: `E782A0..E782EC` creates a PRUDP URL and address, `E7CC10..E7CC1B` adds its port, and `E8C367..E8C36F` adds SID. `E76A50` copies the full URL list. `E767E0` adds a full URL and deduplicates via full-string comparison (`E76150 → E5D700`). Missing type is read as 0 at `E5E030`; substituting type 2 would change a later CompleteLogin branch. Original-server selection/NAT policy has not been recovered.

## Response transport and expiry

Responses now use the bounded multipart queue described in
[response fragmentation](LOCAL-RESPONSE-FRAGMENTATION.md): up to 64 KiB per
logical response, at most two outstanding logical responses and a two-slot
sequence window. Each plaintext fragment remains at most 947 bytes. The encoder
appends its u16LE sequence, optionally compresses only when smaller, encrypts
with AES-128-CBC/PKCS7 and a fresh IV, then emits DATA/reliable/ACK-request with
server session and client cookie. Nonfinal parts are 1, 2, ...; final part is 0.
The first reliable server sequence remains 1, following native EBF8E1..EBF8E6
and EC15E1..EC15E8. Nonreliable ACKs do not consume it.

Retries reuse identical encoded bytes. Local policy remains one-second spacing,
at most four transmissions and a two-minute baseline peer lifetime. Empty DATA
ACKs must match the existing peer context, sequence and echoed part. A later ACK
cannot advance the sequence window past a missing earlier ACK. Native lookup
EBADE0 -> EC0EF0 uses sequence; matching the echoed part remains an additional
conservative restriction. Unsent or malformed ACKs cannot clear stored packets.
Timeout closes the session and clears sent/unsent ciphertext and owned state.

PING and DISCONNECT are classified passively and are not answered or consumed by the incoming reliable DATA assembler. A reliable control interleaved with DATA would therefore leave a sequence gap in this experiment. The decoder follows jump table `E84A98`: 3 DISCONNECT, 4 PING, 5 USER. Cookie comparison exceptions are SYN/USER, not PING (`EB4C98..EB4CA5`). These omissions may prevent a sustained connection even if Login/Register responses are accepted; that is a separate implementation step requiring observed evidence.

## Optional bounded keepalive experiment

`--local-keepalive-probe` includes the local Login probe and additionally answers
empty non-reliable PING requests after both RPC responses have been sent and
acknowledged. The normal `--local-login-probe` retains its two-minute absolute
lifetime and passive controls. The separate-copy launcher's
`--local-connect-probe` selects the keepalive service mode.

The accepted PING subset is type 4, flags `0x20` or `0x60`, complete empty
payload, seed-zero checksum and matching established peer routing, client
session and server cookie. ACKs, non-request packets, reliable controls,
payloads and mismatched contexts receive no response and do not refresh the
session. The native ACK branch `EBBC75..EBBD1D` preserves type and sequence and
sets bit `0x08`. The resulting 14-byte reply has type/flags `0x0c`, the unchanged
server session and the client's cookie. Repeated requests produce identical
bytes; no DATA sequence is consumed. Replies are limited to ten per second.

The loopback optional session expires after two minutes without an accepted PING or
after twenty minutes total, whichever comes first. Expiry clears session keys
and pending ciphertext; traffic cannot revive a closed session. The existing
four-transmission response timeout and two-RPC login budget remain. The opt-in
service now also supports a separately bounded empty session search; see
[local search details](LOCAL-SESSION-SEARCH.md). These
are bounded test policies, not a complete reconnect or server lifecycle.

Activity correction (2026-10-26): the receive loop now passes its monotonic
timestamp to DATA handling. A complete, validated RPC that successfully queues
a reply for an acknowledged registration refreshes the idle deadline too.
Previously an active session browser could expire because only PING counted.
Malformed/incomplete DATA, duplicate sequences, rejected requests, bare ACKs
and exhausted response budgets do not extend activity. Expiry is checked
before processing timestamped DATA, so traffic cannot revive a closed peer;
the absolute cap and response retransmission deadlines still apply.

The compile-time S7_LOCAL_PAIR_LAB service deliberately gives human-operated
two-window tests fifteen minutes idle, one hour total and 512 post-login
responses per peer. Normal builds retain two minutes idle, twenty minutes
total and 32 post-login responses. The baseline non-keepalive probe retains
its two-minute absolute lifetime. This policy is bounded laboratory support,
not a claim of reconnect handling or game-session stability.

### Explicit LAN lifetime

Keepalive sessions constructed with an explicit LocalNetworkPolicy.IsLan now
use a separate policy: fifteen minutes idle, twenty-four hours absolute, and
512 answered post-login RPCs per fixed sixty-second window. A new window
renews the response allowance, not registration, membership or an expired
connection. The receive loop supplies monotonic time. Rejected/duplicate DATA
does not refresh activity; pending response limits and ACK/retry cleanup remain.
Non-keepalive probes and non-LAN loopback/laboratory limits are unchanged.

The LAN launcher starts its own service with the matching 86,400-second cap
and still terminates that child when its host game ends. No subnet or additional
peer is enabled. Tests use encrypted synthetic peers in both address directions,
exhaust/reopen a response window, advance a virtual clock past two hours and
to the final cap, and verify idle cleanup and baseline isolation. This is
not evidence of a real twenty-four-hour game or two-PC synchronization.

Synthetic Windows checks cover reply encoding with an independent checksum,
peer/flag/payload rejection, rate limiting, activity beyond the old absolute
deadline, invalid-traffic expiry, the hard cap and actual loopback UDP replies.
Control metadata now includes only public flag bits alongside existing fixed
categories and lengths. No cookie, sequence, identity, key or payload is logged.
The separate-copy game test on 2026-10-26 confirmed this subset: PING flags
were `0x20`, and 17 replies were sent over 176 seconds without session expiry.
At approximately three minutes, the expected native object still reported
requested=true, connected=true and pending=false. Its network updates continued
normally. This exceeds the old two-minute absolute cap; it does not establish
stability beyond the twenty-minute test cap or successful lobby/gameplay.
The full configuration-server regression suite passes 612 checks, including
88 isolated session checks and 21 actual loopback login/keepalive checks.

## Bounded post-login header observation

Once the existing two-response budget is exhausted, at most eight complete
messages per peer are classified into fixed labels. The classifier checks
message length, bounded ASCII DDL headers and the request discriminator, then
compares known protocol/method names. `matchmaking-search-sessions-v1` denotes
an exact `MatchmakingProtocol::SearchSessions_V1` header, not validated arguments
or a successfully handled search. Unknown names, call IDs and arguments are
never emitted. Retransmitted fragments do not consume another observation.
Plaintext is still cleared in the existing finally block. The classifier
neither creates replies nor enlarges response, lifetime or transport limits.
The following live run identified actual `SearchSessions_V1` requests. The
separate search handler described above now handles that exact method after
registration, with full argument-shape validation.

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
