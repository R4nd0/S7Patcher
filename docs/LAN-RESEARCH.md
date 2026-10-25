# History Edition local multiplayer research

Status on 2026-10-25: **no working replacement multiplayer server or LAN play**.
The tools provide build identification, a reproducible diagnostic archive,
and a guarded local bootstrap experiment. A visible LAN menu, successful
archive validation, or a native
function returning success is not evidence of a working multiplayer session.

## Supported research target

- Ubisoft Connect History Edition, executable file version `1,12,1395,0`.
- `Settlers7R.exe` SHA-256:
  `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.
- Pristine `Interface.bba` SHA-256:
  `766ae21ef06709309a68fb5bb792b0fd56373c668f02140122eef181917b0b94`.
- Observed installation layout: `Base/Bin` and `Base/BBA`. Tools also recognize
  the `Data/Base` layout. These fingerprints do not cover other editions or
  executables already modified by the original patching command.

## Findings

The original interface defines an Online/LAN filter, selects Online, and hides
the filter. It also passes a LAN flag into session creation. These surviving
interfaces alone do not establish that usable LAN multiplayer was shipped in
this build.

Native inspection of the fingerprinted executable established the following.
Addresses below are virtual addresses for the preferred image base `0x400000`;
they are research locations, not portable patch offsets.

| Operation | Evidence | Consequence |
| --- | --- | --- |
| Matchmaking construction | `0xEDAC10` creates both Online and LAN objects | Both paths are represented in the engine. |
| Discovery selection | `0xEDA320` selects LAN at `this+0x10` for true, Online at `this+0x0c` for false | The Lua discovery boolean has a native effect. |
| Lua join arguments | Binding `0x84F050` reads the LAN flag from argument **3** | Changing only argument 2 does not select LAN. |
| LAN join | Vtable `0x11411A4`, slot `+0x24`, targets `0xEF8E00`: `mov al,1; ret 4` | It reports success without implementing a peer join. |
| LAN create | `0xEF8F70` reaches `0xED62D0`, which consults login getter `0xED7230` and NAT getter `0xED7270` | Removing Lua UI gates does not eliminate native online dependencies. |

The single-player Lua path also selects local session creation when logged
out. Consequently, some of this machinery may serve local single-player
sessions. We have not established whether an older edition ever had complete
LAN discovery and joining, or whether those capabilities were removed.

## Scope of the diagnostic archive

The archive delta adds `LAN diagnostics (not playable)`, exposes the filter,
and carries the selected mode through the relevant screens. It changes only
the associated Lua UI gates; it does not replace native login, readiness,
transport, synchronization, or game-start logic. LAN joining is deliberately
disabled because its native implementation is a success-returning stub.

The preparer requires exact input fingerprints and verifies the original and
modified bytes of every delta. It appends replacement payloads while retaining
the existing entry order and filename lookup table, then checks all 284 files
in the resulting archive. It writes only a new staging directory.

The repository contains patch descriptions and our tools, not full game
scripts, archives, executables, accounts, or network captures. A generated
archive contains locally installed game material and must remain local.

## What a replacement needs

There are two distinct routes to investigate: implement the missing local
discovery/join behavior and connect it to the actual transport, or reproduce
the game's online matchmaking protocol on a local service. The presence of
Quazal/RendezVous code does not establish compatibility with another game's
server emulator.

A native `localhost` sandbox branch resolves to `127.0.0.1:9110`. That is a
useful routing experiment, not a documented command-line option or proof of
an offline backend. Ubisoft service initialization and later authentication
dependencies must be accounted for separately. See the
[bounded routing probe](../tools/research/README.md).

The exact HTTP configuration response has been derived from this build's
parser. It contains a Base64 CNG ECDSA P-256 public blob and PRUDP StationURLs;
it does not use the older Quazal Name/Values array. See the
[configuration protocol findings](CONFIGURATION-PROTOCOL.md). The new
`--local-config-server` implements that configuration endpoint and binds the
advertised UDP port. By default it counts datagrams without replying.
`--handshake-metadata` enables passive structural classification;
`--syn-probe` adds a narrow SYN-only response experiment, with stricter gates
than the generic decoder and at most eight local sender cookies. CONNECT,
the authenticated UDP handshake, login RPCs, matchmaking and game
synchronization remain unimplemented.

The next transport stage has a separately documented
[SYN/CONNECT wire format](HANDSHAKE-PROTOCOL.md), including byte ordering,
packet boundaries, the two distinct key pairs, and unresolved session/cookie
behavior. The [SYN ACK relationships](SYN-ACK-PROTOCOL.md) have since been
derived separately to support a deliberately limited response experiment.

Full offline operation also needs a separate
[UbiServices session/bootstrap adapter](UBISERVICES-BOOTSTRAP.md). The normal
client checks a session ticket and expiration, application and space parameter
readiness, and an initialized asynchronous HTTP engine before the local
RendezVous stage. A configuration reply alone does not remove these dependencies.

## Verification so far

- Debug build completed without warnings or errors. The inspection/preparation
  command-line harness passed 17 cases; archive tests passed 16 cases including
  the real installation and a Windows junction target.
- Independent extraction checked all 284 files in the staged archive. Lua
  parsing checked the six original and six patched scripts, and all six byte
  deltas reconstructed their expected hashes.
- Starting a separate test-copy executable caused Ubisoft Connect to relaunch
  the registered installation. A subsequent attempt temporarily installed the
  diagnostic archive from a verified backup. The UI test was interrupted before
  the changed menu was observed. The pristine archive was restored and both
  original EXE/archive fingerprints were checked afterward.
- An initial probe attached too late or otherwise missed initialization:
  `hook-ready` alone produced neither a redirect nor a local request.
- A subsequent fresh-start probe reached `hook-ready`, then
  `sandbox-redirected`, followed by a local `GET
  /public/rendezvous/v1/configuration` (197 request bytes read). The observer
  replied HTTP 503 as designed and confirmed hook/listener cleanup. This is
  temporal correlation with the authorized game's redirect; the HTTP socket
  did not independently establish the sender's process identity. It confirms
  the first routing milestone, not configuration acceptance or login.
- The observer's 32 synthetic Python tests cover bounded attachment retries,
  relaunches, stale-generation rejection, error and cancellation cleanup,
  header redaction, and hook-only completion after the constructor returns.
  Fourteen additional scenarios run the actual JS source with mocks, including
  fixed error categories and bounded waiting for an absent main module. Native
  Frida lifetime behavior is not established by these synthetic tests.
- The configuration-service harness now passes 143 checks with real local HTTP/UDP
  sockets, Windows CNG import of the advertised ECDSA public key, error routes,
  metadata-only logging, request timeout, cancellation, port rebinding and CLI
  dispatch. The optional SYN probe is also checked for its exact reply layout,
  retry-cookie consistency, narrow request gates, and sender limit. The Debug
  build completed with zero warnings and errors; all 17
  existing CLI cases passed again after integration.
- The isolated SYN/CONNECT decoder passed 1,893 checks and 5,000 deterministic
  malformed-input samples. These use invented bytes; they cover truncation,
  packet boundaries and an independently calculated additive checksum without
  treating an unknown seed as verified or establishing peer authentication.
- A subsequent live game start reached `redirection-completed` in hook-only
  mode and detached with exit code 0. The separate configuration service
  replied HTTP 200 to a 197-byte request, then observed ten UDP datagrams of
  18 bytes on its advertised loopback port. This supports progression from
  configuration to UDP connection attempts. Only lengths were observed; the
  packet type, sender process, handshake completion, and login were not
  independently verified. The service sent no UDP response.
- The live service was stopped through the terminal harness. That interrupted
  the output pipeline without a final stopped event; graceful shutdown was
  therefore not established by this live run. Both local ports were checked
  closed afterward, and the original EXE/archive hashes still matched.
- The first SYN-response experiment did not reach the service: attachment to
  the restarted game failed during script setup before `hook-ready`. The
  original error was deliberately generic, so its cause is unknown. A later
  five-second check against the running game passed every hook guard, then
  timed out without reinitialization. Diagnostics now preserve only fixed
  failure categories and wait up to two seconds only when the main module is
  absent; path, architecture, memory and byte failures remain terminal. The
  unused SYN service stopped automatically with zero datagrams and confirmed
  its shutdown.
- The final bounded run with refined startup diagnostics attached to the
  existing game and reached `hook-ready`, but recorded no new process
  generation, constructor redirect, HTTP request or UDP datagram during its
  window. The hook timed out and confirmed cleanup; the service stopped at
  its deadline with zero datagrams. Live SYN-ACK acceptance remains unverified
  and requires a fresh game start while both components are ready.

The archive and CLI checks above validate the tools. They do not validate the
in-game menu or multiplayer compatibility. Runtime tests must be recorded
separately from synthetic observer tests.

Completion requires two game clients to discover or explicitly select the
same local host, join, synchronize slots and readiness, start a map, and keep
simulation state synchronized with internet access unavailable. It also
requires clean leave/rejoin and useful failures when the host disappears.
None of those end-to-end checks has passed yet.

## Sources

- [Requested base fork](https://github.com/R4nd0/S7Patcher).
- [Upstream patcher](https://github.com/Eisenmonoxid/S7Patcher).
- [S7Packer archive format implementation](https://github.com/Eisenmonoxid/S7Packer/tree/685ee365564f4566dba8091d474076c692466975), MIT license retained under `tools/lan`.
- Read-only inspection of the exact local game files identified above. Game
  file content is not redistributed with this report.
