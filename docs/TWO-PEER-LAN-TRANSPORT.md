# Explicit two-PC LAN catalogue experiment

2026-10-26. This is transport/catalogue preparation, not a completed join or match implementation.

## Implemented

The service accepts `--local-catalogue-probe --lan-address <local> --lan-peer <other>
--content-id <64 lowercase hex>`. Both addresses must be distinct canonical
RFC1918 IPv4 hosts; no wildcard, DNS, subnet or public endpoint is allowed.
HTTP and UDP bind the selected local interface, and both accept only the two
configured addresses (plus loopback). The login engine validates the observed
transport endpoint under the same policy. Ordinary mode remains loopback only.

The adapter reads the paired addresses from the bounded fresh runtime file.
The selected server must equal one of them. Existing executable hash, native
ABI/callsite guards and signed server-key setup remain active. Outbound Winsock
allows only loopback or the exact pair; wildcard IPv4 binds and gethostname
advertise the local LAN address. Numeric legacy resolution preserves the
requested address instead of always returning loopback. IPv6 LAN is unsupported.
This is still the bounded import guard documented in NATIVE-LOCAL-START.md,
not a system-wide firewall or comprehensive inbound UDP filter.

`Test-LAN-Verbindung.cmd` selects host/client and both addresses. Host uses TCP
9110 for public configuration and UDP 9111 for the existing PRUDP experiment.
Client fetches that explicit host, compares the deterministic content ID,
validates the returned PRUDP endpoint and key, and only then starts the game.
The client launcher aborts on missing/different content ID. This is a cooperative
startup compatibility check, not an authenticated per-RPC admission protocol
and not proof of deterministic simulation. No automatic firewall changes occur.

The preparation package includes both roles, runtimes and archive delta. It
still declares lan_host/lan_join false: those flags mean verified playable
capabilities. Installation uses each recipient's own original game files.

## Verification

- Build succeeds with zero warnings/errors; native /W4 /WX.
- 4,613 service checks, 477 isolated login-engine checks.
- 61 network guard, 272 patch-writer, 88 platform, 18 connection-state,
  14 CPU-affinity checks pass.
- Seven LAN launcher and ten installer tests pass. Python tests use a workspace
  temporary directory because the sandbox's default TEMP denied writes.
- Actual no-game preflight on this machine's selected LAN address succeeded.
- User then started the installed test copy and reached a four-slot public lobby.
  Native status records explicit-two-peer-lan-enabled and connected; Login,
  Register, Search, Create and Update replies were acknowledged. The game's
  inspected IPv4 UDP sockets bind its actual LAN address, not loopback.
- Independent real installer run completed all 54 game-file copies. The original
  vs working-copy comparison differs only in the adapter and Interface.bba.

## Still required

Actual foreign-client catalogue display; GetSession and Join request validation
against a game client; member lifecycle, notifications, game station route
validation, host/join success, match start, role reversal and sustained matches.
Existing bounded experiments retain a 20-minute connection lifetime and 32
post-login response cap; they are not suitable for long games yet.
No claim of desync-free gameplay is made. Do not silently lift these limits
before implementing and testing resource/lifecycle handling.
