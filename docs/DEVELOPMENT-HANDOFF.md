# Local S7 development handoff

Updated 2026-10-26. Baseline implementation commit: `b94c978`.

## Verified

The separate History Edition test copy reaches the main menu directly without
Ubisoft Connect, startup movies or a click gate. The user confirmed this.
The native adapter establishes a genuine local Login/Register exchange and
the service acknowledges keepalives beyond three minutes. The real connected
state now enables the multiplayer menu. The user opened an empty session list.

The last native change passed 218 checks and 14 original-byte guard checks,
plus configuration validation. The keepalive service passed 612 checks.
These are separate results, not evidence of a playable LAN match.

## Current blocker: discovery does not reach the server

A bounded observer saw seven online discovery requests and seven calls to the
native session-search function. The LAN discovery path was not called.
The search returns at its NAT/network-readiness gate before sending an RPC.
Therefore the empty session list is not a successful empty server response.

Static addresses below refer only to the SHA-256-guarded original executable
documented in `NATIVE-LOCAL-START.md` (preferred image base `0x400000`):

- Online path: `EDA550 -> EF83A0 -> EFD410 -> ED2710 -> ED6C00`.
- `ED6C00` passes the replaced login query at `ED6C2B`, then calls `ED7270`
  at `ED6C3A`. The latter returns false in the observed run.
- `ED7270` reaches `C8FFD0` on the network owner (`Network + 0xA18`).
- `C8FFD0` first checks owner byte `+0x3A`, then the actual RendezVous
  connected state, then a conditional dependency involving `+0x249/+0x25C`.
- A bounded static scan found a write to owner `+0x3A` at `C927C2`, from a
  virtual `+0x14` result. Investigate its enclosing initializer and the actual
  dependency. Do not simply force the readiness flag true.

The native update bridge and real connection state must remain intact.
The SDK-level Ubisoft readiness predicate is not globally patched.
Next milestones are real discovery RPC handling, session creation/joining,
and only then a two-client match test. Full network isolation and LAN are
still unverified. Existing experiments allow loopback only.

## Local workspace (not portable paths)

The containing output directory holds `S7-Local.code-workspace` and the separate
`S7-Local-Test` bundle. User launcher: `Test-Lokale-Anmeldung.cmd` inside that
bundle. The launcher creates fresh local service/configuration state each run.
Its active keepalive peer has a 20-minute hard limit and a two-minute idle limit.
Do not assume an old game process still has a usable service session.

The chat workspace's `work/` contains the private static analysis scripts,
bounded observers, SDK and compiler outputs. It is outside this repository.
Latest verified adapter build: `work/native-menu-build`.
The original installation is `C:/Spiele/thesettlers7` and must remain unchanged.

## TokenSave

Initialized and queried successfully on 2026-10-26 using TokenSave 7.15.0.
The initial index contains 80 source/artifact files and 1,587 symbols.
Use an absolute `graph_root` for MCP queries. `tokensave sync` refreshes local
changes; the index is ignored by Git. No global settings or Git hooks were
installed. No Cairn journal was initialized.

The existing workspace file opens the repository. Registering its folder in
the Codex project sidebar is a separate UI step; this chat can already work
on the repository and query its TokenSave index.
