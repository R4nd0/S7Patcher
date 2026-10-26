# History Edition content and CPU patch audit

2026-10-26, supported Ubisoft HE executable only; original files stay unchanged.

## Upstream definitions checked

The embedded `Definitions/Definitions.bin` (gzip EMX version 1) has three
variant blocks. Original/Gold has 16 default edits plus optional DBG/AFF edits.
Ubisoft HE has exactly one default edit (file offset 13D9FC, byte 94), one
optional DBG edit (AC5D4A, two NOPs), and three AFF edits (458BAB, D31AD0,
AC6505). Gold's reward/DLC/crash patches cannot be applied at those offsets to HE.

The default HE edit changes SETNE AL to SETE AL at 53E5FB. The adapter now
applies that exact development-mode change in memory, checking all three
original instruction bytes, after full EXE identity validation. It uses the
existing transactional patch writer, with bounded raw edits added alongside
CALL and relocated-pointer edits. Debug-only edits are not required here.

AFF resolves SetProcessAffinityMask and replaces the original main-thread
CPU-0 pin. Upstream's user-entered signed byte mask does not discover physical
cores. Our adapter uses the same Windows process-affinity mechanism, selects
one allowed logical CPU per physical core (at most four), prefers higher
Windows efficiency classes on hybrid CPUs, and widens the bootstrap thread to
that mask. No system-wide SMT or BIOS setting changes. Topology/group errors
stop startup rather than silently selecting SMT siblings. Fewer than four
available physical cores use the available count.

## Content changes and boundaries

The native ED0300 predicate returns whether a known privilege descriptor is
locked. Its two direct callers ED02EE/ED05DF retain their existing item lookup
and existence checks; guarded cdecl replacements return false for that lock
query. This covers the exposed privilege-item and IsPrivilegeItemLocked paths,
including editor content checks. No arbitrary SDK function gets guessed success.
Other gameplay/reward paths have not all been live-tested; do not claim every
reward, title or online feature is functional from this alone.

Campaign selection calls the existing GetUnlockedCampaignMaps(true) branch.
Native 54A3B0/54A3FD enumerates the full campaign vector for that argument.
The delta is fingerprinted and appended to Interface.bba through the existing
S7Packer-derived archive engine. Saved progress is not rewritten. AI restrictions
on two-slot multiplayer maps and the extra-human Start rule remain unchanged.

## Validation and deployment

- Native build: zero warnings/errors with /W4 /WX.
- 272 patch-writer checks, 88 platform checks, 18 connection-state checks,
  38 network-guard checks and 14 CPU checks pass. The platform harness initially
  rejected a relative fixture path; its required absolute path passed.
- 20 original CALL/pointer guards plus the full development instruction match
  the fingerprinted original executable. All three modified Lua files parse;
  all 284 archive entries verify.
- Ten installer tests pass. The preparation package retains LAN host/join=false.
- Deployed under the test bundle lock after the user closed S7, with old adapter,
  archive and manifest in LocalData/Before-content-cpu. No-game preflight passes.
- The user restarted the test copy and confirmed campaign missions selectable.
  Host inspection verified that exact test executable, PID 60344, with process
  affinity 0x55 on Ryzen 7 9800X3D: logical CPUs 0,2,4,6. Native startup and local
  connection completed. This is not a performance benchmark or a LAN test.

Adapter SHA256: `17d86b1ebfe670a838ff89dbdddd8e477ef1abc128001eb301268930c9c3ed09`.
Interface SHA256: `ebee0ff593cdb9c38442d03875041f8c1825c0fc3e2414291098e08f3517ced5`.

Playable LAN, remote host/join and simulation synchronization remain separate
outstanding requirements; see DEVELOPMENT-HANDOFF.md and TWO-PC-DELIVERY.md.
