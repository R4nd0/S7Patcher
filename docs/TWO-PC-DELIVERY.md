# Two-PC delivery and synchronization acceptance

User target: install the same patch package on two Windows PCs, each with its
own Ubisoft Connect History Edition installation. Either PC must be able to
create a match and the other must be able to join. Avoid synchronization faults;
do not equate a working lobby or reliable packet delivery with deterministic play.

## Current real LAN status (2026-10-27)

Both separate PCs have joined the same lobby and loaded a running match.
The corrected native adapter keeps the guest command horizon at five turns
instead of growing with every turn; the user confirms responsive commands.
The user then confirmed ten additional minutes of play with timely commands
and no errors. The host log contained no disconnect/expiry event before
intentional shutdown for the reverse-host test. An earlier peer-left/waiting-
for-player failure has no verified cause, and reverse real-PC hosting remains
untested.
Neither checksum equality nor freedom from desynchronization is established.
See DEVELOPMENT-HANDOFF.md for current builds, hashes and observations.

The complete package builder now pins the corrected adapter and the verified
catalogue-route service. Its LAN starter permits only the explicitly chosen
pair. Manifest capability flags remain conservative experimental claims,
not switches for enabling networking. Full content checks precede startup;
they are not a network admission proof or a simulation checksum.

The rebuilt v3 package passes 12 synthetic installer tests and a fresh
54-file installation using the original game as source. Only the intended
loader/menu archive differ in Base; the installed content ID matches both
updated PCs (d1db6b1a...). Bundled-runtime preflight starts no game and passes.
All 249 ZIP entries pass CRC and payload fingerprint verification. No previous
incremental update is required when installing this consolidated test package.

The sections below retain the earlier preparation milestones and original
acceptance plan; their not-yet-implemented statements describe that stage.

## Initial delivery implementation

`tools/installer/build_package.py` builds an offline preparation package from
the tested adapter, service, existing archive byte-deltas, pinned CPython
embeddable runtime and .NET runtime. It includes runtime licenses. It never
packages Settlers7R.exe, Interface.bba, other game files or LocalData. The
CPython 3.14.10 archive is pinned to the published SHA-256 at
https://www.python.org/downloads/release/python-31410/ .

`Installieren.cmd` asks for the recipient's game installation and a new output
folder. `install.py` checks payload hashes, supported original EXE/archive,
available disk space and disjoint paths, rejects links/junctions, and copies
the game into an independent Base layout. Base and Data/Base source layouts
are supported. Original files remain untouched; no hard links are used.
Only the new copy receives the local adapter and the verified archive patch.
Runtime/service/launcher copies are checked before publishing starters.
Failures retain an incomplete marker and the launcher refuses that marker.
Existing destinations are never overwritten; no recursive cleanup is automatic.

The resulting `Start-S7-Test.cmd` uses only bundled runtimes and relative
paths. It checks the complete Base/Server/Launcher inventory before requesting
the existing local-test start. There is no dependency on the developer's user
name, SDK path, Python installation, account or profile. Local identities are
generated separately on first start; the package contains none.

**This package is a preparation preview, not the completed LAN installer.**
Its manifest fixes `lan_host=false` and `lan_join=false`; changing those claims
is rejected. It cannot silently remove the native loopback restrictions or
enable an unimplemented join path. The ordinary service mode is selected, not
the display-only fake row. Do not tell the second-PC user to expect multiplayer
yet, and do not redistribute a resulting game copy.

## Content compatibility implemented

Validation: 10 synthetic installer tests pass (including symlink rejection).
A real installation check copied 54 game files; only the intended adapter and
UI archive differed afterward. The prepared copy's full content check and
no-game-launch local-service preflight passed with bundled runtimes. Final
package validation and ZIP CRC verification passed for 246 entries. These are
local preparation results, not tests performed on the user's second PC.

`compatibility.json` contains normalized relative names and SHA-256 hashes of
all game files under Base plus service/launcher files. Its aggregate ID is
independent of installation path, machine, account and player identity.
Validation detects changed, added and removed files, including map archives,
native libraries, adapter, executable and local-service/launcher revisions.
It excludes LocalData and external settings/saves. A copied profile is not
part of this comparison and must never be used to provision another PC.

`Dateistand-pruefen.cmd` validates the installed inventory. To compare two
validated installations, run the bundled Python with
`Launcher/compatibility.py --bundle <copy> --compare <other compatibility.json>`.
A remote report alone is not trusted evidence of that PC's current disk state;
that PC must also run local validation. This comparison is not yet wired into
network admission because real join is not implemented.

Matching bytes eliminate one source of incompatibility. They do not establish
equal simulation state, settings, RNG stream, input order or deterministic
execution. No desync-free claim is made by the fingerprint or service tests.

## Required next milestones

1. Real search-result consumption. The display probe was delivered and ACKed,
   but the user's session list stayed empty. Investigate client deserialization,
   descriptor/filter callback and UI consumption. Do not bypass filtering in a
   production catalogue based on the display probe's test-only policy.
2. Implement and test GetSession and join/member state transitions, real host
   routing and session notifications. Ownership is the registered transport,
   not a claimed GUID from metadata. Repeated requests must remain idempotent.
3. Deliberate LAN transport: shared coordinator endpoint and namespace,
   per-PC identity, explicit private-network scope, selected game routes and
   both adapter/server policies. Distinguish coordinator location from match
   ownership: either participant can create a match even with one coordinator.
   Do not advertise public endpoints or silently open broad firewall access.
4. Enforce compatible build/content and game settings before admitting players
   and starting the match. Incompatible clients receive an actionable mismatch
   result. Never satisfy the human-player requirement by fabricating a peer.
5. Exercise real matches in both directions: A hosts/B joins, then B hosts/A
   joins. Validate selected map/settings/player slots, readiness, load completion
   and actual input exchange before marking any LAN capability verified.

## Synchronization release gates

Keep these as **unrun acceptance tests**, not existing test results:

- Both host directions on multiple maps, with and without AI, for at least
  60 minutes each. Include simultaneous building, combat, trading, pause/resume
  and supported speed changes; collect durations and exact build/content IDs.
- Find and validate the native simulation checksum/turn diagnostics before
  claiming equal state. Compare at the same simulation turn, not wall-clock
  time. Transport ACKs, visually similar screens and lack of a disconnect are
  insufficient. Do not disable the game's desync detection to pass a test.
- Controlled latency, packet loss, duplicate and reordered delivery with a
  reproducible seed. Verify commands are neither lost nor executed twice and
  clients do not advance beyond required synchronized input. Start with local
  transport simulations, then a deliberate test network; never alter the user's
  general network settings as an incidental test.
- Leave/recreate, client disconnect, host disappearance and repeated joins;
  define supported recovery honestly. No silent reconnect that resets identity
  or rejoins an incompatible state. Save/resume only after separately verified.
- On first differing checksum, retain bounded local diagnostic metadata needed
  to reproduce the earliest differing turn, not credentials or unrestricted
  packet dumps. Treat simulation divergence separately from service timeout.

Only after these gates should the preview become a LAN release. Any remaining
engine defect needs a reproducible cause and a focused fix. A replacement
matchmaking service alone cannot guarantee that an unchanged engine is free
of synchronization bugs.
