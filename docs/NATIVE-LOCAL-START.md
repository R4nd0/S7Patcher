# Experimental native local start, 2026-10-26

This is an incomplete separate-copy prototype for the fingerprinted History
Edition. The separate copy now reaches the main menu directly, without startup
videos or the intro click gate, using the local platform adapter. Do not replace an
installed game's loader with it or describe it as a finished offline/LAN patch.
The original installation used for development remains unchanged.

## Components and boundaries

`native/local_platform.cpp` implements the verified x86 startup, offline
identity, event polling and bounded save interfaces. Online presence is
explicitly unavailable: the verified two-argument cdecl call at
`4D2F7F` ignores its result, so no argument strings need inspection and no
presence data is sent. Its module definition
exports all 84 names imported by this HE executable. Unsupported interfaces
log their fixed export name and terminate with `0xE0537001`; they never return
guessed success values. It loads no Ubisoft SDK or launcher DLL. Actual loader
dependencies of the built adapter are Windows WS2_32, WinHTTP, BCrypt,
Crypt32 and Kernel32; the C++ runtime is linked statically.

The stable platform UUID, `LocalPlayer` display name and explicit
`local-s7:<uuid>` ticket are created under the bundle's `LocalData`. They are
independent local values, not Ubisoft account identities or credentials. The
server's current Login probe still allocates a separate per-peer random
ProfileID; persistent server-side identity/progression is not implemented.

Local platform saves use `LocalData/saves/<numeric-slot>.s7local`, an owned
versioned format, atomic replacement, bounded buffers and separately tracked
opaque completions. Only one complete Write per write handle is supported;
repeated-write SDK semantics remain unproved. Existing game-internal settings
and profile paths outside the installation are **not yet fully isolated**.

`native/network_guard.cpp` rewrites the main executable's and already-loaded
`vBase90.dll`'s known Winsock, WinHTTP and ShellExecute imports. It restricts
these calls to loopback, turns wildcard binds into local binds, prevents
external DNS/HTTP, forces no proxy/no redirects, and rejects unwrapped socket
extension pointers. Both named and ordinal imports are handled: the Windows
loader can present legacy Winsock entries as ordinals even when the on-disk
imports were named. Synthetic TCP/UDP traffic verified this distinction.

This is a bounded import guard, **not proof that every possible network path
in the whole game is covered**. Later-loaded modules, dynamically resolved
functions, initialization before UPLAY_Start and the real game's behavior
still need validation. It changes no system hosts/firewall settings. The
current loopback-only policy intentionally does not yet permit a second LAN
computer. A failed patch rolls back completed exchanges; uncertain protection
restoration/rollback terminates with `0xE0537003`.

## Native RendezVous bootstrap

The constructor at `E43550` accepts a nullable borrowed Ubi facade. Guarded
relative CALL replacements at `D3C62D` and `D4A083` invoke that real constructor
with null. The replacement at `D49CFD` preserves the real CallContext and
space identifier, installs the local public ECS1 key using native functions
`E82240/E770E0/E8AE20/E77190`, and calls native Login `E43810` with an empty
sandbox, explicit local ticket and loopback UDP endpoint. That selects the
existing direct mode0 transport path. Native qString allocation, destruction
and by-value ownership transfer are preserved. Signature verification remains
active; no private key is persisted or supplied to the game.

Before installing any of these three calls, the adapter checks PE32 machine,
image size `0x10e7000`, timestamp `0x5d1b15c1`, complete original executable
SHA-256 and all original callsite bytes. Native operations execute only when
the original game thread invokes the hooks, never from DllMain. Bootstrap
integrity/reentrancy failures use `0xE0537002`.

**Remaining trigger blocker:** `C90230` gates login on the platform wrapper's
SDK session readiness (`EF3EC0` via vtable `1140D90+54`). Its caller `C8EBE0`
has another readiness gate. The reconnect call at `C958CF` also reaches
`C90230`. These gates have not been forced true or replaced: the three hooks
alone do not establish that offline startup reaches RendezVous login. A local
connect operation must preserve pending/connected state and real asynchronous
callbacks. Merely fabricating SDK-ready status would not establish that.

## Fast menu startup

`tools/offline-ui/prepare.py` applies seven fingerprinted raw-Lua deltas to
`mainMenu.lua`, retaining its original constant-table header. Both movie
dispatches and the timed menu flight/click blocker are skipped. First-start
profile synchronization and the missing-profile check remain; creating a
missing profile can still require interaction. Main-menu store/FB promotions
and Uplay visibility are suppressed; both external shop callbacks are empty.
Other screens, owned content, rewards and credits are not rewritten.

All 284 archive entries are read back and compared against their expected
contents. The output is a new staging directory, never an installation edit.

## Building and preparing a test

Requires Windows with Visual Studio C++ x86/x64 Build Tools and a Windows SDK:

```powershell
./native/build.ps1 -OutputDirectory C:/path/to/new-build
python ./tools/offline-ui/prepare.py C:/path/to/original-game --output C:/path/to/new-ui-stage
```

Use a separate complete copy of the game, retaining the original EXE. Copy
the built loader into its `Base/Bin`, and the staged UI archive into its
`Base/BBA`. The local bundle manifest contains exactly those three file
fingerprints. Game archives, executables, local IDs and run logs are not source
artifacts and must not be committed or distributed with this repository.

`tools/offline-ui/launch_local.py` validates the bundle and starts only its own
local service child. It reads the public configuration through a direct
loopback HTTP connection, writes a fresh bounded configuration, and cleans it
up with its service child on exit. The native configuration reader rejects
files older than five minutes. The service uses a one-hour overall cap, while
the current two-response Login probe retains its two-minute per-peer limit.
`--launch-game` is required to start the game. Without that flag it runs a
preflight and exits, which is how the prepared bundle was checked.

The supplied local start file therefore has no external restart countdown:
it prepares a new service/configuration each time the user starts it. It does
not invoke Ubisoft Connect. The user has now confirmed its visible main menu
and fast startup; source/build checks alone would not establish that outcome.

## Validation so far

- x86 builds with `/W4 /WX`, no warnings or errors.
- 86 synthetic platform/save checks; 38 host network-guard checks, including
  local TCP/UDP roundtrips and external-call rejection.
- Loader export set exactly equals the 84 HE imports.
- Real local service/configuration/public-key validation using a synthetic
  host; the full DLL rejects that host's incorrect executable fingerprint.
- All 284 UI archive entries verified; patched original-format Lua parses.
- Existing archive regression suite: 15 passed, one junction-dependent test
  skipped in this environment.
- Prepared bundle preflight passed without launching S7 or Ubisoft Connect.

The first user launch of the actual separate copy reached `UPLAY_Start`,
installed the guarded native bootstrap, completed local platform startup and
constructed the null-Ubi RendezVous facade. It then exited deliberately on
unsupported `UPLAY_PRESENCE_SetPresence` (`0xE0537001`). The verified offline
unavailable implementation above fixes that specific abort. The subsequent
user test reached the main menu without movies or a click gate. Host checks
confirmed both the running EXE and loaded replacement loader came from the
separate copy. The new run logged successful local startup and construction,
with no unsupported-export exit. No game-owned TCP/UDP endpoints appeared in
that snapshot, but no Login entered event or client UDP request reached our
server either. Thus the SDK readiness trigger remains a blocker. An earlier
reported main menu belonged to the original installation and is not counted
as evidence for this prototype.

Every game outbound path, campaign saves, sustained server
protocol, lobby/matchmaking and two-computer LAN remain unverified or missing.
