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

**Baseline trigger blocker:** `C90230` gates login on the platform wrapper's
SDK session readiness (`EF3EC0` via vtable `1140D90+54`). Its caller `C8EBE0`
has another readiness gate. The reconnect call at `C958CF` also reaches
`C90230`. The three baseline hooks alone do not make offline startup reach
RendezVous login.

### Opt-in local connection experiment

The launcher flag `--local-connect-probe` adds `connect_probe=1` to the bounded
runtime configuration. The normal launcher leaves this experiment disabled.
Four guarded calls to the outer request operation (`C92127`, `C93A31`,
`C9511A`, `C956F5`) and the reconnect call (`C958CF`) then use local connection
operations. A guarded, ASLR-aware update vtable slot at `1091B08` retains the
original `C956C0` update first and requests the initial local connection when
the real native objects exist.

These operations set requested/pending state before dispatching the original
`D49B80` login action, which owns the real CallContext and callbacks. They do
not set the connected flag or report a successful Ubisoft SDK session.
Requested/pending state prevents duplicate jobs. All nine original call/table
guards are checked before any writes. Pointer-slot writes preserve adjacent
bytes and restore page protection; rollback uses the rebased original pointer.

Synthetic validation passes 18 state-policy checks and 73 checks of the actual
patch writer, including guard rejection before mutation, pointer relocation,
protection restoration and rollback. All nine guards also match the original
on-disk executable. Configuration/public-key validation and bundle preflight
pass with the flag enabled. In the first opt-in game run, the user reached the
main menu and the launcher recorded exit code 0. The adapter logged opt-in
bootstrap installation and facade construction, but no local login entry or
client UDP reached the service. Connection remains unverified. A subsequent
diagnostic build adds once-only fixed labels for update entry/return and each
readiness blocker, plus the fixed bootstrap error before a fatal exit.

The diagnostic game run reached the main menu with the correct separate-copy
EXE and adapter loaded. In each of two ten-second observation windows,
`UPLAY_Update` ran 160 times (caller `4C81C7`), while the hooked update, original
`C956C0`, and RendezVous `C95840` updates ran zero times. The replacement
vtable slot pointed into our adapter. The real owner and embedded RendezVous
objects had their expected vtables; requested, connected and pending were all
false, and the facade existed. Thus the opt-in update hook itself was never
reached. Fixed call counts, module-relative callsite metadata and type/state
booleans established this without reading account strings or network payloads.

The next experimental build adds a bridge from the local `UPLAY_Update` to
the existing native owner update. Static constructor code at `ED5B6F/ED5BA5`
establishes ownership through the network singleton at `1379E14`, field
`+A18`. The bridge re-reads that ownership each tick, validates both vtables,
waits for the facade and update dependencies, and only executes on the bootstrap
thread. It rejects reentrancy and stops bridging once the normal update path
is observed. The platform lock is released before calling game code, permitting
callbacks to re-enter the platform safely. Ten added synthetic checks exercise
disabled/foreign-thread/recursive/natural-update paths and partial construction;
two added platform checks cover startup gating and callback lock release.
The subsequent separate-copy game run verified the bridge: native diagnostics
recorded update entry/return, dispatch and login entry. The local server received
SYN, CONNECT, Login and Register, sent both encrypted RPC responses, and received
both DATA ACKs. A bounded inspection then confirmed requested=true,
connected=true and pending=false on the expected native object. Over ten seconds,
platform, bridge, original owner and RendezVous updates each ran 160 times.
The user confirmed that the game remained in the main menu. This establishes
the initial local Login/Register exchange and native connected state; it does
not establish persistence beyond the current probe lifetime or playable modes.
These checks do not establish login, sustained service or LAN functionality.

### Local game/menu readiness experiment

After the keepalive run, the user still found the multiplayer entry missing or
disabled. Bounded live observation confirmed the distinction: the RendezVous
object was connected and updating, but the game-level getter `ED7230` returned
false. Its implementation delegates to the Ubisoft session wrapper at `+A50`,
whose `+54` virtual method is `EF3EC0`.

The next opt-in build replaces the five verified calls to `ED7230` at
`ED2CAE`, `ED62FC`, `ED651D`, `ED672C` and `ED6C2B`. The replacement checks that
the caller is the current network singleton, that the owner/RendezVous vtables
match, that the facade is local (null borrowed Ubi), and that its actual native
connected bit is set while pending is clear. Disabled, initializing,
disconnected, pending and mismatched-object cases return false. It does not
change the SDK session predicate or synthesize NAT/session-creation success.

The expanded patch/readiness suite passes 112 checks; all 14 selected native
guards match the fingerprinted original executable. Together with the 88
platform and 18 state checks, 218 native checks pass. Configuration/public-key
validation also passes. The subsequent separate-copy run logged the transition
from not-ready to locally connected, completed Login/Register with both ACKs,
and continued answering PINGs. The user confirmed that the multiplayer entry
became selectable. This verifies menu readiness, not a working lobby or match.

### Local master/core update experiment

The user subsequently opened an empty session list. Bounded observation found
online discovery reaching `ED6C00`, but its native `ED7270` readiness check
returned false before sending a search RPC. The owner had no core attachment
at `+0x1C`, its `+0x3A` network-ready byte was clear, and no network-result
callback (`C92600`) arrived. The existing bridge delivered owner updates,
but both `ED7950` and the core update `CBC710` had zero observed calls.

The expanded opt-in bridge preserves the relevant native ordering from
`ED7950`: master dispatch `ED3BA0`, then core update `CBC710` with phase 3.
Core, implementation and master types must match the fingerprinted executable,
the master must reference that same core, and its scheduler must exist. The
borrowed-Ubi facade must remain null. Ownership is rechecked after callbacks.
If the core already invokes the patched owner update, the fallback is skipped;
otherwise the existing owner update continues. Thread/reentrancy guards and
cessation when natural updates resume remain in place. No readiness byte or
completed network event is fabricated. The loopback guard remains active.

Synthetic x86 trampoline tests exercise the actual bridge with owned objects:
call order, calling conventions, recursive entry, suppression of duplicate
owner updates, incomplete initialization, and network/owner/core removal in
callbacks. The user-started game reached the session list. A 20-second observer
counted 636 core updates and 318 owner updates, with local Login/Register and
keepalives intact. The core returned success, but master startup, child
attachment and network readiness remained absent. This establishes functioning
core dispatch only, not discovery, hosting, joining or a working match.

Validation: 147 bootstrap/bridge checks, 88 platform checks, 18 connection-state
checks, 38 network-guard checks, 14 original-byte guards and the real local
configuration/fingerprint rejection test pass. No game is launched by these tests.

## Local network startup policy

A live read-only observation identified the startup gate: `ED480A` invokes the
platform offline predicate through vtable offset `+0x28`; `ED4815` stores its
result at `Network + 0xA71`. The true offline policy skips the entire original
Startup ECHO job. The command queue is initialized but empty; master children
exist but the three game components are unattached.

The opt-in table now guards and replaces the full five-byte indirect-call
sequence at `ED480A`. Its replacement only allows native network startup on the
bootstrap thread with the initialized probe and exact known platform object.
Unknown objects, another thread or disabled/uninitialized probes skip startup.
It leaves `UPLAY_USER_IsInOfflineMode`, the platform offline byte and all genuine
network readiness flags unchanged. The native startup job and its callbacks
must still succeed; no success response is fabricated. The original shutdown
path sees the same stored network policy. Baseline mode does not install this
hook. All network operations remain subject to the loopback guard.

Validation: 161 bootstrap checks, 88 platform checks, 18 connection-state checks,
38 network-guard checks, 15 original-byte comparisons and real configuration
validation pass. A user-started run confirmed native master startup success,
owner attachment, interface presence, 2,886 queue ticks and 5,812 core ticks in
three minutes. Local Login/Register remains connected. Native network readiness
is still false and no search RPC has been observed.

## Local session-search eligibility and sandbox configuration

The local probe replaces only the readiness call at `ED6C3A` inside session
search. Its policy requires the actual connected local facade (no pending login),
the current guarded owner/core, bootstrap thread, configured service port,
completed master start, owner attachment, interface presence, a successful
network result and no optional owner `+0x249` dependency. Pending/error results,
disconnects and incomplete/replaced objects remain ineligible. No native NAT
flag is changed, and other readiness callers, hosting and joining are untouched.
This permits an experimental request to the loopback service; it does not
establish a successful server response or playable multiplayer. The underlying
native readiness failure remains unresolved.

The first live search passed this gate and entered `C8DCA0`, then crashed at
`AB0E30` with access violation `0xC0000005`. Static verification traces this
to `D43F50`: it reads `matchmakingSandboxName` from the deliberately null
borrowed Ubi facade at `RV+54 -> facade+0C`. No search RPC reached the service.

The correction replaces only `C8DCC5 -> D43F50`, returning the same empty
sandbox used by the local direct-mode login. The original caller supplies a
fresh 24-byte small-string result, receives its pointer in EAX and expects
callee cleanup of four stack bytes. The replacement initializes inline data,
length 0 and capacity 15, requiring no foreign allocator or destructor. The
caller retains its original copy/destruction lifecycle. Current ownership,
thread, probe and actual local readiness are checked before constructing the
result. Search additionally requires its helper at owner `+108` to exist.
Other Ubi configuration readers are unchanged and may need separate work.

Validation: 211 bootstrap checks (including repeated native calling-convention
tests, buffer canaries, missing helper and rejected-context preservation), 88
platform, 18 connection-state, 38 network-guard checks, 17 byte comparisons and
the real configuration test pass. The correction is deployed with backup and
passing no-game-launch preflight. The user's next run opened the session list
and repeated native search dispatch passed this formerly crashing call.

The following blocker was the empty SpaceId string at search helper `+0x10`
(length `+0x20`, capacity `+0x24`). The established local connection already
holds its public SpaceId as a qString at backend `+0xE4`. The search gate now
uses `EnsureLocalSearchSpace` to validate ownership, type and a bounded printable
namespace, then invokes the game's `D4A860` setter with a borrowed 24-byte
small-string view. The setter copies with the game's allocator and updates
its dependent session name. The view is never destroyed by the adapter.
Existing nonempty namespaces must match; post-call ownership and content are
revalidated. No credentials or raw identifiers are logged.

This candidate passes 229 bootstrap, 88 platform, 18 connection-state and
38 network-guard checks, 17 original-byte comparisons and real configuration
validation. It is deployed with backup and passing no-game-launch preflight;
the user's following session-list test confirmed the transfer (native helper
length 36, capacity 47, fixed ready event, actual connection still active).
Additional encrypted messages now reach the server's two-response budget
rejection. Their method and an actual search response remain unverified.

The additional Frida observer caused a separate `frida-agent.dll` fail-fast
crash (`0xC0000409`). Subsequent game restart without it succeeded. Use only
the external read-only Windows snapshot for the next test; do not inject the
retired observer again.

## Local create-request policy: deployed

After the empty search response was delivered and acknowledged repeatedly,
the user's create attempt failed before any new RPC. `ED630B` still invokes
the global readiness predicate; its underlying owner `+0x3A` remains false.
The candidate adds an exact guarded replacement of that call with
`QueryLocalSessionCreate`, requiring the existing local connected state,
owned objects, bootstrap thread, explicit probe and native SpaceId transfer.
It enables only the original asynchronous create-request path. It sets no
network readiness flags and supplies no fabricated creation result.

The candidate passes 354 adapter checks (248 bootstrap, 88 platform, 18
connection-state), 38 network checks, 18 original-byte comparisons and the
real configuration/executable-rejection test. After confirmed game shutdown,
the adapter was deployed with a retained backup, verified bundle hashes and
passing no-game-launch preflight. Live request verification is pending; the
service still needs an actual create handler.

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
the baseline two-response Login probe retains its two-minute per-peer limit.
The opt-in local-connect launcher selects the bounded keepalive experiment:
two minutes idle or twenty minutes total. See [local keepalive details](LOCAL-LOGIN-PROBE.md).
`--launch-game` is required to start the game. Without that flag it runs a
preflight and exits, which is how the prepared bundle was checked.

The supplied local start file therefore has no external restart countdown:
it prepares a new service/configuration each time the user starts it. It does
not invoke Ubisoft Connect. The user has now confirmed its visible main menu
and fast startup; source/build checks alone would not establish that outcome.

## Validation so far

- x86 builds with `/W4 /WX`, no warnings or errors.
- 88 synthetic platform/save checks; 38 host network-guard checks, including
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
server either. That baseline observation preceded the successful opt-in bridge
test described above. An earlier
reported main menu belonged to the original installation and is not counted
as evidence for this prototype.

Every game outbound path, campaign saves, sustained server
protocol, lobby/matchmaking and two-computer LAN remain unverified or missing.
