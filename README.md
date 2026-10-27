# S7Patcher
A simple application for the game "The Settlers 7 - Paths to a Kingdom".
<p align="center">
	<img src="https://github.com/Eisenmonoxid/S7Patcher/blob/9ee91e1bbfae1d9420e88e9cd23f59c6088aadbe/Images/S7.jpg" width="60%" height="60%" alt="Header"/>
</p>

**Should there be any questions: [Settlers Discord Server](https://discord.gg/7SGkQtAAET).**

---
## History Edition diagnostics (this fork)

**Experimental two-PC LAN join and match start now work; this is not yet a stable replacement-server release.**

A portable **preparation installer** is now available in `tools/installer/`.
It makes a separate copy from each PC's own supported installation, includes
its runtimes, and checks game/patch/content fingerprints before local startup.
The current guarded adapter and service have completed a real two-PC join and
running match. The guest's growing command delay is corrected: its horizon
stays at five turns and the user confirms responsive commands through ten
additional minutes of play without errors. Longer stability, an earlier
connection loss and reverse real-PC hosting still need verification. See
[two-PC delivery and synchronization acceptance](docs/TWO-PC-DELIVERY.md).

The inspected Ubisoft Connect build contains a native LAN Join function that returns success without joining a peer. The experimental bridge uses the game's native session transport through its local matchmaking service instead. See [LAN research](docs/LAN-RESEARCH.md) and the [current development handoff](docs/DEVELOPMENT-HANDOFF.md).

The separate [native local-start prototype](docs/NATIVE-LOCAL-START.md) reaches the main menu using its own platform adapter, without startup videos or the intro click gate. Its opt-in local-connect test completes encrypted Login/Register and real search/create/join exchanges. Longer sessions, complete network isolation and simulation synchronization remain unqualified.

Build this fork with the .NET 10 SDK (`dotnet build -c Debug`). The original patching workflow below remains available; these explicit diagnostic commands return before that workflow starts.

```powershell
S7Patcher.exe --inspect "C:\Spiele\thesettlers7"
S7Patcher.exe --lan-experiment prepare "C:\Spiele\thesettlers7" --output "C:\S7Research\new-diagnostic"
```

- `--inspect` reads an executable or installation folder and prints JSON with SHA-256, file version and nearby network-library fingerprints. It creates no backup and changes no files. Exit codes: `0` recognized Ubisoft HE build, `1` read error, `2` invalid/missing/ambiguous input, `3` unknown executable hash. Recognition does not imply LAN compatibility.
- `--lan-experiment prepare` requires Python 3.10 or newer on PATH and the accompanying `tools/lan` files. It writes only an archive copy and `manifest.json` into a **new**, separate directory whose parent already exists. It does not install the copy or start the game. Both `Base/Bin` and `Data/Base/Bin` layouts are supported. Original EXE/archive SHA-256 and every Lua delta's source bytes and result hash must match. Existing output directories and output inside game paths, including resolved junction targets, are rejected.
- The staged menu is explicitly labelled **LAN diagnostics (not playable)** and disables LAN Join. Six Lua files contain 25 research edits; native networking code is unchanged. The archive writer appends replacements, preserves filename lookup tables, and checks all 284 archive files. Exit codes: `0` staged, `1` missing tool/interpreter, `2` invalid input or failed validation.
- The supported Ubisoft HE executable hash is `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`; the original `Interface.bba` hash is `766ae21ef06709309a68fb5bb792b0fd56373c668f02140122eef181917b0b94`. Gold, Steam HE and modified builds are not accepted for staging.

Staged archives contain your local game data and must not be distributed or committed. This repository contains source code and small byte deltas only. Remove the staging directory to discard the experiment; the preparation command never changes the installed game, `Options.ini`, accounts, firewall or hosts file.

### Local bootstrap configuration endpoint

```powershell
S7Patcher.exe --local-config-server --seconds 300
```

This separate mode serves only the bootstrap configuration at `http://127.0.0.1:9110/public/rendezvous/v1/configuration`. A successful HTTP response is **not a login or working multiplayer**. It does not patch, instrument or launch the game.

The server creates a fresh ECDSA P-256 key in memory for each run and advertises its CNG `ECS1` public blob together with one loopback PRUDP URL. Its private key is never exported or saved. The advertised UDP port is actually bound. By default, received datagrams are counted by length and receive no protocol response. Request headers, query values, UDP contents and remote endpoints are not logged. Account authentication, a complete PRUDP session and matchmaking remain unimplemented.

Add the optional boolean switch `--handshake-metadata` to passively classify structurally valid SYN/CONNECT/DATA packets. UDP events then add only `packet_type` (`syn`, `connect`, `data` or `unrecognized`) and, for recognized packets, `bytes_consumed` and `checksum_matches_zero_seed`. The latter compares the packet checksum with an **unverified zero-seed hypothesis**; even a match does not authenticate a peer or establish that the stream's actual seed is zero. Unrecognized packets omit the checksum result. Routing identifiers, signatures, cookies, keys and payloads are never logged, and the mode sends no replies. A declared packet may consume only part of a datagram; trailing bytes are not classified or included in that packet's checksum. DATA payloads remain opaque: classification does not establish encryption, successful decryption, client acceptance or a login. See the [DATA metadata findings](docs/DATA-METADATA-PROTOCOL.md).

The separate opt-in `--syn-probe` implies handshake metadata and adds a deliberately limited SYN-ACK experiment. It responds only to a loopback SYN with flags exactly `0x20` or `0x60`, stream 3, destination virtual port `0x31`, no payload or trailing frame, and a checksum matching seed zero. Its 18-byte ACK swaps virtual ports, echoes the sequence and uses a random nonzero cookie retained only in memory for up to eight senders; retries keep that sender's cookie. Reply logs contain only a fixed event, byte length and incomplete-capability flags. It never replies to CONNECT or acknowledges a login. This mode does not establish a full handshake, authentication or multiplayer, and is off by default.

The opt-in `--connect-probe` includes the SYN probe and can additionally answer an **empty-payload CONNECT** from the same endpoint and virtual port after a SYN reply. It requires the issued server cookie, flags `0xb0` or `0xf0`, a nonzero client session, a valid 72-byte ECK1 P-256 public key, full packet consumption and a checksum matching seed zero. Its 158-byte reply uses a separate ECDH key signed by the current configuration key, echoes the client's sequence and places the client's connection cookie in the reply header. Exact retries receive the same session, key and signature. Changed connection tuples, nonempty payloads, DATA and login requests receive no reply. Keys and connection state remain in memory and are disposed when the service stops. This is a transport experiment with [documented static evidence](docs/CONNECT-ACK-PROTOCOL.md), not a working authenticated session or offline multiplayer server.

`--data-ack-probe` additionally acknowledges strictly validated DATA packets from that established context, after a CONNECT ACK has actually been sent. It requires matching routing, client session, server cookie and checksum, a complete single frame, and flags exactly `0x20`, `0x30`, `0x60` or `0x70`. Its empty 15-byte ACK uses the client's cookie and unchanged server session, and echoes the current DATA sequence and part byte. Repeated requests receive the same ACK. It does not acknowledge ACKs, inspect payloads or produce application replies. See the [native DATA ACK evidence](docs/DATA-ACK-PROTOCOL.md).

In metadata-enabled modes, DATA observations also report only booleans for a known peer, successfully sent CONNECT ACK and routing/session/header-cookie matches. The cookie and session values themselves are never logged. A context match or transport ACK does not establish authentication.

The additional `--data-crypto-probe` implies the ACK experiment and checks the [derived DATA transformation](docs/DATA-CRYPTO-PROTOCOL.md) for packets passing the same narrow context gates. It derives the connection key, validates AES-CBC padding, decodes the flat/Zlib envelope with a conservative 64 KiB expansion cap, and checks the encrypted sequence copy. Only fixed outcome categories, sizes and booleans are emitted. Plaintext, IVs and keys are never logged or saved; owned temporary buffers are cleared after each check. Empty bodies are reported as bypassed, not decrypted. This mode performs no RPC parsing, reassembly or application response. The default, SYN, CONNECT and ACK-only modes do not decrypt DATA.

`--local-login-probe` additionally enables experimental [Login/Register handling](docs/LOCAL-LOGIN-PROBE.md). It assembles bounded reliable messages, validates known request structures without decoding tokens, and sends encrypted responses with temporary local identities. Those identities are not Ubisoft account identities and are discarded at shutdown. Reliable responses have finite retries; matching ACKs remove them. No lobby, matchmaking, game synchronization or fully offline bootstrap is implemented. Client acceptance of these new application responses still requires a controlled live test.

Metadata modes also passively classify complete supported PING/DISCONNECT packets. Their payloads are not interpreted and controls receive no reply; packet length alone never identifies a control type.

Both listeners bind exclusively to IPv4 loopback. HTTP defaults to port 9110; UDP defaults to a free port. Use `--http-port` or `--udp-port` to choose a port (`0` chooses a free port). `--seconds 1..86400` limits the run; without it, stop with Ctrl+C. Shutdown closes both listeners and finishes request workers before its final JSON event. Exit codes: `0` orderly stop, `1` local bind/key/I/O failure, `2` invalid arguments. No Python or external library is needed for this mode.

### Diagnostic regression checks

```powershell
python -B -m unittest discover -s tests -p test_lan_tools.py -v
dotnet run --project tests/InspectionTests -- "C:\path\to\dotnet.exe" "C:\path\to\S7Patcher\bin\Debug\net10.0\S7Patcher.dll"
dotnet run --project tests/ConfigServerTests -- "C:\path\to\dotnet.exe" "C:\path\to\S7Patcher\bin\Debug\net10.0\S7Patcher.dll"
dotnet run --project tests/PrudpDecoderTests
dotnet run --project tests/PrudpControlDecoderTests
dotnet run --project tests/ReliableMessageAssemblerTests
dotnet run --project tests/LoginRpcCodecTests
dotnet run --project tests/LoginRpcArgumentShapeTests
dotnet run --project tests/LocalLoginRpcEngineTests
```

The tests use invented archive data and temporary files. To include the known local game in read-only integration checks, set `S7_INSTALLATION` for the Python tests and append the installation folder to the C# test command. Set `S7_TEST_TEMP` to an existing writable temporary parent if your environment restricts the system temporary directory. The Windows junction test is skipped when the environment cannot create junctions. No test installs the diagnostic archive.

The config-server harness uses real loopback sockets, imports the advertised public key with Windows CNG when available, checks passive modes send no UDP answers and logs contain no test secrets, and verifies cancellation, bounded lifetimes, released ports and absence of file changes. Invented SYN/CONNECT fixtures check optional metadata and its absence by default. SYN-probe tests check exact reply fields, fixed checksum vectors, stable retry cookies, sender limits and rejected packets. CONNECT tests verify the signed ECK1 blob against the actual HTTP trust anchor using Windows CNG, exercise ECDH public-key import, preserve exact retry bytes and reject unsupported payloads, changed connection tuples and invalid curve points. The separate decoder harness checks lengths, truncated inputs, declared packet boundaries and optional checksum verification without networking. Neither harness starts a game.

The BBA format/crypto implementation follows MIT-licensed [S7Packer](https://github.com/Eisenmonoxid/S7Packer); its [license](tools/lan/LICENSE.S7Packer.txt) is included. [Lua research notes](tools/lan/research-notes.txt) describe the deltas and their limitations.

---
## Usage
1. Make sure that the game has been launched successfully `at least once` before using the S7Patcher.
2. Check that the latest official patch `1.12.1396` is installed (Not necessary when using the History Edition).
3. Download the [latest release](https://github.com/Eisenmonoxid/S7Patcher/releases/latest).
4. After downloading, simply drag&drop your game executable (Settlers7R.exe) onto the S7Patcher application **OR** start the application and input the path to the file manually.
5. When patching, the application will create a backup of the original file that can be restored at any time.

In case your History Edition is from `Steam`, the executable will have to be extracted with the tool `Steamless` before using the S7Patcher!

*Find the Settlers7R.exe here:* 
```
<Settlers7>\Data\Base\_Dbg\Bin\Release\Settlers7R.exe -> Original Release (Gold Edition)
<Settlers7>\Data\Base\Bin\Settlers7R.exe -> History Edition
```

---
## Features
### All Versions
- Enables the Development Mode (e.g. skippable intros).
- Enables setting the process affinity mask directly in the executable leading to better and smoother game performance.
### Original Release (Gold Edition)
- Unlocks all the DLC and UPlay Rewards that became unavailable when the servers got shut down. This includes the DLC maps, the DLC campaign (which can also be played in skirmish now), the "Enormous Advantage" in the ingame map editor, new prestige decoration, 3 new victory points, and (possibly) more.
- Enables all local features (like the castle forge and the profile system) that required network access.
- Fixes a few crashes that happened in offline-mode when local features were present.

---
## Development Mode Options
Using the following key combinations, you can enable/disable a few special features of the Development Mode:
- `CTRL + G`: Toggle the ingame UI.
- `CTRL + C`: Switch between the free view camera mode and the default camera mode. Control the free view camera using WASD or the arrow keys, 
the right mouse button and Q and E.
- `CTRL + SHIFT + T`: Toggle terrain rendering.
- `CTRL + SHIFT + W`: Toggle water and lava rendering.
- `CTRL + SHIFT + C`: Toggle grass and bush rendering.
- `F11`: Toggle the general development mode menu.
- `F10`: Toggle the AI menu.

<p align="center">
	<img src="https://github.com/Eisenmonoxid/S7Patcher/blob/9ee91e1bbfae1d9420e88e9cd23f59c6088aadbe/Images/F11.jpg" width="50%" height="50%" alt="F11"/>
	<img src="https://github.com/Eisenmonoxid/S7Patcher/blob/9ee91e1bbfae1d9420e88e9cd23f59c6088aadbe/Images/F10.jpg" width="50%" height="50%" alt="F10"/>
</p>

It is also possible to play the campaign and scenario maps in skirmish mode (drop-down menu in the upper left corner of the map selection screen).

---
## Recommendation
To gain better performance in the game, the S7Patcher can limit the game to your physical processors, since it does not work well with `Simultaneous Multithreading/HyperThreading`. For the best performance, choose three or four
physical cores of your CPU when patching.   
For further information on this topic, see [here](https://en.wikipedia.org/wiki/Affinity_mask) or [here](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask).

Utilizing [DXVK](https://github.com/doitsujin/dxvk/releases/latest) can also be beneficial for performance and enables you to tweak some settings in the [configuration file](https://github.com/doitsujin/dxvk/wiki/Configuration) (like enabling VSync).

---
## Command Line Arguments
Use the command line argument `-debug` when launching the Patcher to enable some additional options when patching, such as restoring the functionality
of the LUA functions `UI.WriteToLog(_string)` and `UI.WriteToConsole(_string)` (only Gold Edition, not History Editions). This can be helpful 
when working with LUA scripts.

---
## Unpacking Archive Files
The archive files `.bba` can be packed/unpacked using [the S7Packer](https://github.com/Eisenmonoxid/S7Packer). 
