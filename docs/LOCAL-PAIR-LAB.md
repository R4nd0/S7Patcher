# Two real clients on one development PC

This is a development laboratory, not the LAN installer. It was exercised on
2026-10-26 after the user authorized local game operation without further manual
restart requests. The original installation is unchanged.

## Isolation

`tools/local-pair/lab_executable.py` derives two fixed, fully fingerprinted EXEs
from the supported original. It changes only two equal-length, NUL-guarded data
strings: the singleton mutex and the My Documents profile suffix. It does not
change executable instructions, timing or protocol code. The normal adapter
rejects both resulting hashes. The separately compiled laboratory adapter
rejects the original and every unknown hash, retaining PE, callsite, ABI and
thread checks.

Build the adapter with `native/build.ps1 -LocalPairLab`. The matched complete
EXE hash selects A = 127.0.0.2 or B = 127.0.0.3. Wildcard and explicit 127.0.0.1
binds use that slot address, as do initially unbound senders. Both games can
therefore bind their own UDP 3074, 6200 and 9103. No Windows adapter, hosts or
firewall settings are changed. The normal build has no slot-address behavior.

Build the separate service with `-p:DefineConstants=S7_LOCAL_PAIR_LAB`. Only
this build recognizes `S7_LOCAL_PAIR_ADDRESS`: a canonical private IPv4 address
actually assigned to this computer. When Storm advertises that physical address
but the registered client uses IPv4 loopback, project it to that client's
registered address, retaining the game port and descriptor. Registration/RVCID
ownership remains required. Unrelated addresses are not projected. The normal
service ignores the environment flag and keeps its original ownership policy.

Do not use laboratory binaries in production bundles or PC 2 update packages.

## Local artifacts

Under the task's `rec/work` directory:

- `pair-A` and `pair-B`: independent Base copies, not links; fresh LocalData
  identities/saves; `lab-manifest.json` checks EXE, adapter and Interface archive.
- `prepare_local_pair.py`: already-run private preparation script. It refuses
  existing target folders; do not rerun over these copies.
- `operate_local_pair.py server|A|B`: private process controller. Start server
  first, wait for its ready line, then A and B. It writes loopback runtime
  configuration, locks each slot and records its owned PID/exit status. It starts
  no Ubisoft launcher. Service lifetime is one hour; registered-peer limits
  still apply. Stop the exact owned service when finished.
- `pair-ready.json`, runtime INI files and raw logs remain private and untracked.

The fixed EXE data suffixes are `\Codex\2026-10-25\rec\work\S7LabA` and
`S7LabB`, relative to the actual Windows My Documents folder. On this machine
that folder is on Z:, not C:. Both profile directories were prepared separately;
only Options.ini was initially copied, not an existing player profile or saves.
The real games created separate Profiles.xml and replay files there.

## Observations, separate from tests

1. Two actual games authenticated concurrently. A created a public Turminsel
   lobby and B displayed it. A shared loopback address initially caused host
   descriptor ownership rejection.
2. With the laboratory descriptor projection, the real JoinSession request was
   reserved and answered. The client reported **link-reach-failed**, kind 0,
   description length 71. UI remained `Sitzungsfehler (0)`. Evidence is in the
   private `pair-shared-loopback-link-failed.jsonl` log. This narrows the failure
   to the native peer connection; it does not establish its cause on two PCs.
3. On the shared address, the guest lacked a persistent UDP 3074 listener. The
   distinct-address build subsequently authenticated both real games and OS
   inspection confirmed each had UDP 3074, 6200 and 9103 on its own address.
4. Screen capture then failed repeatedly with `FrameArrived timed out`, including
   after reselecting windows and resetting the Computer Use session. No further
   UI input was attempted without a valid observation. Both owned games and
   their service were stopped. The distinct-address join remains untested.

A short attempt using the physical LAN address triggered a Windows firewall
prompt. It was not acted upon; those owned processes were stopped and the
laboratory remained loopback-only.

The next real test is A hosting / B joining with distinct slot addresses, then
the reverse direction. Read the bounded failure classification and subsequent
RPCs, and inspect only guarded known structures if necessary. Do not guess a
success state or suppress the native failure. Membership completion, host
notification, match start and synchronization remain unverified.

## Verification

Laboratory build: 361 bootstrap checks (including both exact hashes, per-byte
digest mutation rejection and slot selection); 69 network checks, including
same-port distinct-address binding, UDP transfer and automatic source binding;
88 platform checks; 18 connection-state and 14 CPU checks. Service: 5,763 checks,
including actual-NIC projection, port preservation, both slot addresses,
idempotence, invalid/nonlocal inputs and encrypted synthetic peers.

Default build: 359 bootstrap, 61 network and 5,753 service checks independently
verify that laboratory hashes and environment flags cannot enable the laboratory
behavior. The real original also passes 13 read-only derivation/immutability
checks. These tests and the two-process
startup evidence do not establish a successful native join or desync-free play.
