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
   their service were stopped. The user subsequently authorized launching both
   copies while they perform the lobby/join clicks; this is the current workflow.
5. Distinct-address joining initially still sent game traffic to the physical
   NIC. The lab catalogue now projects a copied snapshot through the same
   registered-host route validation as JoinSession; the stored record remains
   unchanged. Both real games subsequently logged sent/received UDP 3074
   datagrams to/from the other slot. This is not proof of a completed handshake.
6. D4781C/D49B10 returns a positive native request result, but the user still
   sees Sitzungsfehler (0). The D3F928 completion and seven selected Session
   rejection branches have not been observed; neither join report RPC arrives.
7. A guarded post-core manager tick matching ED7A40/ED7A47 runs in both games,
   but did not fix joining. Vtable 10934EC+14C targets CA6380, which drains
   completed jobs and invokes callbacks. Count actual virtual updates to avoid
   duplicates and revalidate owner/core/manager after callbacks.
8. The blocking Join Session wait at ED68B9..ED68D3 calls only ED3BA0 and sleeps;
   it does not return to UPLAY_Update. A lab-only replacement at ED68C4 supplies
   the existing local pump, retaining startup/thread/ownership/reentrancy guards
   and the original master fallback. The real wait bridge ran; joining still
   failed with no completion observed.
9. Bounded external status reads found master started=1, core tick enabled=1,
   master state=1, four children and network phase policy=1 on both games.
   C97FE0 calls BAF5D0 only when the master state exceeds 1. The new lab-only
   fallback dispatches the same Echo phase 3 operation when that gate skips it;
   BAF5D0 retains its own real SDK initialization check. It changes no readiness
   flags or result. A guarded observer at C98023 prevents duplicate dispatch,
   with owner/core revalidation after callbacks. The fallback and dispatcher
   C33020 both ran, but the real join still failed.
10. Network+30 is 1, so ED3BA0 omits its CB90C0 phase 1/2 boundaries. The lab
    pump now supplies those around the master tick when the policy selects
    external boundaries and the core is enabled, with teardown checks after
    each call. Both fixed delivery labels were observed. Joining still failed.
11. The request result is specifically 2 (pending). Static RTTI resolves its
    B64190/1087F1C event to player::inEvent::RequestJoin, not
    session::inEvent::RequestJoin. Therefore the absence of C24050/D3F928 is
    not sufficient evidence of an unprocessed queue: those are later stages.
    The correct player handler B833E0, called at B7D92F, was observed entered
    and pending. Its Peer Conflict, Pending Request, Invalid GUID and missing
    player-data branches were not observed in that run.
12. The normal player path constructs B643C0/108737C:
    session::inEvent::RequestTicketSessionId. C0BC30 initializes it; Session
    dispatch C0E809 invokes C25610. That function looks up an existing native
    session; the failed lookup branch C256DA constructs an empty diagnostic
    before producing an asynchronous failure. The current candidate observes
    entry and this exact branch without reading the key, GUID or ticket.
    Its live test failed: guest entry and pending were observed, while the
    missing-reference branch was absent. The user's initial success selection
    was accidental and explicitly corrected; there is no successful join.
13. Followed the found-reference path into C24BC0. Nine lab-only diagnostic
    callsites now classify state/flag rejection, empty peer, transport pool,
    host insertion, existing request, ticket pool, no ready peer and host
    reference rejection. Original constructors, arguments, results and error
    slots are preserved. Callsite addresses classify empty diagnostic strings;
    no lookup keys, peer identities or ticket contents are read. Live result:
    joining still fails, with none of these rejection branches observed.
14. The next candidate observes the two onward paths at C252AC (C2BEB0,
    thiscall RET 1C) and C25277 (C0BAE0, thiscall RET 1C), plus the original
    result getter at C2C269. Opaque arguments are only forwarded. Tests verify
    stack arguments, original return values and last-error preservation. Live
    result: guest transport entered/created and link accepted, followed by
    ticket/player pending; no internal event construction was observed. The
    user still sees the session error. A positive link result only establishes
    that initial transport request, not a completed connection or join.
15. Static RTTI identifies C0BAE0's event as ReceiveTicketRequest. Added fixed
    observations for the C0E961 -> C22790 event handler, C22819 -> C223F0 wire
    handler and C22611 -> C15E80 application-approval dispatch. No event payload
    or identity is read; forwarding and result/error preservation are tested.
    Live: host wire receive, approval dispatch/queued and wire accepted were
    observed; guest transport creation/link acceptance and pending request were
    observed. Join still fails. This proves the request crosses to the host,
    but does not prove that the application approved it or membership completed.
16. Static dispatch follows RequestTicket through PlayerManager_Network's
    B86710 to session::outEvent::JoinRequest, then SimpleSessionHandler's
    virtual callback. The game override ED3070 rejects when its C0 full/in-game
    boolean is set, otherwise invokes original CA36C0. The new candidate
    observes B7DA97 -> B86710, B86770 -> C0A8B0 session lookup (after the native
    metadata type check), and virtual slot 1140060 -> ED3070. Only presence,
    result and the known gate boolean are classified; nothing is overridden.
    Live: player-ticket entered, metadata-qualified session found, positive
    return. The game-specific full/in-game gate was not observed; join fails.
17. B86710 routes its JoinRequest at B86886 -> CFA5E0, but ignores the returned
    result. That route can reject an invalid destination or unavailable engine
    context. The current candidate classifies its original result, without
    reading the destination or payload. CA285B -> C9A280 additionally observes
    a true original JoinRequest type match, covering base handlers as well as
    the game override. This avoids interpreting absence of the game-specific
    gate alone as absence of all application dispatch. Current candidate
    Live: host routing returns queued, but the JoinRequest type match does not
    reach the handler. Joining still fails.
18. Known-field, read-only runtime counters show the host's main queue holding
    ten events while its scheduler frame counter stays fixed; the guest frame
    counter advances and its queues are empty. The existing global
    natural_updates_seen latch disables PumpOfflineBootstrap forever after any
    owner-only C956C0 update, even when no later core dispatch occurs.
    Current lab-only candidate work/native-pair-core-resume removes that
    permanent owner-based stop condition. It observes the exact validated
    scheduler's +78 native frame counter instead, skips a fallback when real
    intervening core progress is seen, and resumes when it stops. Interrupted
    supplied ticks invalidate the snapshot. Thread, recursion, executable,
    native object, callback teardown and default-build isolation remain guarded.
    The blocking join uses the same policy. Regression tests cover queued work
    after an isolated owner tick and recovery after an external core tick.
    Live result pending; this change does not establish admission or gameplay.

Bounded external type/state inspection also found the main Echo implementation
as the scheduler's only child, initialized state 3 on both slots. Its dispatcher
is C0CD90; PlayerManager_Main dispatch is B7D570. The observed active task-loop
counts were 1 on the host and 0 on the guest. These are observations, not proof
that the guest needs a fabricated loop or readiness value. Inspect only known
typed state/counters; do not read local peer/profile identities.

Diagnostic wrappers emit only fixed port/direction/result/branch categories,
preserving original return values, arguments and error slots. They inspect no
peer/profile identifier or packet body. D49B10 is stdcall with seven stack
arguments (RET 1C); D3F928 calls the simple result getter 4DA460.

A short attempt using the physical LAN address triggered a Windows firewall
prompt. It was not acted upon; those owned processes were stopped and the
laboratory remained loopback-only.

The next real test is the ticket-rejection diagnostic with distinct addresses,
then the reverse direction after a successful join. Read fixed classifications and
subsequent RPCs. Do not guess a
success state or suppress the native failure. Membership completion, host
notification, match start and synchronization remain unverified.

## Verification

Laboratory build: 876 bootstrap checks (including both exact hashes, per-byte
digest mutation rejection, native ABI/result preservation, pump order,
duplicate suppression, reentrancy and teardown); 69 network checks, including
same-port distinct-address binding, UDP transfer and automatic source binding;
88 platform checks; 18 connection-state and 14 CPU checks. Service: 5,776 checks,
including actual-NIC projection, port preservation, both slot addresses,
idempotence, invalid/nonlocal inputs and encrypted synthetic peers.

Default build: 359 bootstrap, 61 network and 5,755 service checks independently
verify that laboratory hashes and environment flags cannot enable the laboratory
behavior. The real original also passes 13 read-only derivation/immutability
checks. These tests and the two-process
startup evidence do not establish a successful native join or desync-free play.
