# S7 History Edition: UbiServices prerequisites for local bootstrap

Read-only static investigation, 2026-10-25. No process attachment, game changes,
account files, cache files, credential values, or network bodies were inspected.

Target: `Settlers7R.exe`, PE32 x86,
version 1.12.1395, size 17,333,680 bytes, preferred image base 0x400000.
SHA256: `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`.
Addresses below are preferred-image virtual addresses, not file offsets.
Disassembly reproduced with local `decode_x86.py`, pefile 2024.8.26 and
Capstone 5.0.9. Function names are attributed only where embedded diagnostic
strings support them; field names otherwise describe observed use.

## Result

The existing localhost sandbox branch changes the RendezVous configuration
destination. It does not supply an offline identity, create a UbiServices
session, or remove the HTTP engine dependency. In the normal game login path,
the RendezVous token is copied from the UbiServices session's `ticket` field.
The client checks UbiServices session readiness and expiration before it starts
the RendezVous login job. A local configuration service alone therefore cannot
establish a fully offline bootstrap.

This identifies interfaces to reproduce; it is not a recommendation to force a
boolean or fabricate a pointer. The public authentication protocol and complete
SDK post-login contract are not fully recovered by this bounded investigation.

## 1. Normal caller and readiness checks

- Game method at D49B80 (pointer in vtable at 109CB40) constructs sandbox and
  space wrappers and calls E43C90 at D49CFD. It passes an empty explicit token.
  No dynamic value was read.
- E43C90 wraps E43810 (call E43CF3) and has `ret 0x14`.
- E43810 stores/uses the UbiServices facade at owner+0x0c, an existing login job
  at owner+0x10, and the RendezVous engine at owner+0x20. Existing job state
  other than 5 is rejected with the embedded `Login already in progress.`
  diagnostic.
- E438DF..E43907 calls AAF7B0 -> ABD920 -> AC4B30 to inspect current SessionInfo.
  On a false result, error 4 is propagated via E58DB0/E5FB70 and the diagnostic
  says UbiServices login must finish before RendezVous login (E439B7/E43A8B).
- AC4B30 reads the session payload through wrapper+8, requires bytes +0x71 and
  +0x72 to be nonzero, then calls AD0940. Follow-up analysis below identifies
  these as application-parameter and space-parameter completion flags; they
  must not be casually named `loggedIn`/`online` or treated as sufficient alone.
- AD0940 requires the string object at payload+0x14 to have nonzero length
  (holder+0x18). It obtains a clock value through AC0800, divides by 1,000,000
  using A23BC0, and compares with the 64-bit deadline at payload+0x50/+0x54.
  A nonempty token alone does not satisfy this predicate.

## 2. Token source and propagation

When the explicit token is empty, E43AFD..E43B23 obtains the same SessionInfo
through AAF7B0 and ABD920, then AC0790 -> AC1530 -> E599D0 copies its ticket:

- AC0790 returns `[[wrapper+8]+0x14]` as a string wrapper location.
- AC1530 resolves the ref-counted string holder and its small-string storage;
  the 0x10 threshold confirms string representation, not an arbitrary handle.
- The SessionInfo parser AA71E0 maps JSON field `ticket` to payload+0x14
  (AA75E1 plus descriptor AA7671), independently identifying the source.
- E43B34..E43B6C allocates a 0x140-byte JobFacadeLogin via E44170. Constructor
  E44213..E44220 copies this token to job+0x130. Other relevant fields are
  owner+0x128, address+0x12c, port+0x134, Ubi facade+0x138, sandbox+0x13c.
- E43B8C..E43B92 fills job+0x138 with the UbiServices facade; E63740 queues it.
- E44170 schedules `JobFacadeLogin::ProcessRVLogin` at E44B60 via E65D90.
  E442B2 logs that UbiServices is authenticated and RendezVous login is next.
- E44BD2 calls E8AAD0 with the copied token, backend address/port, sandbox,
  UbiServices facade and direct configuration URL wrapper.
- E8AAD0 rejects an empty token at E8AB37..E8AB54. E8ABA6 invokes E8A2A0.
- E8A6CE passes that token to constructor E8C670, which copies it to the
  backend job's +0x15c at E8C705..E8C712. E90420 sets its facade at +0x274.
- E905B0 checks token length again at E90629..E90637. Empty yields Core error
  10 and diagnostic `Empty token; necessary for authentication with Rendez-Vous.`
  (E9068A). This check also applies to the localhost configuration mode.

## 3. Session creation result and parsing boundary

- The URL builder at AC8B43..AC8B89 combines the SDK UbiServices base URL with
  `/profiles/sessions` (literal at 108170C). This is separate from the
  RendezVous localhost sandbox configuration endpoint.
- A9C34B labels `JobGetSessionInfo::reportOutcome`; it installs B12E40 as the
  callback at A9C352 via B56700.
- B12E40 checks asynchronous result state 2 (B12E5F..B12E69) and a 2xx HTTP
  status (B12F1E..B12F33). Body processing uses AAFE10 and A4D6B0.
- B13050 constructs a 0x78-byte SessionInfo payload via A46760;
  B13082 calls AA71E0 to parse it. On parser failure, B134CC follows a failure
  path with a diagnostic mentioning the profile/sessions response JSON.
- B1341A..B13450 stores the parsed session into the job result object, then
  B13474 calls B208B0. B208B0 validates success error code 0, writes completion
  through virtual accessor +0x10 -> B346A0, then sets job state 4 via B33730
  at B2097D..B20981. Thus an asynchronous result lifecycle is part of the
  contract, not only a JSON blob.

AA71E0 builds fourteen string descriptors at AA75CF..AA779A and invokes the
generic parser A68BD0 at AA77BF. Descriptor flag 2 contributes to the parser's
required-field bitset (A68F42); flag 1 does not. The parser checks remaining
bits at A69827. The table is:

| Field | Descriptor flag | Destination / observation |
| --- | --- | --- |
| platformType | 1 | payload+0x58 |
| ticket | 2 | payload+0x14; later feeds RendezVous token |
| profileId | 2 | GUID parsing/validation; invalid GUID diagnostic AA79AE |
| userId | 1 | GUID validated when supplied; diagnostic AA7C30 |
| nameOnPlatform | 1 | payload+0x2c |
| environment | 2 | converted after parsing |
| expiration | 2 | participates in local expiration deadline |
| spaceId | 2 | GUID validation; diagnostic AA7E41 |
| clientIp | 1 | payload+0x40 |
| clientIpCountry | 2 | payload+0x48 |
| serverTime | 1 | used with expiration |
| sessionId | 1 | temporary string wrapper |
| rememberMeTicket | 1 | payload+0x60 |
| sessionKey | 1 | payload+0x68 |

The descriptor requirement is a parsing contract, not evidence that every
optional field is dispensable during all later game operations. AA8169..AA81DB
parses/compares times. On invalid time data a diagnostic at AA82A2 states the
expiration defaults to three hours. AA8329..AA834D computes and stores the
local deadline at payload+0x50/+0x54. No attempt was made to exploit that fallback.

Upstream SDK code contains separate create-session, access-token acquisition,
post-login configuration and event-session jobs. The exact game's chosen
platform-credential source is still unresolved. The follow-up below identifies
the SessionInfo+0x71/+0x72 setters. The embedded callback above is a concrete
session-REST completion boundary, not proof that it alone finishes all SDK
initialization.

## 4. HTTP engine must remain valid

- E8A831..E8A880 refuses HTTP sandbox configuration without a UbiServices
  facade. E8FC99 checks backend+0x274 again; E8FCB8 says the facade is mandatory
  for obtaining the HTTP client and E8FD04 asserts `m_pFacade != NULL`.
- E8FD69..E8FDB4 obtains an application ID from a configured override, otherwise
  from the facade through AB0E30 -> 4D6740 -> 4C4460. No actual application ID
  value was inspected during this task.
- E8FF5C..E8FF7B adds the literal Ubi-AppId header; the request object is built
  via A45200. E8FFB9 calls AB3850, then E8FFC0 B295A0; the asynchronous request
  result is retained at backend+0x290 via 6A61F0.
- AB3850 dereferences facade internals and calls A37A10, which requires its
  internal valid flag (+0x60) to be 1. A non-null fabricated facade pointer is
  therefore not an appropriate replacement interface.
- E90005..E90020 schedules `WaitingForSandboxConfig` at E90910. This state
  expects asynchronous completion, HTTP status and the actual schema parsed
  by the existing native code. The separate config-schema research covers it.

## 5. Downstream game completion boundary

E44C30 (`JobFacadeLogin::WaitForLogin`) waits while context state +0x84 is 1,
then reads its outcome through D43DC0 -> E59230. Success at E44DB0 schedules
E44460 (`CallOnConnectForClients`). That traverses registered clients and calls
their vtable+8 at E444C3 with a context and facade wrapper. E44596 logs completed
RendezVous facade login. E44632..E4464A propagates the final result through job
vtable+0x34. Setting owner+0x24 to 1, which happens earlier in E44170, is not
equivalent to completing these callbacks.

## Minimal interfaces a real offline adapter would need

These are engineering inferences from the verified contracts above:

1. A local identity/session provider with owned local identities and ticket
   values, valid SessionInfo representation, deadline semantics and the SDK's
   readiness/completion contract. Do not reuse, harvest or print account tokens.
2. A usable SDK facade/HTTP engine (or an explicit adapter at its request
   boundary) with app configuration, request lifetime, cancellation, status,
   response and asynchronous completion semantics for local sandbox config.
3. RendezVous login outcome/context propagation and registered game-client
   connect callbacks, in addition to the separate PRUDP/server protocol work.

Concrete gaps before implementing a fully offline bootstrap are the actual
selected platform login input, the content contracts of application/space
parameters, and remaining post-login setup/failure contracts. The
UPLAY launcher/platform entitlement boundary was not investigated or replaced.
The existing successful route probe proves only the scoped sandbox destination
change; it cannot establish independence from Ubisoft authentication.

## Follow-up: flag setters, session installation and date/GUID contracts

Second bounded read-only block, 2026-10-25. No runtime observations.

### Flags are separate from session JSON

The setters establish the meaning through named SDK callbacks:

| Payload flag | Normal setter path | Evidence |
| --- | --- | --- |
| +0x71 | Application parameters applied | B2297F associates callback AF41B0 with `JobApplyDynamicUpdates::processParametersApplication` at B2299F. That callback requires async result state 2 at AF41D6, applies parameters with AE2840 at AF425B, then writes 1 at AF4269. |
| +0x72 | Space parameters applied | B22B28 associates AF54A0 with `JobApplyDynamicUpdates::processParametersSpace` at B22B45. AF54C8 requires async result state 2, AE3420 applies the result at AF54EE, B31360 propagates configuration at AF54F6, then AF5501 writes 1. |

Additional setters are consistent with this mapping:

- B312D0 obtains the session manager, invokes AE2840, and writes +0x71 at
  B312E9. AF47B7 and AF5077 call it from application-parameter processing.
- B31320 invokes AE3420 and B31360 and writes +0x72 at B3134B.
- B31360 copies parameters into several facade subcomponents, writes both
  flags at B314E6/B3150B, and rebuilds the published SessionInfo wrapper.
  This is more than setting readiness bits: consumers receive copied config.
- AF4A8A is the application-parameter setter in the callback following a new
  population assignment (named callback AF49D0, B22A37/B22A57).
- After application parameters, AF47CF..AF481C chooses either population
  update or `requestParametersSpace` (B22AD0). It does not finish at +0x71.

The session response itself starts with both flags zero: B13050 calls A46760,
which clears the two bytes together at A46823 before AA71E0 parses JSON.
The parser descriptors contain no fields for these flags.

The normal installation path is also explicit:

1. `JobLogin::checkUniqueProfileId` callback A84CB0 is registered at
   B23B29/B23B46. It checks the session-result async status at A84D59.
2. A84D82 validates the facade's bound profile identifier shape; A84D9E
   compares it with the returned SessionInfo profile. A mismatch follows the
   diagnostic at A84DAB requiring another facade for a different player.
   A syntactically valid unrelated profile cannot simply replace an existing
   facade's player identity.
3. A84EB3 calls SessionManager method B33450 with the new SessionInfo.
   B33470..B334C6 checks that it has valid associated PlayerCredentials. The
   embedded assertion is `sessionInfo.m_data->m_playerCredentials.isValid()`.
   These credentials are constructor input from JobGetSessionInfo+0xfc at
   B13047; they are not supplied by the JSON field table.
4. B33515..B33529 reads the OLD session's +0x71/+0x72; B33531..B3353F replaces
   its ref-counted payload; B33561/B33587 restores the old flags into the NEW
   payload. Thus JSON installation preserves parameter readiness rather than
   independently granting it.
5. A85444..A8545E schedules `JobLogin::applyDynamicUpdates` at A77B80, which
   then registers `JobLogin::processPostLogin` AF6E50 at A77C20/A77C40 while
   launching the dynamic-update subtask.

Default empty SessionInfo construction also uses false/false: A46DF9..A46DFF
and A51180..A51186 call A46830 with 0,0. A46830 is a constructor accepting
two booleans, not evidence of an existing offline-login option. Session
invalidation B24220 preserves previous parameter flags when constructing an
empty replacement at B24283; flags alone therefore explicitly do not mean an
authenticated session.

### Post-login continues beyond parameter completion

- AF6E50 waits for the dynamic-update result (state 2 at AF6EF9).
- AF6F09..AF6F1A reads feature switches. One path invalidates the session and
  logs `FeatureSwitch CreateSession was disabled. Session invalidated`
  (AF7035); it is not a successful offline-login path.
- The successful path additionally checks session-result state at AF7249,
  starts the post-login subtask, and registers final outcome handling at
  AF740F..AF7423. The diagnostic at AF7329 explicitly describes mandatory
  operations to finish session creation.
- JobPostLogin constructor A49630 names `initiateConnection` and binds it to
  AC81C0 (A4963C/A4965B). AC84C9 invokes B24710; AC84E5 AD5780; AC84F7 AD0CA0.
  It then schedules B3AC60 as `startEventsSession` (AC8536/AC8558).
- SDK post-login/event/websocket paths are therefore present after session
  parsing. This analysis has not established which feature switches make each
  operation mandatory for this game's selected configuration. Do not claim
  that every generic SDK event endpoint must be emulated, nor that all can be
  ignored.

Conclusion: local `/profiles/sessions` JSON can enter the normal parsing and
installation path only with valid surrounding job/PlayerCredentials state and
consistent identity. It does not itself set the two parameter flags. A normal
local bootstrap would also need compatible application/space parameter
responses or an explicit SDK adapter preserving their data/completion effects,
then the configured post-login outcomes. No such adapter was implemented here.

### Expiration format

AA7F46 calls AE0A90 for `expiration`; AA7F7E uses the same parser for nonempty
`serverTime`. The diagnostic AE0C77 identifies the input as ISO 8601.

The recovered parser is a fixed-position parser, not a demonstrated complete
ISO-8601 implementation:

- AE0AD4..AE0AE4 admits strings of exactly 10 characters or at least 19.
- It extracts the year from the first four characters (AE0E05..AE0E19),
  month from positions 5..6, day from 8..9; all converted with `atoi`.
- For length >=19, it extracts hour at positions 11..12 (AE1045..AE1060),
  minute at 14..15 (AE1088..AE10A3), second at 17..18 (AE10CB..AE10E6).
- AD0280 validates month 1..12, day 1..31, hour <=23 and minute/second <=59.
  The inspected check does not validate month-specific day counts.
- The conventional `YYYY-MM-DDTHH:mm:ssZ` representation fits these positions;
  acceptance was inferred statically, not tested by injecting JSON. Do not
  infer timezone-offset or fractional-second semantics from the ISO label.
- AA8194 compares the parsed times, AB5090 converts both, and AA81BE..AA81D0
  computes expiration minus server time. AA8329..AA834D adds that delta to the
  local clock. Fallback delta AA81DF is 0xA4CB80 = 10,800,000 (three hours in
  milliseconds), agreeing with the embedded fallback diagnostic.

### profileId / spaceId shape

Both use AD02B0 as their GUID-shape predicate before storage (profile at
AA77EE, space at AA7D21). AD02D1 requires exactly 36 characters. AD05FD,
AD0603, AD0609 and AD060F require hyphens at offsets 8,13,18,23. AD0615..AD062B
rejects the all-zero GUID through static pointer 12FE930 -> 107330C.
The function has no observed hexadecimal-character or UUID-version validation;
describe these fields as nonzero GUID-shaped strings, rather than claiming
complete RFC UUID validation. Later identity consistency checks still apply.
