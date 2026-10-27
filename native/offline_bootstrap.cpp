#include "lan_address.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <intrin.h>
#include "offline_bootstrap.h"
#include "runtime_config.h"
#include "local_connect_policy.h"
#include "cpu_affinity.h"
#include "local_pair_lab.h"

// The proven native dispatch bridge can be tested against the original HE
// executable without enabling lab hashes, profiles or loopback slot addresses.
#if defined(S7_LOCAL_PAIR_LAB) && !defined(S7_LOCAL_NETWORK_PUMP)
#define S7_LOCAL_NETWORK_PUMP
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace {
constexpr uintptr_t PreferredBase = 0x400000;
constexpr DWORD ExpectedImageSize = 0x10e7000;
constexpr DWORD ExpectedTimestamp = 0x5d1b15c1;
constexpr UINT FatalExitCode = 0xE0537002u;
const unsigned char ExpectedHash[32] = {
    0x4e,0xf5,0x16,0x32,0xa8,0xa1,0x93,0x05,0x0e,0xbe,0x8e,0xf3,0xf3,0xfe,0x38,0xa9,
    0xb2,0x40,0xb4,0xaa,0x57,0xff,0x62,0xa4,0xf3,0x81,0xbc,0x0f,0x53,0x9d,0xf6,0x4f
};
enum Error : LONG {
    None, RepeatedInitialization, InvalidConfiguration, InvalidPublicKey,
    WrongExecutable, ChangedCallsite, PatchFailure, NativeNetworkUnavailable,
    NativeFacadeMismatch, NativeReentrancy, RollbackFailure, NativeGameObjectMismatch
};
volatile LONG initialization = 0;
volatile LONG error_code = None;
volatile LONG login_active = 0;
uintptr_t image_base = 0;
unsigned short udp_port = 0;
char server_address[16] = "127.0.0.1";
bool local_connect_probe = false;
DWORD bootstrap_thread = 0;
bool pump_active = false;
bool natural_updates_seen = false;
unsigned int owner_update_count = 0;
#ifdef S7_LOCAL_NETWORK_PUMP
unsigned int manager_update_count = 0;
unsigned int echo_update_count = 0;
void* lab_last_scheduler = nullptr;
unsigned int lab_last_core_frame = 0;
#endif
char public_key[97] = {};
char local_ticket[257] = {};

void SetError(Error error) { InterlockedExchange(&error_code, error); }
__declspec(noreturn) void Stop(Error error) {
    SetError(error);
    ReportLocalStatus(GetOfflineBootstrapError());
    TerminateProcess(GetCurrentProcess(), FatalExitCode);
    __fastfail(7);
}

template<typename T> T Native(uintptr_t va) {
    return reinterpret_cast<T>(image_base + va - PreferredBase);
}

// This native qString owns a char allocation whose allocator metadata starts
// four bytes before data. Never substitute a CRT pointer or CRT destructor.
struct QString { uintptr_t data; };
static_assert(sizeof(QString) == 4, "native qString is one x86 word");
using StringCtor = void* (__thiscall*)(QString*, const char*);
using StringDtor = void (__thiscall*)(QString*);
using FacadeCtor = void* (__thiscall*)(void*, void*);
using FacadeLogin = bool (__thiscall*)(void*, void*, const QString*, const QString*,
                                      unsigned int, uintptr_t, unsigned int);
using NetworkGetter = void* (__cdecl*)();
using NetworkSelectAes = void (__thiscall*)(void*);
using KeyCacheSetter = void (__cdecl*)(const QString*);
using NetworkKeySetter = void (__thiscall*)(void*, uintptr_t);
using SpaceSetter = void* (__thiscall*)(void*, const QString*);

struct OwnedString {
    QString value = {};
    explicit OwnedString(const char* text) { Native<StringCtor>(0xE59900)(&value, text); }
    ~OwnedString() { if (value.data) Native<StringDtor>(0xE59940)(&value); }
    OwnedString(const OwnedString&) = delete;
    OwnedString& operator=(const OwnedString&) = delete;
    uintptr_t Release() { uintptr_t result = value.data; value.data = 0; return result; }
};

// __fastcall supplies ECX=this and consumes dummy EDX; remaining stack layout
// and callee cleanup exactly match the replaced __thiscall CALL targets.
void* __fastcall ConstructLocalFacade(void* self, void*, void*) {
    ReportLocalStatus("local-rendezvous-facade-created");
    return Native<FacadeCtor>(0xE43550)(self, nullptr);
}

bool __fastcall LoginLocalFacade(void* self, void*, void* context,
                                const QString*, const QString*, unsigned int,
                                const QString* space_id) {
    if (InterlockedCompareExchange(&login_active, 1, 0) != 0) Stop(NativeReentrancy);
    ReportLocalStatus("local-rendezvous-login-entered");
    // The constructor hook must have installed a real facade with its supported
    // null borrowed-Ubi argument, never an invalid nonnull facade substitute.
    if (!self || *reinterpret_cast<void**>(static_cast<unsigned char*>(self) + 0x0c))
        Stop(NativeFacadeMismatch);
    void* backend = *reinterpret_cast<void**>(static_cast<unsigned char*>(self) + 0x20);
    void* network = Native<NetworkGetter>(0xE82240)();
    if (!backend || !network) Stop(NativeNetworkUnavailable);

    // Preserve the production wrapper's space identifier copy. This is a
    // borrowed native string supplied and later destroyed by the original caller.
    if (space_id && space_id->data && *reinterpret_cast<const char*>(space_id->data))
        Native<SpaceSetter>(0xE898D0)(backend, space_id);

    OwnedString key(public_key);
    Native<NetworkSelectAes>(0xE770E0)(network);
    Native<KeyCacheSetter>(0xE8AE20)(&key.value);
    // E77190 consumes/destroys the one-word by-value native qString.
    Native<NetworkKeySetter>(0xE77190)(network, key.Release());

    OwnedString sandbox("");
    OwnedString address(server_address);
    OwnedString ticket(local_ticket);
    // E43810 consumes ticket, copies it into its normal job, and retains the
    // original context/callback lifecycle. Empty sandbox + null Ubi = mode0.
    bool result = Native<FacadeLogin>(0xE43810)(self, context, &sandbox.value,
        &address.value, udp_port, ticket.Release(), 0);
    InterlockedExchange(&login_active, 0);
    return result;
}

struct Patch {
    uintptr_t va;
    unsigned char original[5];
    const void* replacement;
    bool pointer_slot = false;
    unsigned char raw_length = 0;
};

struct NativeResult { int32_t code; uint32_t detail; };
using GameLogin = void (__thiscall*)(void*);
unsigned char* CheckedGame(void* game) {
    auto* bytes = static_cast<unsigned char*>(game);
    if (!bytes || *reinterpret_cast<uintptr_t*>(bytes) != image_base + 0x109C9D8 - PreferredBase)
        Stop(NativeGameObjectMismatch);
    void* facade = *reinterpret_cast<void**>(bytes + 0x54);
    if (!facade || *reinterpret_cast<void**>(static_cast<unsigned char*>(facade) + 0x0c))
        Stop(NativeFacadeMismatch);
    return bytes;
}
NativeResult* __fastcall ConnectLocalGame(void* self, void*, NativeResult* output) {
    auto* game = CheckedGame(self);
    if (!output) Stop(NativeGameObjectMismatch);
    const bool ready = initialization == 2 && local_connect_probe && udp_port != 0;
    output->code = BeginLocalConnect(ready, game[0x38], game[0x48], [&]() {
        ReportLocalStatus("local-connect-job-dispatched");
        // The original login action allocates the genuine CallContext, retains
        // callbacks, and reaches our existing LoginLocalFacade hook. Never set
        // the native connected flag or fabricate a completed SDK session.
        Native<GameLogin>(0xD49B80)(self);
    });
    output->detail = 0;
    return output;
}
NativeResult* __fastcall RequestLocalGame(void* self, void*, NativeResult* output) {
    if (!self || !output) Stop(NativeGameObjectMismatch);
    auto* owner = static_cast<unsigned char*>(self);
    auto* game = CheckedGame(owner + 0x50);
    NativeResult local{};
    // C8EBE0 uses owner+78 (=game+28) for requested, owner+278 for its result.
    const int32_t code = RequestLocalConnect(initialization == 2 && local_connect_probe, game[0x28], [&]() {
        return ConnectLocalGame(game, nullptr, &local)->code;
    });
    auto* stored = reinterpret_cast<NativeResult*>(owner + 0x278);
    stored->code = code; stored->detail = 0;
    *output = *stored;
    return output;
}
unsigned char* LocalUpdateOwner(unsigned char* network);
void __fastcall UpdateLocalGame(void* self, void*) {
    // Preserve the original update/callback delivery before requesting a local
    // connection. Readiness comes from real native objects and our config,
    // not UbiServices. The requested/pending fields prevent duplicate jobs.
    if (!pump_active) natural_updates_seen = true;
    ++owner_update_count;
    static bool entered = false;
    static bool returned = false;
    static bool wrong_object = false;
    static bool no_facade = false;
    static bool no_network = false;
    static bool already_requested = false;
    if (!entered) { entered = true; ReportLocalStatus("local-connect-update-entered"); }
    Native<GameLogin>(0xC956C0)(self);
    if (!returned) { returned = true; ReportLocalStatus("local-connect-update-returned"); }
    if (initialization != 2 || !local_connect_probe || !self) return;
    if (LocalUpdateOwner(*Native<unsigned char**>(0x1379E14)) != self) return;
    auto* game = static_cast<unsigned char*>(self) + 0x50;
    if (*reinterpret_cast<uintptr_t*>(game) != image_base + 0x109C9D8 - PreferredBase) {
        if (!wrong_object) { wrong_object = true; ReportLocalStatus("local-connect-update-object-mismatch"); }
        return;
    }
    if (!*reinterpret_cast<void**>(game + 0x54)) {
        if (!no_facade) { no_facade = true; ReportLocalStatus("local-connect-update-awaiting-facade"); }
        return;
    }
    if (!Native<NetworkGetter>(0xE82240)()) {
        if (!no_network) { no_network = true; ReportLocalStatus("local-connect-update-awaiting-network"); }
        return;
    }
    if (game[0x28] && !already_requested) {
        already_requested = true; ReportLocalStatus("local-connect-update-already-requested");
    }
    if (!game[0x28]) { NativeResult result{}; RequestLocalGame(self, nullptr, &result); }
}

bool LocalConnectionReady(void* self) {
    if (initialization != 2 || !local_connect_probe || !self ||
        self != *Native<void**>(0x1379E14)) return false;
    auto* owner = *reinterpret_cast<unsigned char**>(static_cast<unsigned char*>(self) + 0xa18);
    if (!owner || *reinterpret_cast<uintptr_t*>(owner) != image_base + 0x10919BC - PreferredBase) return false;
    auto* game = owner + 0x50;
    if (*reinterpret_cast<uintptr_t*>(game) != image_base + 0x109C9D8 - PreferredBase) return false;
    auto* facade = *reinterpret_cast<unsigned char**>(game + 0x54);
    // Report the real locally connected transport, not a fabricated Ubisoft SDK
    // session. Pending, disconnected and differently owned objects stay false.
    return facade && !*reinterpret_cast<void**>(facade + 0x0c) && game[0x38] && !game[0x48];
}

unsigned char* LocalUpdateOwner(unsigned char* network) {
    if (!network || network != *Native<unsigned char**>(0x1379E14)) return nullptr;
    auto* owner = *reinterpret_cast<unsigned char**>(network + 0xa18);
    if (!owner || *reinterpret_cast<uintptr_t*>(owner) != image_base + 0x10919BC - PreferredBase)
        return nullptr;
    auto* game = owner + 0x50;
    if (*reinterpret_cast<uintptr_t*>(game) != image_base + 0x109C9D8 - PreferredBase) return nullptr;
    auto* facade = *reinterpret_cast<unsigned char**>(game + 0x54);
    if (!facade || *reinterpret_cast<void**>(facade + 0x0c) ||
        !*reinterpret_cast<void**>(owner + 0x100) ||
        !*reinterpret_cast<void**>(owner + 0x104) ||
        !*reinterpret_cast<void**>(owner + 0x110)) return nullptr;
    return owner;
}

unsigned char* LocalUpdateCore(unsigned char* network) {
    if (!network || network != *Native<unsigned char**>(0x1379E14)) return nullptr;
    auto* master = network + 0x5c;
    auto* core = *reinterpret_cast<unsigned char**>(network + 0x2c);
    // ED46A0 publishes the master's core only after ED60F0/ED55F0 have
    // constructed the core and registered the game-side observers.
    if (!core || *reinterpret_cast<uintptr_t*>(core) != image_base + 0x10940A0 - PreferredBase ||
        *reinterpret_cast<uintptr_t*>(master) != image_base + 0x1091E3C - PreferredBase ||
        *reinterpret_cast<void**>(master + 0x4c0) != core) return nullptr;
    auto* implementation = *reinterpret_cast<unsigned char**>(core + 0x20);
    if (!implementation ||
        *reinterpret_cast<uintptr_t*>(implementation) != image_base + 0x1099548 - PreferredBase ||
        !*reinterpret_cast<void**>(implementation + 4)) return nullptr;
#ifdef S7_LOCAL_NETWORK_PUMP
    auto* scheduler = *reinterpret_cast<unsigned char**>(implementation + 4);
    if (*reinterpret_cast<uintptr_t*>(scheduler) != image_base + 0x109959C - PreferredBase) return nullptr;
#endif
    return core;
}
#ifdef S7_LOCAL_NETWORK_PUMP
unsigned char* LabCoreScheduler(unsigned char* core) {
    auto* implementation = *reinterpret_cast<unsigned char**>(core + 0x20);
    return *reinterpret_cast<unsigned char**>(implementation + 4);
}
bool LabCoreAdvanced(unsigned char* core) {
    auto* scheduler = LabCoreScheduler(core);
    const unsigned int frame = *reinterpret_cast<unsigned int*>(scheduler + 0x78);
    // CFD2D0 advances this counter only for a real phase 1/3 core dispatch.
    // An owner-only C956C0 callback does not establish that dispatch occurred.
    if (lab_last_scheduler != scheduler) return false;
    if (frame == lab_last_core_frame) return false;
    lab_last_core_frame = frame;
    static bool reported = false;
    if (!reported) { reported = true; ReportLocalStatus("lab-native-core-natural-progress-observed"); }
    return true;
}
void RememberLabCoreFrame(unsigned char* core) {
    auto* scheduler = LabCoreScheduler(core);
    lab_last_scheduler = scheduler;
    lab_last_core_frame = *reinterpret_cast<unsigned int*>(scheduler + 0x78);
}

void __fastcall SetLocalTurnOffset(void* self, void*, unsigned int requested) {
    const DWORD entry_error = GetLastError();
    unsigned int selected = requested;
    bool used_default = false;
    if (initialization == 2 && local_connect_probe && GetCurrentThreadId() == bootstrap_thread) {
        auto* network = *Native<unsigned char**>(0x1379E14);
        auto* main = *Native<unsigned char**>(0x13A5210);
        if (LocalUpdateOwner(network) && main &&
            *reinterpret_cast<uintptr_t*>(main) == image_base + 0x113F2C0 - PreferredBase &&
            self && *reinterpret_cast<void**>(main + 0x18) == self &&
            *static_cast<uintptr_t*>(self) == image_base + 0x113F424 - PreferredBase) {
            auto* latency = *reinterpret_cast<unsigned char**>(network + 0xa58);
            if (latency && *reinterpret_cast<uintptr_t*>(latency) == image_base + 0x1140188 - PreferredBase && latency[0x18]) {
                // ED2EA0 initializes twenty samples to UINT_MAX. ED2DE0 returns
                // their minimum; ECF59F otherwise divides the unknown sentinel
                // by 66 and increases the guest offset on every command turn.
                unsigned int minimum = UINT32_MAX;
                for (unsigned int i = 0; i < 20; ++i) {
                    const auto value = *reinterpret_cast<unsigned int*>(latency + 0x44 + i * 4);
                    if (value < minimum) minimum = value;
                }
                if (minimum == UINT32_MAX) {
                    auto* state = static_cast<unsigned char*>(self);
                    // Use the game's own desired turn horizon (normally five),
                    // not a fabricated latency sample. With no desired horizon,
                    // retain the existing target. Real samples keep native policy.
                    selected = state[0x60] ? state[0x60] : *reinterpret_cast<unsigned int*>(state + 0x28);
                    used_default = true;
                }
            }
        }
    }
    using Setter = void (__thiscall*)(void*, unsigned int);
    SetLastError(entry_error);
    Native<Setter>(0xECC870)(self, selected);
    const DWORD result_error = GetLastError();
    static bool reported = false;
    if (used_default && !reported) {
        reported = true;
        ReportLocalStatus("local-command-offset-unknown-latency-default");
    }
    SetLastError(result_error);
}
#endif

bool __fastcall QueryLocalLoginStatus(void* self, void*) {
    const bool ready = LocalConnectionReady(self);
    static volatile LONG previous = -1;
    if (InterlockedExchange(&previous, ready ? 1 : 0) != (ready ? 1 : 0))
        ReportLocalStatus(ready ? "local-game-login-status-connected" : "local-game-login-status-not-ready");
    return ready;
}

bool __fastcall SkipLocalNetworkStartup(void* self, void*) {
    // ED480A asks the platform's offline policy only to decide whether to
    // create the native Startup ECHO job. Allow that job for the local probe;
    // keep the platform offline and leave actual network readiness untouched.
    if (initialization != 2 || !local_connect_probe ||
        GetCurrentThreadId() != bootstrap_thread || !self ||
        self != *Native<void**>(0x13789D0) ||
        *static_cast<uintptr_t*>(self) != image_base + 0x112BE3C - PreferredBase)
        return true;
    ReportLocalStatus("local-network-startup-enabled");
    return false;
}

bool LocalSessionSearchReady(void* self) {
    if (GetCurrentThreadId() != bootstrap_thread || !udp_port ||
        !LocalConnectionReady(self)) return false;
    auto* network = static_cast<unsigned char*>(self);
    auto* owner = LocalUpdateOwner(network);
    if (!owner || !LocalUpdateCore(network) ||
        !*reinterpret_cast<void**>(owner + 0x108)) return false;
    // Scope this to dispatching search/create/join requests to the connected
    // local service. This does not assert global NAT or match readiness.
    return network[0x5c + 0x4c4] == 1 && owner[0x18] == 1 && owner[0x38] == 1 &&
        *reinterpret_cast<int32_t*>(owner + 0x28) == 1 && owner[0x249] == 0;
}

bool EnsureLocalSearchSpace(void* self);
bool __fastcall QueryLocalSessionSearch(void* self, void*) {
    const bool ready = LocalSessionSearchReady(self) && EnsureLocalSearchSpace(self);
    static volatile LONG previous = -1;
    if (InterlockedExchange(&previous, ready ? 1 : 0) != (ready ? 1 : 0))
        ReportLocalStatus(ready ? "local-session-search-ready" : "local-session-search-not-ready");
    return ready;
}
bool __fastcall QueryLocalSessionCreate(void* self, void*) {
    // Only ED630B in the Create Session request path. Its original asynchronous
    // job still owns success/failure; no lobby or transport state is fabricated.
    const bool ready = LocalSessionSearchReady(self) && EnsureLocalSearchSpace(self);
    ReportLocalStatus(ready ? "local-session-create-ready" : "local-session-create-not-ready");
    return ready;
}
bool __fastcall QueryLocalSessionJoin(void* self, void*) {
    // Only ED673B, before construction of the original Join Session job.
    // Preserve its RPC, native state transitions and eventual result.
    const bool ready = LocalSessionSearchReady(self) && EnsureLocalSearchSpace(self);
    ReportLocalStatus(ready ? "local-session-join-ready" : "local-session-join-not-ready");
    return ready;
}

// D43F50 returns a freshly constructed 24-byte native small string through
// a stack output pointer, EAX=output, RET 4. Its only search caller C8DCC5
// immediately copies the value and frees it only when capacity >= 16.
// This is not qString and must never contain a pointer owned by our CRT.
struct NativeSmallString {
    char inline_data[16];
    uint32_t length;
    uint32_t capacity;
};
static_assert(sizeof(NativeSmallString) == 24, "native small string is 24 bytes");

const char* SmallStringData(const NativeSmallString& value) {
    return value.capacity < 16 ? value.inline_data :
        *reinterpret_cast<const char* const*>(value.inline_data);
}
bool SameSearchSpace(const NativeSmallString& value, const char* text, size_t length) {
    if (value.length != length || value.capacity < value.length) return false;
    const char* data = SmallStringData(value);
    return data && memcmp(data, text, length) == 0 && data[length] == 0;
}
bool EnsureLocalSearchSpace(void* self) {
    if (!LocalSessionSearchReady(self)) return false;
    auto* network = static_cast<unsigned char*>(self);
    auto* owner = LocalUpdateOwner(network);
    auto* helper = *reinterpret_cast<unsigned char**>(owner + 0x108);
    if (*reinterpret_cast<uintptr_t*>(helper) != image_base + 0x109CB58 - PreferredBase ||
        !*reinterpret_cast<void**>(helper + 0x1d8)) return false;
    auto* facade = *reinterpret_cast<unsigned char**>(owner + 0xa4);
    auto* backend = *reinterpret_cast<unsigned char**>(facade + 0x20);
    if (!backend) return false;
    // E898D0 copies the public application SpaceId to backend+E4 as qString.
    // Read no credentials; reuse the actual local connection's namespace.
    const char* space = *reinterpret_cast<const char**>(backend + 0xe4);
    if (!space) return false;
    const size_t length = strnlen_s(space, 129);
    if (!length || length > 128) return false;
    for (size_t i = 0; i < length; ++i)
        if (static_cast<unsigned char>(space[i]) < 0x21 ||
            static_cast<unsigned char>(space[i]) > 0x7e) return false;
    auto* current = reinterpret_cast<NativeSmallString*>(helper + 0x10);
    if (current->length) return SameSearchSpace(*current, space, length);

    // Borrowed input only: D4A860 copies it through the game's string allocator,
    // then updates its dependent default_session_ name. Never destroy this view.
    NativeSmallString input{};
    input.length = static_cast<uint32_t>(length);
    input.capacity = length < 16 ? 15 : static_cast<uint32_t>(length);
    if (length < 16) memcpy(input.inline_data, space, length + 1);
    else memcpy(input.inline_data, &space, sizeof(space));
    using SetSearchSpace = void (__thiscall*)(void*, const NativeSmallString*);
    Native<SetSearchSpace>(0xD4A860)(helper, &input);
    if (LocalUpdateOwner(network) != owner || !LocalSessionSearchReady(network) ||
        *reinterpret_cast<void**>(owner + 0x108) != helper ||
        *reinterpret_cast<void**>(owner + 0xa4) != facade ||
        *reinterpret_cast<void**>(facade + 0x20) != backend ||
        *reinterpret_cast<const char**>(backend + 0xe4) != space) return false;
    const bool ready = SameSearchSpace(*current, space, length);
    if (ready) ReportLocalStatus("local-session-search-space-ready");
    return ready;
}
bool ConstructLocalSearchSandbox(void* self, NativeSmallString* output) {
    if (!output || initialization != 2 || !local_connect_probe ||
        GetCurrentThreadId() != bootstrap_thread) return false;
    auto* network = *Native<unsigned char**>(0x1379E14);
    if (!LocalSessionSearchReady(network)) return false;
    auto* owner = LocalUpdateOwner(network);
    if (!owner || self != owner + 0x50) return false;
    // The local direct-mode login uses an empty sandbox. Preserve that value
    // here instead of dereferencing the deliberately absent borrowed Ubi facade.
    *output = {};
    output->capacity = 15;
    return true;
}
NativeSmallString* __fastcall GetLocalSearchSandbox(void* self, void*, NativeSmallString* output) {
    if (!ConstructLocalSearchSandbox(self, output)) Stop(NativeGameObjectMismatch);
    static bool reported = false;
    if (!reported) { reported = true; ReportLocalStatus("local-session-search-sandbox-ready"); }
    return output;
}
#ifdef S7_LOCAL_NETWORK_PUMP
NativeResult* __fastcall ObserveLabEchoDispatcher(void* self, void*, NativeResult* result, unsigned int phase, int timeout) {
    static bool entered = false;
    const DWORD incoming_error = GetLastError();
    if (!entered) { entered = true; ReportLocalStatus("lab-native-echo-dispatcher-entered"); }
    SetLastError(incoming_error);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, unsigned int, int);
    return Native<Original>(0xC33020)(self, result, phase, timeout);
}
NativeResult* __fastcall ObserveLabSessionDispatch(void* self, void*, NativeResult* result, void* event) {
    const DWORD incoming_error = GetLastError();
    ReportLocalStatus("lab-native-session-request-dispatched");
    SetLastError(incoming_error);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, void*);
    auto* returned = Native<Original>(0xC24050)(self, result, event);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned != result || !result ? "lab-native-session-dispatch-result-unavailable"
        : result->code > 0 ? "lab-native-session-dispatch-accepted"
        : result->code == 0 ? "lab-native-session-dispatch-zero" : "lab-native-session-dispatch-failed");
    SetLastError(error); return returned;
}
NativeResult* __fastcall ObserveLabPlayerRequest(void* self, void*, NativeResult* result, void* event) {
    const DWORD incoming_error = GetLastError();
    ReportLocalStatus("lab-native-player-request-entered"); SetLastError(incoming_error);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, void*);
    auto* returned = Native<Original>(0xB833E0)(self, result, event);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned != result || !result ? "lab-native-player-result-unavailable"
        : result->code == 2 ? "lab-native-player-request-pending"
        : result->code > 0 ? "lab-native-player-request-immediate" : "lab-native-player-request-failed");
    SetLastError(error); return returned;
}
NativeResult* __fastcall ObserveLabTicketRequest(void* self, void*, NativeResult* result, void* event) {
    const DWORD incoming_error = GetLastError();
    ReportLocalStatus("lab-native-ticket-request-entered"); SetLastError(incoming_error);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, void*);
    auto* returned = Native<Original>(0xC25610)(self, result, event);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned == result && result && result->code == 2
        ? "lab-native-ticket-request-pending" : "lab-native-ticket-request-returned");
    SetLastError(error); return returned;
}
void* __fastcall ObserveLabTicketReferenceMissing(void* output, void*, const char* text, unsigned int length) {
    using Original = void* (__thiscall*)(void*, const char*, unsigned int);
    auto* returned = Native<Original>(0x657E70)(output, text, length);
    const DWORD error = GetLastError();
    // This callsite is reachable only after the original session lookup fails.
    // Observe that native branch, never the lookup key or any ticket content.
    ReportLocalStatus("lab-native-ticket-session-reference-missing");
    SetLastError(error); return returned;
}
const char* LabTicketRejectionLabel(uintptr_t caller) {
    switch (caller) {
    case 0xC24C0E: return "lab-native-ticket-session-state-rejected";
    case 0xC24CA2: return "lab-native-ticket-session-flag-rejected";
    case 0xC24D41: return "lab-native-ticket-empty-peer-rejected";
    case 0xC24DD6: return "lab-native-ticket-transport-pool-exhausted";
    case 0xC24E27: return "lab-native-ticket-add-host-failed";
    case 0xC24E8B: return "lab-native-ticket-existing-request";
    case 0xC24F11: return "lab-native-ticket-pool-exhausted";
    case 0xC25143: return "lab-native-ticket-no-ready-peer";
    case 0xC252C3: return "lab-native-ticket-host-reference-rejected";
    default: return "lab-native-ticket-rejection-unclassified";
    }
}
uintptr_t __fastcall ObserveLabTicketTransport(void* self, void*, uintptr_t a, uintptr_t b,
    uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    using Original = uintptr_t (__thiscall*)(void*, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
    const DWORD incoming = GetLastError(); ReportLocalStatus("lab-native-ticket-transport-entered"); SetLastError(incoming);
    const uintptr_t returned = Native<Original>(0xC2BEB0)(self, a, b, c, d, e, f, g);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned ? "lab-native-ticket-transport-created" : "lab-native-ticket-transport-unavailable");
    SetLastError(error); return returned;
}
void __fastcall ObserveLabTicketEvent(void* self, void*, uintptr_t a, uintptr_t b,
    uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    using Original = void (__thiscall*)(void*, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
    Native<Original>(0xC0BAE0)(self, a, b, c, d, e, f, g);
    const DWORD error = GetLastError();
    ReportLocalStatus("lab-native-ticket-event-constructed"); SetLastError(error);
}
int __fastcall ObserveLabTicketLinkResult(const NativeResult* result, void*) {
    // Original getter 4DA460 reads only the result code. Preserve it exactly.
    const int code = result->code; const DWORD error = GetLastError();
    ReportLocalStatus(code == 2 ? "lab-native-ticket-link-pending"
        : code > 0 ? "lab-native-ticket-link-accepted" : "lab-native-ticket-link-failed");
    SetLastError(error); return code;
}
NativeResult* __fastcall ObserveLabTicketReceived(void* self, void*, NativeResult* result, void* event) {
    const DWORD incoming = GetLastError(); ReportLocalStatus("lab-native-ticket-received-event"); SetLastError(incoming);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, void*);
    auto* returned = Native<Original>(0xC22790)(self, result, event);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned == result && result && result->code > 0
        ? "lab-native-ticket-received-accepted" : "lab-native-ticket-received-failed");
    SetLastError(error); return returned;
}
NativeResult* __fastcall ObserveLabPlayerTicket(void* self, void*, NativeResult* result, void* event) {
    const DWORD incoming = GetLastError(); ReportLocalStatus("lab-native-player-ticket-entered"); SetLastError(incoming);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, void*);
    auto* returned = Native<Original>(0xB86710)(self, result, event);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned == result && result && result->code > 0
        ? "lab-native-player-ticket-returned-positive" : "lab-native-player-ticket-failed");
    SetLastError(error); return returned;
}
void* __fastcall ObserveLabTicketSessionLookup(void* self, void*, uintptr_t reference) {
    // B86770 is reached only after the native metadata type check succeeds.
    // Forward the lookup reference without examining or logging it.
    using Original = void* (__thiscall*)(void*, uintptr_t);
    auto* returned = Native<Original>(0xC0A8B0)(self, reference);
    const DWORD error = GetLastError();
    ReportLocalStatus(returned ? "lab-native-player-ticket-session-found" : "lab-native-player-ticket-session-missing");
    SetLastError(error); return returned;
}
void __fastcall ObserveLabHostJoinGate(void* self, void*, void* event) {
    // Exact GameSessionHandler virtual slot. C0 is the native full/in-game
    // gate read by ED307C, not an identity or a replacement readiness value.
    const DWORD incoming = GetLastError();
    ReportLocalStatus(static_cast<unsigned char*>(self)[0xc0]
        ? "lab-native-host-join-gate-closed" : "lab-native-host-join-gate-open");
    SetLastError(incoming);
    using Original = void (__thiscall*)(void*, void*);
    Native<Original>(0xED3070)(self, event);
}
NativeResult* __fastcall ObserveLabHostEventRoute(void* self, void*, NativeResult* result,
    uintptr_t context, void* event, uintptr_t destination) {
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, uintptr_t, void*, uintptr_t);
    auto* returned = Native<Original>(0xCFA5E0)(self, result, context, event, destination);
    const DWORD error = GetLastError();
    const char* label = "lab-native-host-event-route-result-unavailable";
    if (returned == result && result)
        label = result->code > 0 ? "lab-native-host-event-route-queued"
            : result->code == -999996 ? "lab-native-host-event-route-invalid-destination"
            : result->code == -1000000 ? "lab-native-host-event-route-unavailable"
            : "lab-native-host-event-route-failed";
    ReportLocalStatus(label); SetLastError(error); return returned;
}
bool __fastcall ObserveLabHostJoinEventType(void* event, void*, uintptr_t left, uintptr_t right) {
    using Original = bool (__thiscall*)(void*, uintptr_t, uintptr_t);
    const bool matched = Native<Original>(0xC9A280)(event, left, right);
    const DWORD error = GetLastError();
    if (matched) ReportLocalStatus("lab-native-host-join-event-dispatched");
    SetLastError(error); return matched;
}
template<uintptr_t Target>
NativeResult* __fastcall ObserveLabTicketSeven(void* self, void*, NativeResult* result,
    uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g) {
    constexpr bool wire = Target == 0xC223F0;
    const DWORD incoming = GetLastError();
    ReportLocalStatus(wire ? "lab-native-ticket-wire-received" : "lab-native-ticket-approval-dispatched");
    SetLastError(incoming);
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
    auto* returned = Native<Original>(Target)(self, result, b, c, d, e, f, g);
    const DWORD error = GetLastError();
    const bool accepted = returned == result && result && result->code > 0;
    ReportLocalStatus(wire ? (accepted ? "lab-native-ticket-wire-accepted" : "lab-native-ticket-wire-failed")
        : (accepted ? "lab-native-ticket-approval-queued" : "lab-native-ticket-approval-failed"));
    SetLastError(error); return returned;
}
void* __fastcall ObserveLabTicketRejection(void* output, void*, const char* text) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress()) - image_base + PreferredBase;
    using Original = void* (__thiscall*)(void*, const char*);
    auto* returned = Native<Original>(0x6576D0)(output, text);
    const DWORD error = GetLastError();
    ReportLocalStatus(LabTicketRejectionLabel(caller)); SetLastError(error); return returned;
}
void* __fastcall ObserveLabTicketStateRejection(void* output, void*, const char* text, unsigned int length) {
    using Original = void* (__thiscall*)(void*, const char*, unsigned int);
    auto* returned = Native<Original>(0x657E70)(output, text, length);
    const DWORD error = GetLastError();
    ReportLocalStatus("lab-native-ticket-session-state-rejected"); SetLastError(error); return returned;
}
void* __fastcall ObserveLabPlayerReason(void* output, void*, const char* text, unsigned int length) {
    using Original = void* (__thiscall*)(void*, const char*, unsigned int);
    auto* returned = Native<Original>(0x657E70)(output, text, length);
    const DWORD error = GetLastError();
    ReportLocalStatus(text == Native<const char*>(0x10888D8) ? "lab-native-player-peer-conflict"
        : text == Native<const char*>(0x10888E8) ? "lab-native-player-pending-conflict"
        : text == Native<const char*>(0x10888C8) ? "lab-native-player-invalid-guid" : "lab-native-player-reason-other");
    SetLastError(error); return returned;
}
void LabCoreBoundary(void* core, unsigned int phase) {
    using Original = NativeResult* (__thiscall*)(void*, NativeResult*, unsigned int);
    NativeResult result{};
    Native<Original>(0xCB90C0)(core, &result, phase);
    static bool begin_reported = false, end_reported = false;
    bool& reported = phase == 1 ? begin_reported : end_reported;
    if (!reported) {
        reported = true;
        ReportLocalStatus(phase == 1 ? "lab-native-core-begin-delivered" : "lab-native-core-end-delivered");
    }
}
NativeResult* __cdecl UpdateLabEcho(NativeResult* result, unsigned int phase, int timeout) {
    if (GetCurrentThreadId() == bootstrap_thread) ++echo_update_count;
    using Original = NativeResult* (__cdecl*)(NativeResult*, unsigned int, int);
    return Native<Original>(0xBAF5D0)(result, phase, timeout);
}
void __fastcall UpdateLocalJoinWait(void* self, void*) {
    // ED68C4 runs inside the blocking Join Session loop. That loop does not
    // return to UPLAY_Update, so the ordinary platform bridge cannot deliver
    // the missing core/manager work while the join is waiting.
    if (initialization == 2 && local_connect_probe && !pump_active &&
        GetCurrentThreadId() == bootstrap_thread && self == *Native<void**>(0x1379E14) &&
        LocalUpdateOwner(static_cast<unsigned char*>(self)) &&
        LocalUpdateCore(static_cast<unsigned char*>(self)) && Native<NetworkGetter>(0xE82240)()) {
        static bool reported = false;
        if (!reported) { reported = true; ReportLocalStatus("lab-native-join-wait-pump-active"); }
        PumpOfflineBootstrap();
    } else {
        Native<GameLogin>(0xED3BA0)(self);
    }
}
unsigned char* LocalLabManager(unsigned char* network) {
    auto* owner = LocalUpdateOwner(network);
    if (!owner) return nullptr;
    auto* manager = *reinterpret_cast<unsigned char**>(owner + 0x100);
    return manager && *reinterpret_cast<uintptr_t*>(manager) == image_base + 0x10934EC - PreferredBase
        ? manager : nullptr;
}
void __fastcall UpdateLabManager(void* self, void*) {
    // Observe the real virtual update, preserving its original thiscall.
    // ED7A40/ED7A47 explicitly dispatch this manager after CBC710 phase 3.
    if (GetCurrentThreadId() == bootstrap_thread) ++manager_update_count;
    Native<GameLogin>(0xCA6380)(self);
}
void* __fastcall ObserveLabSessionRejection(void* output, void*, const char* text) {
    // Only fixed, hash-guarded native diagnostic branches reach this wrapper.
    // Compare literal addresses, never inspect a peer/profile identifier or text.
    const char* label = "lab-native-session-rejection-unclassified";
    if (text == Native<const char*>(0x108DAD0)) label = "lab-native-session-reference-pool-exhausted";
    if (text == Native<const char*>(0x108DB10)) label = "lab-native-session-create-failed";
    if (text == Native<const char*>(0x108DC4C)) label = "lab-native-session-host-migration";
    if (text == Native<const char*>(0x108DC78)) label = "lab-native-session-already-joined";
    if (text == Native<const char*>(0x108DCA4)) label = "lab-native-session-self-join-rejected";
    if (text == Native<const char*>(0x108DCDC)) label = "lab-native-session-empty-peer-rejected";
    if (text == Native<const char*>(0x108DD04)) label = "lab-native-session-host-descriptor-rejected";
    if (text == Native<const char*>(0x10888F8)) label = "lab-native-player-data-missing";
    using Original = void* (__thiscall*)(void*, const char*);
    auto* returned = Native<Original>(0x6576D0)(output, text);
    DWORD error = GetLastError(); ReportLocalStatus(label); SetLastError(error);
    return returned;
}
int __fastcall ObserveLabJoinCompletion(const NativeResult* result, void*) {
    // The guarded original call at D3F928 targets 4DA460: MOV EAX,[ECX]; RET.
    // Observe only that same result code; no object identities are inspected.
    const int code = result->code;
    const DWORD error = GetLastError();
    const char* label = "lab-native-join-completion-other-failure";
    if (code > 0) label = "lab-native-join-completion-succeeded";
    else switch (code) {
    case 0: label = "lab-native-join-completion-zero"; break;
    case -1000000: label = "lab-native-join-completion-failed"; break;
    case -999985: label = "lab-native-join-completion-invalid-guid"; break;
    case -999977: label = "lab-native-join-completion-inappropriate-state"; break;
    case -999930: label = "lab-native-join-completion-session-request-refused"; break;
    case -999925: label = "lab-native-join-completion-invalid-session"; break;
    case -999920: label = "lab-native-join-completion-session-exists"; break;
    case -999912: label = "lab-native-join-completion-link-reach-failed"; break;
    }
    ReportLocalStatus(label); SetLastError(error); return code;
}
// D49B10 does not consume ECX and returns RET 1C: seven stack arguments.
// D47803 leaves the trailing zero on the stack across BA4750; the six following
// pushes form the rest. Observe only the real caller's result, preserving all
// arguments, return pointer and native failure/success behavior.
NativeResult* __stdcall ObserveLabJoinRequest(NativeResult* result, void* peer, void* session,
    void* metadata, void* job, void* callback, unsigned int flags) {
    using Original = NativeResult* (__stdcall*)(NativeResult*, void*, void*, void*, void*, void*, unsigned int);
    auto* returned = Native<Original>(0xD49B10)(result, peer, session, metadata, job, callback, flags);
    const DWORD error = GetLastError();
    const char* label = "lab-native-join-result-unavailable";
    if (result && returned == result) {
        if (result->code > 0) {
            label = "lab-native-join-request-accepted";
            ReportLocalStatus(result->code == 2 ? "lab-native-join-request-pending"
                : result->code == 1 ? "lab-native-join-request-immediate" : "lab-native-join-request-positive-other");
        }
        else switch (result->code) {
        case 0: label = "lab-native-join-result-zero"; break;
        case -1000000: label = "lab-native-join-request-failed"; break;
        case -999985: label = "lab-native-join-invalid-guid"; break;
        case -999982: label = "lab-native-join-invalid-parameter"; break;
        case -999979: label = "lab-native-join-module-not-initialized"; break;
        case -999978: label = "lab-native-join-module-not-started"; break;
        case -999977: label = "lab-native-join-inappropriate-state"; break;
        case -999937: label = "lab-native-join-invalid-session-reference"; break;
        case -999930: label = "lab-native-join-session-request-refused"; break;
        case -999925: label = "lab-native-join-invalid-session"; break;
        case -999920: label = "lab-native-join-session-exists"; break;
        default: label = "lab-native-join-other-failure"; break;
        }
    }
    ReportLocalStatus(label);
    SetLastError(error);
    return returned;
}
#endif
// ED0300 returns a *locked* boolean for a known privilege descriptor. Both
// callers retain their original lookup/existence checks and cdecl cleanup.
bool __cdecl LocalContentLocked(const void*) { return false; }
// Exact upstream HE_UBI default delta: file 13D9FC, 95 -> 94. Guard the whole
// SETcc instruction, and keep the on-disk executable pristine for validation.
const unsigned char DevelopmentModeBytes[] = {0x0f,0x94,0xc0};
const Patch Patches[] = {
    {0xD3C62D, {0xe8,0x1e,0x6f,0x10,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD4A083, {0xe8,0xc8,0x94,0x0f,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD49CFD, {0xe8,0x8e,0x9f,0x0f,0x00}, reinterpret_cast<const void*>(&LoginLocalFacade)},
    {0xED02EE, {0xe8,0x0d,0x00,0x00,0x00}, reinterpret_cast<const void*>(&LocalContentLocked)},
    {0xED05DF, {0xe8,0x1c,0xfd,0xff,0xff}, reinterpret_cast<const void*>(&LocalContentLocked)},
    {0x53E5FB, {0x0f,0x95,0xc0}, DevelopmentModeBytes, false, 3}
};
// Explicit opt-in substitutes complete connect operations at known callers,
// instead of making a UbiServices session-readiness predicate return true.
const Patch ConnectPatches[] = {
    {0xC92127, {0xe8,0xb4,0xca,0xff,0xff}, reinterpret_cast<const void*>(&RequestLocalGame)},
    {0xC93A31, {0xe8,0xaa,0xb1,0xff,0xff}, reinterpret_cast<const void*>(&RequestLocalGame)},
    {0xC9511A, {0xe8,0xc1,0x9a,0xff,0xff}, reinterpret_cast<const void*>(&RequestLocalGame)},
    {0xC956F5, {0xe8,0xe6,0x94,0xff,0xff}, reinterpret_cast<const void*>(&RequestLocalGame)},
    {0xC958CF, {0xe8,0x5c,0xa9,0xff,0xff}, reinterpret_cast<const void*>(&ConnectLocalGame)},
    {0xED2CAE, {0xe8,0x7d,0x45,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalLoginStatus)},
    {0xED62FC, {0xe8,0x2f,0x0f,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalLoginStatus)},
    {0xED651D, {0xe8,0x0e,0x0d,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalLoginStatus)},
    {0xED672C, {0xe8,0xff,0x0a,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalLoginStatus)},
    {0xED6C2B, {0xe8,0x00,0x06,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalLoginStatus)},
    // Replace the complete five-byte MOV EAX,[EDX+28]; CALL EAX sequence.
    {0xED480A, {0x8b,0x42,0x28,0xff,0xd0}, reinterpret_cast<const void*>(&SkipLocalNetworkStartup)},
    {0xED6C3A, {0xe8,0x31,0x06,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalSessionSearch)},
    {0xED630B, {0xe8,0x60,0x0f,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalSessionCreate)},
    {0xED673B, {0xe8,0x30,0x0b,0x00,0x00}, reinterpret_cast<const void*>(&QueryLocalSessionJoin)},
    {0xC8DCC5, {0xe8,0x86,0x62,0x0b,0x00}, reinterpret_cast<const void*>(&GetLocalSearchSandbox)},
#ifdef S7_LOCAL_NETWORK_PUMP
    {0xECF5D8, {0xe8,0x93,0xd2,0xff,0xff}, reinterpret_cast<const void*>(&SetLocalTurnOffset)},
    {0xECF5F4, {0xe8,0x77,0xd2,0xff,0xff}, reinterpret_cast<const void*>(&SetLocalTurnOffset)},
    {0xC0E809, {0xe8,0x02,0x6e,0x01,0x00}, reinterpret_cast<const void*>(&ObserveLabTicketRequest)},
    {0xC256DA, {0xe8,0x91,0x27,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketReferenceMissing)},
    {0xC24C09, {0xe8,0x62,0x32,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketStateRejection)},
    {0xC24C9D, {0xe8,0x2e,0x2a,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC24D3C, {0xe8,0x8f,0x29,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC24DD1, {0xe8,0xfa,0x28,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC24E22, {0xe8,0xa9,0x28,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC24E86, {0xe8,0x45,0x28,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC24F0C, {0xe8,0xbf,0x27,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC2513E, {0xe8,0x8d,0x25,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC252BE, {0xe8,0x0d,0x24,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketRejection)},
    {0xC252AC, {0xe8,0xff,0x6b,0x00,0x00}, reinterpret_cast<const void*>(&ObserveLabTicketTransport)},
    {0xC25277, {0xe8,0x64,0x68,0xfe,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketEvent)},
    {0xC2C269, {0xe8,0xf2,0xe1,0x8a,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketLinkResult)},
    {0xC0E961, {0xe8,0x2a,0x3e,0x01,0x00}, reinterpret_cast<const void*>(&ObserveLabTicketReceived)},
    {0xC22819, {0xe8,0xd2,0xfb,0xff,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketSeven<0xC223F0>)},
    {0xC22611, {0xe8,0x6a,0x38,0xff,0xff}, reinterpret_cast<const void*>(&ObserveLabTicketSeven<0xC15E80>)},
    {0xB7DA97, {0xe8,0x74,0x8c,0x00,0x00}, reinterpret_cast<const void*>(&ObserveLabPlayerTicket)},
    {0xB86770, {0xe8,0x3b,0x41,0x08,0x00}, reinterpret_cast<const void*>(&ObserveLabTicketSessionLookup)},
    {0x1140060, {0x70,0x30,0xed,0x00,0x00}, reinterpret_cast<const void*>(&ObserveLabHostJoinGate), true},
    {0xB86886, {0xe8,0x55,0x3d,0x17,0x00}, reinterpret_cast<const void*>(&ObserveLabHostEventRoute)},
    {0xCA285B, {0xe8,0x20,0x7a,0xff,0xff}, reinterpret_cast<const void*>(&ObserveLabHostJoinEventType)},
    {0xB7D92F, {0xe8,0xac,0x5a,0x00,0x00}, reinterpret_cast<const void*>(&ObserveLabPlayerRequest)},
    {0xB834AB, {0xe8,0xc0,0x49,0xad,0xff}, reinterpret_cast<const void*>(&ObserveLabPlayerReason)},
    {0xB8359E, {0xe8,0xcd,0x48,0xad,0xff}, reinterpret_cast<const void*>(&ObserveLabPlayerReason)},
    {0xB839E1, {0xe8,0x8a,0x44,0xad,0xff}, reinterpret_cast<const void*>(&ObserveLabPlayerReason)},
    {0xB8377D, {0xe8,0x4e,0x3f,0xad,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xBAF5F8, {0xe8,0x23,0x3a,0x08,0x00}, reinterpret_cast<const void*>(&ObserveLabEchoDispatcher)},
    {0xC0E931, {0xe8,0x1a,0x57,0x01,0x00}, reinterpret_cast<const void*>(&ObserveLabSessionDispatch)},
    {0xC98023, {0xe8,0xa8,0x75,0xf1,0xff}, reinterpret_cast<const void*>(&UpdateLabEcho)},
    {0xED68C4, {0xe8,0xd7,0xd2,0xff,0xff}, reinterpret_cast<const void*>(&UpdateLocalJoinWait)},
    {0x1093638, {0x80,0x63,0xca,0x00,0x00}, reinterpret_cast<const void*>(&UpdateLabManager), true},
    {0xD4781C, {0xe8,0xef,0x22,0x00,0x00}, reinterpret_cast<const void*>(&ObserveLabJoinRequest)},
    {0xD3F928, {0xe8,0x33,0xab,0x79,0xff}, reinterpret_cast<const void*>(&ObserveLabJoinCompletion)},
    {0xC241AB, {0xe8,0x20,0x35,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC2426E, {0xe8,0x5d,0x34,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC23C7B, {0xe8,0x50,0x3a,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC23D05, {0xe8,0xc6,0x39,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC23DD5, {0xe8,0xf6,0x38,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC23E6F, {0xe8,0x5c,0x38,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
    {0xC23F37, {0xe8,0x94,0x37,0xa3,0xff}, reinterpret_cast<const void*>(&ObserveLabSessionRejection)},
#endif
    {0x1091B08, {0xc0,0x56,0xc9,0x00,0x00}, reinterpret_cast<const void*>(&UpdateLocalGame), true}
};

bool ValidateKey(const char* encoded) {
    unsigned char blob[72] = {};
    DWORD size = sizeof(blob);
    if (!CryptStringToBinaryA(encoded, 96, CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                             blob, &size, nullptr, nullptr) || size != sizeof(blob)) return false;
    const unsigned char header[8] = {'E','C','S','1',32,0,0,0};
    if (memcmp(blob, header, sizeof(header)) != 0) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool valid = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM,
                                             nullptr, 0) >= 0;
    if (valid) valid = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                         &key, blob, sizeof(blob), 0) >= 0;
    if (key) BCryptDestroyKey(key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return valid;
}

bool AcceptExecutableDigest(const unsigned char (&actual)[32]) {
#ifdef S7_LOCAL_PAIR_LAB
    // Development-only builds accept exactly the two data-only variants
    // produced by tools/local-pair/lab_executable.py. Normal builds retain
    // the original-only guard. All PE, callsite, ABI and thread guards remain.
    static const unsigned char lab_a[32] = {
        0x72,0x2c,0xb6,0xe6,0x16,0x85,0x1f,0x20,0xfa,0xe9,0x0b,0x29,0xc8,0xaf,0x65,0xdf,
        0x8a,0xa9,0x4f,0x35,0x3b,0x07,0x39,0xe4,0x4c,0x24,0x72,0x1c,0xfb,0x57,0x4e,0x13};
    static const unsigned char lab_b[32] = {
        0x78,0xc7,0xa4,0xb8,0x7e,0x2f,0x8d,0xce,0xb9,0x5e,0xaa,0xac,0x9a,0xb8,0xcd,0xd5,
        0x59,0xce,0x48,0x2f,0xc8,0x00,0x12,0x93,0x45,0xe9,0x52,0xb7,0x11,0x97,0x4a,0x8a};
    bool valid = (memcmp(actual, lab_a, 32) == 0
                  || memcmp(actual, lab_b, 32) == 0);
    if (valid) local_pair_bind.store(memcmp(actual, lab_a, 32) == 0
        ? 0x7f000002u : 0x7f000003u);
#else
    bool valid = memcmp(actual, ExpectedHash, 32) == 0;
#endif
    return valid;
}

bool HashExecutable() {
    wchar_t path[32768] = {};
    DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
    if (!length || length >= _countof(path)) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    bool valid = GetFileSizeEx(file, &size) && size.QuadPart == 17333680;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    // CNG allocates/frees the hash object when its buffer is omitted (Win7+).
    if (valid) valid = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                                  nullptr, 0) >= 0;
    if (valid) valid = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    unsigned char buffer[65536] = {};
    DWORD read = 0;
    while (valid) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) { valid = false; break; }
        if (!read) break;
        valid = BCryptHashData(hash, buffer, read, 0) >= 0;
    }
    unsigned char actual[32] = {};
    if (valid) {
        valid = BCryptFinishHash(hash, actual, sizeof(actual), 0) >= 0;
        valid = valid && AcceptExecutableDigest(actual);
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return valid;
}

bool ValidateImage() {
    image_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!image_base) return false;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(*dos) ||
        dos->e_lfanew > 0x1000) return false;
    const IMAGE_NT_HEADERS32* pe = reinterpret_cast<const IMAGE_NT_HEADERS32*>(image_base + dos->e_lfanew);
    return pe->Signature == IMAGE_NT_SIGNATURE && pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
        pe->FileHeader.TimeDateStamp == ExpectedTimestamp &&
        pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        pe->OptionalHeader.SizeOfImage == ExpectedImageSize && HashExecutable();
}

unsigned char* PatchAddress(const Patch& patch) {
    return reinterpret_cast<unsigned char*>(image_base + patch.va - PreferredBase);
}

uint32_t OriginalPointer(const Patch& patch) {
    uint32_t preferred = 0;
    memcpy(&preferred, patch.original, sizeof(preferred));
    return static_cast<uint32_t>(image_base + preferred - PreferredBase);
}

bool WritePatch(const Patch& patch, bool restore) {
    if (patch.raw_length > sizeof(patch.original) || (patch.raw_length && patch.pointer_slot)) return false;
    unsigned char* at = PatchAddress(patch);
    DWORD old_protection = 0;
    const size_t length = patch.pointer_slot ? 4 : (patch.raw_length ? patch.raw_length : 5);
    if (!VirtualProtect(at, length, patch.pointer_slot ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    unsigned char bytes[5] = {0xe8,0,0,0,0};
    uint32_t relative = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(patch.replacement)) -
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(at) + 5);
    memcpy(bytes + 1, &relative, sizeof(relative));
    if (patch.pointer_slot) {
        uint32_t value = restore ? OriginalPointer(patch) : static_cast<uint32_t>(reinterpret_cast<uintptr_t>(patch.replacement));
        memcpy(at, &value, sizeof(value));
    } else memcpy(at, restore ? patch.original : (patch.raw_length ? patch.replacement : bytes), length);
    bool flushed = FlushInstructionCache(GetCurrentProcess(), at, length) != FALSE;
    DWORD ignored = 0;
    if (!VirtualProtect(at, length, old_protection, &ignored)) Stop(RollbackFailure);
    return flushed;
}

bool Install() {
    std::vector<const Patch*> selected;
    for (const auto& patch : Patches) selected.push_back(&patch);
    if (local_connect_probe) for (const auto& patch : ConnectPatches) selected.push_back(&patch);
    for (const auto* patch : selected) {
        const bool matches = patch->pointer_slot
            ? *reinterpret_cast<uint32_t*>(PatchAddress(*patch)) == OriginalPointer(*patch)
            : memcmp(PatchAddress(*patch), patch->original, patch->raw_length ? patch->raw_length : 5) == 0;
        if (!matches) {
            SetError(ChangedCallsite); return false;
        }
    }
    size_t modified = 0;
    for (; modified < selected.size(); ++modified) {
        if (!WritePatch(*selected[modified], false)) {
            // The failing write may have changed bytes before cache flush failed.
            for (size_t i = 0; i <= modified; ++i)
                if (!WritePatch(*selected[i], true)) Stop(RollbackFailure);
            SetError(PatchFailure); return false;
        }
    }
    return true;
}
}

bool InitializeOfflineBootstrap(const OfflineBootstrapConfig& config) {
    if (InterlockedCompareExchange(&initialization, 1, 0) != 0) {
        SetError(RepeatedInitialization); return false;
    }
    uint32_t numeric_address = 0;
    bool valid_address = config.server_address && (strcmp(config.server_address, "127.0.0.1") == 0
        || ParsePrivateLanAddress(config.server_address, numeric_address));
    bool valid = valid_address && config.udp_port && config.public_key_base64 && config.local_ticket;
    size_t key_length = valid ? strnlen_s(config.public_key_base64, sizeof(public_key)) : 0;
    size_t ticket_length = valid ? strnlen_s(config.local_ticket, sizeof(local_ticket)) : 0;
    valid = valid && key_length == 96 && ticket_length > 0 && ticket_length < sizeof(local_ticket);
    for (size_t i = 0; valid && i < ticket_length; ++i)
        valid = static_cast<unsigned char>(config.local_ticket[i]) >= 0x21 &&
                static_cast<unsigned char>(config.local_ticket[i]) <= 0x7e;
    if (!valid) { SetError(InvalidConfiguration); return false; }
    if (!ValidateKey(config.public_key_base64)) { SetError(InvalidPublicKey); return false; }
    if (!ValidateImage()) { SetError(WrongExecutable); return false; }
    memcpy(public_key, config.public_key_base64, key_length + 1);
    memcpy(local_ticket, config.local_ticket, ticket_length + 1);
    strcpy_s(server_address, config.server_address);
    udp_port = config.udp_port;
    local_connect_probe = config.local_connect_probe;
    bootstrap_thread = GetCurrentThreadId();
    if (!Install()) {
        SecureZeroMemory(local_ticket, sizeof(local_ticket));
        return false;
    }
    if (!ApplyLocalCpuAffinity()) Stop(PatchFailure);
    ReportLocalStatus("local-cpu-four-physical-cores-no-smt");
    InterlockedExchange(&initialization, 2);
    SetError(None);
    return true;
}

void PumpOfflineBootstrap() {
    // Startup and platform updates belong to the same game thread. Do not
    // access native objects from other threads or during recursive callbacks.
    if (initialization != 2 || !local_connect_probe ||
        GetCurrentThreadId() != bootstrap_thread || pump_active) return;
#ifndef S7_LOCAL_NETWORK_PUMP
    if (natural_updates_seen) return;
#endif
    struct ActiveScope {
        ActiveScope() { pump_active = true; }
        ~ActiveScope() { pump_active = false; }
    } active_scope;
    // ED5B6F constructs C8ABF0; ED5BA5 stores it at Network+0xA18.
    // Re-read ownership each tick and after callbacks, never cache game objects.
    auto* network = *Native<unsigned char**>(0x1379E14);
    auto* owner = LocalUpdateOwner(network);
    if (!owner || !Native<NetworkGetter>(0xE82240)()) return;
    static bool reported = false;
    if (!reported) { reported = true; ReportLocalStatus("local-connect-platform-pump-active"); }
    const unsigned int before = owner_update_count;
    auto* core = LocalUpdateCore(network);
#ifdef S7_LOCAL_NETWORK_PUMP
    // Skip only when the real core progressed since our previous pump. Never
    // latch off forever after one unrelated owner callback: the host can then
    // retain queued JoinRequest events indefinitely while the guest keeps ticking.
    if (core && LabCoreAdvanced(core)) return;
    // An interrupted supplied tick is ours, not evidence of external progress.
    // Restore the snapshot only after the final ownership checks below.
    if (core) lab_last_scheduler = nullptr;
    if (core && natural_updates_seen) {
        static bool resumed = false;
        if (!resumed) { resumed = true; ReportLocalStatus("lab-native-core-resumed-after-owner-update"); }
    }
#endif
    if (core) {
#ifdef S7_LOCAL_NETWORK_PUMP
        auto* manager = LocalLabManager(network);
        const unsigned int manager_before = manager_update_count;
        const unsigned int echo_before = echo_update_count;
        // ED3BA0 omits CB90C0 phase 1/2 when Network+30 selects external
        // frame boundaries. Supply those boundaries around the master update
        // in the local bridge; never alter that policy or native result flags.
        const bool supply_boundaries = network[0x30] && network[0x5c + 0x4c7];
        if (supply_boundaries) {
            LabCoreBoundary(core, 1);
            if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core) return;
        }
#endif
        static bool core_reported = false;
        if (!core_reported) { core_reported = true; ReportLocalStatus("local-network-core-pump-active"); }
        // Preserve ED7950's master-update then core-update ordering. These
        // dispatch real queued startup/network events. The intervening Ubisoft
        // profile/statistics/update calls are not required for this local pump.
        Native<GameLogin>(0xED3BA0)(network);
        // The master update may destroy or replace native objects in callbacks.
        if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core) return;
#ifdef S7_LOCAL_NETWORK_PUMP
        if (supply_boundaries && network[0x30] && network[0x5c + 0x4c7]) {
            LabCoreBoundary(core, 2);
            if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core) return;
        }
#endif
        using CoreUpdate = NativeResult* (__thiscall*)(void*, NativeResult*, unsigned int);
        NativeResult result{};
        Native<CoreUpdate>(0xCBC710)(core, &result, 3);
        if (LocalUpdateCore(network) != core) return;
#ifdef S7_LOCAL_NETWORK_PUMP
        // The master/core may already have dispatched this virtual update.
        // Supply only the omitted post-core tick, with ownership revalidated.
        if (LocalUpdateOwner(network) != owner) return;
        // C97FE0 omits the Echo dispatcher while master state is <= 1, even
        // when its core is started. Local NAT readiness does not advance that
        // state. BAF5D0 independently checks the real Echo SDK initialization;
        // deliver its queued native operations without changing readiness flags.
        auto* master = network + 0x5c;
        if (master[0x4c4] && master[0x4c7] &&
            *reinterpret_cast<unsigned int*>(master + 0x400) <= 1 && echo_update_count == echo_before) {
            static bool echo_reported = false;
            if (!echo_reported) { echo_reported = true; ReportLocalStatus("lab-native-echo-pump-active"); }
            NativeResult echo_result{};
            UpdateLabEcho(&echo_result, 3, -1);
            if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core) return;
        }
        if (manager && LocalLabManager(network) == manager && manager_update_count == manager_before) {
            static bool manager_reported = false;
            if (!manager_reported) {
                manager_reported = true;
                ReportLocalStatus("lab-native-manager-pump-active");
            }
            UpdateLabManager(manager, nullptr);
            if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core ||
                LocalLabManager(network) != manager) return;
        }
#endif
    }
    // A core callback may already have reached the patched owner update slot.
    // Only supply the old fallback tick when the core did not deliver one.
    if (LocalUpdateOwner(network) == owner && owner_update_count == before)
        UpdateLocalGame(owner, nullptr);
#ifdef S7_LOCAL_NETWORK_PUMP
    if (core && LocalUpdateOwner(network) == owner && LocalUpdateCore(network) == core)
        RememberLabCoreFrame(core);
#endif
}

const char* GetOfflineBootstrapError() {
    switch (InterlockedCompareExchange(&error_code, 0, 0)) {
    case None: return "";
    case RepeatedInitialization: return "Offline bootstrap initialization was repeated.";
    case InvalidConfiguration: return "Offline bootstrap configuration is invalid.";
    case InvalidPublicKey: return "Offline bootstrap public key is invalid.";
    case WrongExecutable: return "Offline bootstrap executable identity does not match.";
    case ChangedCallsite: return "Offline bootstrap callsite bytes do not match.";
    case PatchFailure: return "Offline bootstrap hooks could not be installed.";
    case NativeNetworkUnavailable: return "Offline bootstrap native network is unavailable.";
    case NativeFacadeMismatch: return "Offline bootstrap native facade does not match.";
    case NativeReentrancy: return "Offline bootstrap native login is already active.";
    case RollbackFailure: return "Offline bootstrap rollback failed.";
    case NativeGameObjectMismatch: return "Offline bootstrap game object does not match.";
    default: return "Offline bootstrap failed.";
    }
}
