#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include "offline_bootstrap.h"
#include "runtime_config.h"
#include "local_connect_policy.h"

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
bool local_connect_probe = false;
DWORD bootstrap_thread = 0;
bool pump_active = false;
bool natural_updates_seen = false;
unsigned int owner_update_count = 0;
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
    OwnedString address("127.0.0.1");
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
    return core;
}

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
    // Scope this to dispatching search/create requests to the already-connected
    // loopback service. This does not assert global NAT or match readiness.
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
const Patch Patches[] = {
    {0xD3C62D, {0xe8,0x1e,0x6f,0x10,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD4A083, {0xe8,0xc8,0x94,0x0f,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD49CFD, {0xe8,0x8e,0x9f,0x0f,0x00}, reinterpret_cast<const void*>(&LoginLocalFacade)}
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
    {0xC8DCC5, {0xe8,0x86,0x62,0x0b,0x00}, reinterpret_cast<const void*>(&GetLocalSearchSandbox)},
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
    if (valid) valid = BCryptFinishHash(hash, actual, sizeof(actual), 0) >= 0 &&
                       memcmp(actual, ExpectedHash, sizeof(actual)) == 0;
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
    unsigned char* at = PatchAddress(patch);
    DWORD old_protection = 0;
    const size_t length = patch.pointer_slot ? 4 : 5;
    if (!VirtualProtect(at, length, patch.pointer_slot ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    unsigned char bytes[5] = {0xe8,0,0,0,0};
    uint32_t relative = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(patch.replacement)) -
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(at) + 5);
    memcpy(bytes + 1, &relative, sizeof(relative));
    if (patch.pointer_slot) {
        uint32_t value = restore ? OriginalPointer(patch) : static_cast<uint32_t>(reinterpret_cast<uintptr_t>(patch.replacement));
        memcpy(at, &value, sizeof(value));
    } else memcpy(at, restore ? patch.original : bytes, sizeof(bytes));
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
            : memcmp(PatchAddress(*patch), patch->original, 5) == 0;
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
    bool valid = config.udp_port && config.public_key_base64 && config.local_ticket;
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
    udp_port = config.udp_port;
    local_connect_probe = config.local_connect_probe;
    bootstrap_thread = GetCurrentThreadId();
    if (!Install()) {
        SecureZeroMemory(local_ticket, sizeof(local_ticket));
        return false;
    }
    InterlockedExchange(&initialization, 2);
    SetError(None);
    return true;
}

void PumpOfflineBootstrap() {
    // Startup and platform updates belong to the same game thread. Do not
    // access native objects from other threads or during recursive callbacks.
    if (initialization != 2 || !local_connect_probe ||
        GetCurrentThreadId() != bootstrap_thread || pump_active || natural_updates_seen) return;
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
    if (core) {
        static bool core_reported = false;
        if (!core_reported) { core_reported = true; ReportLocalStatus("local-network-core-pump-active"); }
        // Preserve ED7950's master-update then core-update ordering. These
        // dispatch real queued startup/network events. The intervening Ubisoft
        // profile/statistics/update calls are not required for this local pump.
        Native<GameLogin>(0xED3BA0)(network);
        // The master update may destroy or replace native objects in callbacks.
        if (LocalUpdateOwner(network) != owner || LocalUpdateCore(network) != core) return;
        using CoreUpdate = NativeResult* (__thiscall*)(void*, NativeResult*, unsigned int);
        NativeResult result{};
        Native<CoreUpdate>(0xCBC710)(core, &result, 3);
        if (LocalUpdateCore(network) != core) return;
    }
    // A core callback may already have reached the patched owner update slot.
    // Only supply the old fallback tick when the core did not deliver one.
    if (LocalUpdateOwner(network) == owner && owner_update_count == before)
        UpdateLocalGame(owner, nullptr);
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
