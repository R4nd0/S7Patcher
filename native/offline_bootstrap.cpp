#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "offline_bootstrap.h"
#include "runtime_config.h"

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
    NativeFacadeMismatch, NativeReentrancy, RollbackFailure
};
volatile LONG initialization = 0;
volatile LONG error_code = None;
volatile LONG login_active = 0;
uintptr_t image_base = 0;
unsigned short udp_port = 0;
char public_key[97] = {};
char local_ticket[257] = {};

void SetError(Error error) { InterlockedExchange(&error_code, error); }
__declspec(noreturn) void Stop(Error error) {
    SetError(error);
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
};
const Patch Patches[] = {
    {0xD3C62D, {0xe8,0x1e,0x6f,0x10,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD4A083, {0xe8,0xc8,0x94,0x0f,0x00}, reinterpret_cast<const void*>(&ConstructLocalFacade)},
    {0xD49CFD, {0xe8,0x8e,0x9f,0x0f,0x00}, reinterpret_cast<const void*>(&LoginLocalFacade)}
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

bool WritePatch(const Patch& patch, bool restore) {
    unsigned char* at = PatchAddress(patch);
    DWORD old_protection = 0;
    if (!VirtualProtect(at, 5, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    unsigned char bytes[5] = {0xe8,0,0,0,0};
    uint32_t relative = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(patch.replacement)) -
                        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(at) + 5);
    memcpy(bytes + 1, &relative, sizeof(relative));
    memcpy(at, restore ? patch.original : bytes, sizeof(bytes));
    bool flushed = FlushInstructionCache(GetCurrentProcess(), at, sizeof(bytes)) != FALSE;
    DWORD ignored = 0;
    if (!VirtualProtect(at, 5, old_protection, &ignored)) Stop(RollbackFailure);
    return flushed;
}

bool Install() {
    for (const auto& patch : Patches) {
        if (memcmp(PatchAddress(patch), patch.original, 5) != 0) {
            SetError(ChangedCallsite); return false;
        }
    }
    size_t modified = 0;
    for (; modified < _countof(Patches); ++modified) {
        if (!WritePatch(Patches[modified], false)) {
            // The failing write may have changed bytes before cache flush failed.
            for (size_t i = 0; i <= modified; ++i)
                if (!WritePatch(Patches[i], true)) Stop(RollbackFailure);
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
    if (!Install()) {
        SecureZeroMemory(local_ticket, sizeof(local_ticket));
        return false;
    }
    InterlockedExchange(&initialization, 2);
    SetError(None);
    return true;
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
    default: return "Offline bootstrap failed.";
    }
}
