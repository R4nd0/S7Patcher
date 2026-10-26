#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <map>
#include <limits>
#include <algorithm>
#include <cstring>
#include "local_platform.h"
#include "runtime_config.h"

bool InstallOfflineNetworkGuard();
bool InitializeOfflineBootstrap();
void PumpOfflineBootstrap();

namespace {
constexpr uint32_t ExpectedApplication = 11788;
constexpr UINT UnsupportedExitCode = 0xE0537001u;
SRWLOCK state_lock = SRWLOCK_INIT;
bool started = false;
char local_id[37] = {};
char local_name[65] = {};
char local_ticket[129] = {};
bool configured = false;
const char* last_error = "Local platform is not started.";
void ClearStorageState();

struct StateLock {
    StateLock() { AcquireSRWLockExclusive(&state_lock); }
    ~StateLock() { ReleaseSRWLockExclusive(&state_lock); }
};

int Unavailable() {
    StateLock lock;
    last_error = "This capability is unavailable in the local platform adapter.";
    return 0;
}

__declspec(noreturn) void Unsupported() {
    // Unknown ABI functions must never return with guessed values. No message
    // includes arguments, and no user data is inspected or persisted.
    TerminateProcess(GetCurrentProcess(), UnsupportedExitCode);
    __fastfail(7);
}
}

extern "C" int __cdecl UPLAY_Start(uint32_t application_id, uint32_t flags) {
    if (application_id != ExpectedApplication || flags != 0) {
        StateLock lock;
        last_error = "Unsupported application or start flags.";
        return 1;
    }
    { StateLock lock; if (started) return 0; }
    ReportLocalStatus("local-platform-start-requested");
    // Bootstrap calls InitializeLocalPlatform, so do not hold state_lock here.
    // The network guard is a prerequisite, including on repeated Start calls.
    if (!InstallOfflineNetworkGuard() || !InitializeOfflineBootstrap()) {
        ReportLocalStatus("local-platform-start-failed");
        StateLock lock;
        last_error = "Local network guard or bootstrap failed.";
        return 1;
    }
    StateLock lock;
    if (!configured) { last_error = "Local platform configuration is missing."; return 1; }
    started = true;
    last_error = "";
    ReportLocalStatus("local-platform-started");
    return 0; // Verified EXE 4C7F3A..4C7F5A: zero is startup success.
}

extern "C" void __cdecl UPLAY_Quit() {
    StateLock lock;
    started = false;
    ClearStorageState();
    // Keep the identity buffer valid until module unload: the client owns no
    // returned strings. There is no persisted identity or token to erase.
    last_error = "Local platform is not started.";
}

extern "C" int __cdecl UPLAY_Update() {
    { StateLock lock; if (!started) return 0; }
    // Native callbacks may query this adapter again; never hold state_lock
    // across the game-owned update. The bootstrap bounds thread/reentrancy.
    PumpOfflineBootstrap();
    return 1;
}

extern "C" int __cdecl UPLAY_GetNextEvent(void*) {
    // There are no local social-service events to deliver; do not touch an
    // event structure whose complete layout is not yet established.
    return 0;
}

extern "C" void __cdecl UPLAY_GetLastError(char* buffer_512) {
    if (!buffer_512) return;
    StateLock lock;
    // Every verified HE caller supplies a 512-byte zeroed char buffer.
    size_t i = 0;
    while (last_error[i] && i < 511) { buffer_512[i] = last_error[i]; ++i; }
    buffer_512[i] = 0;
}

extern "C" int __cdecl UPLAY_USER_IsInOfflineMode() { return 1; }
extern "C" const char* __cdecl UPLAY_USER_GetNameUtf8() { return local_name; }
extern "C" const char* __cdecl UPLAY_USER_GetAccountIdUtf8() { return local_id; }
extern "C" const char* __cdecl UPLAY_USER_GetEmailUtf8() { return ""; }
extern "C" const char* __cdecl UPLAY_USER_GetTicketUtf8() {
    // Explicit local-only marker from the bundle, never a Ubisoft ticket.
    return local_ticket;
}
extern "C" int __cdecl UPLAY_FRIENDS_Init(uint32_t) { return Unavailable(); }
extern "C" int __cdecl UPLAY_PARTY_Init(uint32_t) { return Unavailable(); }
// HE 4D2ED8 parses an unsigned presence ID; 4D2F78..4D2F8D pushes
// list*, ID and cleans two cdecl arguments. The sole caller ignores EAX.
// Presence is an online social capability; no input/list contents are read.
extern "C" int __cdecl UPLAY_PRESENCE_SetPresence(uint32_t, const void*) { return Unavailable(); }
extern "C" int __cdecl UPLAY_SetLanguage(uint32_t) { return Unavailable(); }
extern "C" int __cdecl UPLAY_USER_SetGameSession(uint64_t, const LocalPlatformBuffer*, uint32_t) {
    return Unavailable();
}
extern "C" void __cdecl UPLAY_USER_ClearGameSession() {}

// Unknown ABI: log only the constant export name, then stop without returning
// through a guessed stack/return contract. No arguments are inspected.
#define S7_UNSUPPORTED(name) extern "C" __declspec(noreturn) void __cdecl name() { ReportLocalStatus("unsupported-export:" #name); Unsupported(); }
#include "unsupported_exports.inc"
#undef S7_UNSUPPORTED

namespace {
// Conservative local storage policies, not SDK/protocol limits. The first
// implementation supports one complete Write per mode-1 handle; unproven
// repeated-write/append semantics are rejected instead of guessed.
constexpr uint32_t MaxSlot = 99999;
constexpr uint32_t MaxSaveBytes = 16 * 1024 * 1024;
constexpr size_t MaxHandles = 32;
constexpr size_t MaxCompletions = 256;
constexpr size_t MaxSaveList = 256;
constexpr uint32_t FileMagic = 0x534c3753; // S7LS, local adapter format only.
struct FileHeader { uint32_t magic, version, slot, name_size, data_size; };
static_assert(sizeof(FileHeader) == 20, "local file format");
struct SaveEntry { uint32_t slot; const char* name; uint32_t size; };
struct SaveList { uint32_t count; SaveEntry** entries; };
static_assert(sizeof(SaveEntry) == 12 && sizeof(SaveList) == 8, "verified save list ABI");
struct SaveHandle {
    uint32_t slot = 0;
    uint32_t mode = 0;
    bool written = false;
    uint32_t listed_size = 0;
    std::string name;
    std::vector<unsigned char> data;
    SaveHandle() = default;
    SaveHandle(const SaveHandle&) = delete;
    SaveHandle& operator=(const SaveHandle&) = delete;
    SaveHandle(SaveHandle&&) = default;
    SaveHandle& operator=(SaveHandle&&) = default;
    ~SaveHandle() { if (!data.empty()) SecureZeroMemory(data.data(), data.size()); }
};
struct OwnedList {
    SaveList exposed{};
    std::vector<SaveEntry> entries;
    std::vector<SaveEntry*> pointers;
    std::vector<std::string> names;
};
std::wstring save_root;
std::map<uint32_t, SaveHandle> handles;
std::map<const void*, uint32_t> completions;
std::map<void*, OwnedList*> lists;
uint32_t next_handle = 1;
uint32_t temp_counter = 0;

struct File {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit File(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};

bool Printable(const char* value, size_t capacity, size_t& length) {
    if (!value) return false;
    for (length = 0; length < capacity; ++length) {
        unsigned char c = static_cast<unsigned char>(value[length]);
        if (!c) return true;
        if (c < 32 || c > 126) return false;
    }
    return false;
}

bool ValidUuid(const char* value) {
    size_t size = 0;
    if (!Printable(value, 37, size) || size != 36) return false;
    bool any_nonzero = false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else {
            const char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
            any_nonzero |= c != '0';
        }
    }
    return any_nonzero;
}

std::wstring SlotPath(uint32_t slot) { return save_root + L"\\" + std::to_wstring(slot) + L".s7local"; }

bool RegularFile(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION info{};
    return GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

bool ExactRead(HANDLE file, void* buffer, DWORD size) {
    DWORD actual = 0;
    return !size || (ReadFile(file, buffer, size, &actual, nullptr) && actual == size);
}
bool ExactWrite(HANDLE file, const void* buffer, DWORD size) {
    DWORD actual = 0;
    return !size || (WriteFile(file, buffer, size, &actual, nullptr) && actual == size);
}

bool LoadSlot(uint32_t slot, SaveHandle& target, bool read_data = true) {
    File file(CreateFileW(SlotPath(slot).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE || !RegularFile(file.value)) return false;
    FileHeader header{};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || !ExactRead(file.value, &header, sizeof(header)) ||
        header.magic != FileMagic || header.version != 1 || header.slot != slot ||
        header.name_size > 255 || header.data_size > MaxSaveBytes ||
        size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) != sizeof(header) + static_cast<uint64_t>(header.name_size) + header.data_size)
        return false;
    target.name.resize(header.name_size);
    if (read_data) target.data.resize(header.data_size);
    if (!ExactRead(file.value, target.name.data(), header.name_size) ||
        (read_data && !ExactRead(file.value, target.data.data(), header.data_size))) return false;
    for (unsigned char c : target.name) if (c < 32 || c > 126) return false;
    target.slot = slot;
    target.listed_size = header.data_size;
    return true;
}

bool StoreSlot(const SaveHandle& source) {
    std::wstring final_path = SlotPath(source.slot);
    DWORD attributes = GetFileAttributesW(final_path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return false;
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        SaveHandle previous;
        if (!LoadSlot(source.slot, previous, false)) return false;
    }
    std::wstring temporary = final_path + L".tmp." + std::to_wstring(GetCurrentProcessId()) +
        L"." + std::to_wstring(++temp_counter);
    HANDLE raw = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE) return false;
    FileHeader header{FileMagic, 1, source.slot, static_cast<uint32_t>(source.name.size()),
                      static_cast<uint32_t>(source.data.size())};
    bool ok = ExactWrite(raw, &header, sizeof(header)) &&
        ExactWrite(raw, source.name.data(), header.name_size) &&
        ExactWrite(raw, source.data.data(), header.data_size) && FlushFileBuffers(raw);
    if (!CloseHandle(raw)) ok = false;
    if (ok) ok = MoveFileExW(temporary.c_str(), final_path.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(temporary.c_str());
    return ok;
}

bool OperationAvailable(void* operation) {
    return configured && operation && completions.find(operation) == completions.end() &&
        completions.size() < MaxCompletions;
}
int Complete(void* operation, uint32_t result) {
    completions.emplace(operation, result);
    return 1;
}
int StorageError() {
    last_error = "Local save operation failed or is outside supported bounds.";
    return 0;
}

void ClearStorageState() {
    handles.clear();
    completions.clear();
    for (auto& item : lists) delete item.second;
    lists.clear();
}
}

bool InitializeLocalPlatform(const wchar_t* storage_root, const char* profile_id,
                             const char* display_name, const char* ticket) {
    StateLock lock;
    if (!storage_root || !ValidUuid(profile_id)) return false;
    size_t name_size = 0, ticket_size = 0;
    if (!Printable(display_name, sizeof(local_name), name_size) || !name_size ||
        !Printable(ticket, sizeof(local_ticket), ticket_size) || !ticket_size) return false;
    // Absolute local DOS paths only. Root supplies bundle/LocalData/saves;
    // disallow device/UNC roots and alternate data streams.
    size_t root_size = 0;
    while (root_size < MAX_PATH - 64 && storage_root[root_size]) ++root_size;
    if (root_size < 4 || root_size >= MAX_PATH - 64 || storage_root[1] != L':' ||
        storage_root[2] != L'\\' || !((storage_root[0] >= L'A' && storage_root[0] <= L'Z') ||
        (storage_root[0] >= L'a' && storage_root[0] <= L'z'))) return false;
    for (size_t i = 2; i < root_size; ++i)
        if (storage_root[i] == L':' || storage_root[i] == L'/' || storage_root[i] == L'*' || storage_root[i] == L'?') return false;
    wchar_t canonical[MAX_PATH]{};
    DWORD canonical_size = GetFullPathNameW(storage_root, MAX_PATH, canonical, nullptr);
    if (!canonical_size || canonical_size >= MAX_PATH || _wcsicmp(canonical, storage_root) != 0) return false;
    try {
        std::wstring candidate(storage_root);
        if (configured) {
            return save_root == candidate && strcmp(local_id, profile_id) == 0 &&
                strcmp(local_name, display_name) == 0 && strcmp(local_ticket, ticket) == 0;
        }
        std::wstring parent = candidate.substr(0, candidate.find_last_of(L'\\'));
        File parent_directory(CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        wchar_t resolved_parent[MAX_PATH + 8]{};
        DWORD parent_size = parent_directory.value == INVALID_HANDLE_VALUE ? 0 :
            GetFinalPathNameByHandleW(parent_directory.value, resolved_parent, MAX_PATH + 8, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!parent_size || parent_size >= MAX_PATH + 8 || wcsncmp(resolved_parent, L"\\\\?\\", 4) != 0 ||
            _wcsicmp(resolved_parent + 4, parent.c_str()) != 0) return false;
        if (!CreateDirectoryW(candidate.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
        File directory(CreateFileW(candidate.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        if (directory.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(directory.value, &info) ||
            !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        wchar_t resolved[MAX_PATH + 8]{};
        DWORD resolved_size = GetFinalPathNameByHandleW(directory.value, resolved, MAX_PATH + 8, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!resolved_size || resolved_size >= MAX_PATH + 8 || wcsncmp(resolved, L"\\\\?\\", 4) != 0 ||
            _wcsicmp(resolved + 4, candidate.c_str()) != 0) return false;
        save_root = candidate;
        memcpy(local_id, profile_id, sizeof(local_id));
        memcpy(local_name, display_name, name_size + 1);
        memcpy(local_ticket, ticket, ticket_size + 1);
        configured = true;
        return true;
    } catch (...) { return false; }
}

extern "C" int __cdecl UPLAY_HasOverlappedOperationCompleted(const void* operation) {
    StateLock lock;
    return operation && completions.find(operation) != completions.end() ? 1 : 0;
}
extern "C" int __cdecl UPLAY_GetOverlappedOperationResult(const void* operation, uint32_t* result) {
    StateLock lock;
    auto found = completions.find(operation);
    if (!operation || !result || found == completions.end()) return StorageError();
    *result = found->second;
    completions.erase(found); // Consume before the caller frees/reuses its opaque operation.
    return 1;
}

extern "C" int __cdecl UPLAY_SAVE_Open(uint32_t slot, uint32_t mode, uint32_t* output, void* operation) {
    StateLock lock;
    if (output) *output = 0;
    if (!output || !OperationAvailable(operation) || slot > MaxSlot || mode > 1 || handles.size() >= MaxHandles)
        return StorageError();
    for (const auto& item : handles) if (item.second.slot == slot && (mode == 1 || item.second.mode == 1)) return StorageError();
    try {
        SaveHandle value;
        value.slot = slot;
        value.mode = mode;
        if (mode == 0 && !LoadSlot(slot, value)) return Complete(operation, 3); // Native not-found result.
        uint32_t handle = next_handle++;
        if (!handle) handle = next_handle++;
        handles.emplace(handle, std::move(value));
        *output = handle;
        return Complete(operation, 0);
    } catch (...) { return StorageError(); }
}

extern "C" int __cdecl UPLAY_SAVE_Read(uint32_t handle, uint32_t size, uint32_t offset,
                                      LocalPlatformBuffer* buffer, uint32_t* bytes_read, void* operation) {
    StateLock lock;
    if (bytes_read) *bytes_read = 0;
    auto found = handles.find(handle);
    if (!bytes_read || !buffer || (size && !buffer->data) || size > buffer->size || size > MaxSaveBytes ||
        !OperationAvailable(operation) || found == handles.end() || found->second.mode != 0)
        return StorageError();
    const auto& data = found->second.data;
    if (offset > data.size()) return StorageError();
    uint32_t count = static_cast<uint32_t>((std::min)(static_cast<size_t>(size), data.size() - offset));
    try {
        int result = Complete(operation, 0);
        if (count) memcpy(buffer->data, data.data() + offset, count);
        *bytes_read = count;
        return result;
    } catch (...) { return StorageError(); }
}

extern "C" int __cdecl UPLAY_SAVE_Write(uint32_t handle, uint32_t size,
                                       const LocalPlatformBuffer* buffer, void* operation) {
    StateLock lock;
    auto found = handles.find(handle);
    if (!buffer || (size && !buffer->data) || size > buffer->size || size > MaxSaveBytes ||
        !OperationAvailable(operation) || found == handles.end() || found->second.mode != 1 || found->second.written)
        return StorageError();
    try {
        auto& target = found->second;
        if (size) target.data.assign(static_cast<const unsigned char*>(buffer->data), static_cast<const unsigned char*>(buffer->data) + size);
        if (!StoreSlot(target)) { target.data.clear(); return StorageError(); }
        target.written = true;
        return Complete(operation, 0);
    } catch (...) { return StorageError(); }
}

extern "C" int __cdecl UPLAY_SAVE_SetName(uint32_t handle, const char* name) {
    StateLock lock;
    size_t length = 0;
    auto found = handles.find(handle);
    if (!Printable(name, 256, length) || found == handles.end() || found->second.mode != 1) return StorageError();
    try {
        auto& target = found->second;
        std::string old_name = target.name;
        target.name.assign(name, length);
        if (target.written && !StoreSlot(target)) { target.name = old_name; return StorageError(); }
        return 1;
    } catch (...) { return StorageError(); }
}

extern "C" int __cdecl UPLAY_SAVE_Close(uint32_t handle) {
    StateLock lock;
    if (handles.erase(handle) == 0) return StorageError();
    return 1;
}

extern "C" int __cdecl UPLAY_SAVE_Remove(uint32_t slot, void* operation) {
    StateLock lock;
    if (slot > MaxSlot || !OperationAvailable(operation)) return StorageError();
    for (const auto& pair : handles) if (pair.second.slot == slot) return StorageError();
    try {
        SaveHandle existing;
        if (!LoadSlot(slot, existing, false)) return Complete(operation, 3);
        if (!DeleteFileW(SlotPath(slot).c_str())) return StorageError();
        return Complete(operation, 0);
    } catch (...) { return StorageError(); }
}

extern "C" int __cdecl UPLAY_SAVE_GetSavegames(void** output, void* operation) {
    StateLock lock;
    if (output) *output = nullptr;
    if (!output || !OperationAvailable(operation) || lists.size() >= 8) return StorageError();
    OwnedList* result = nullptr;
    HANDLE search = INVALID_HANDLE_VALUE;
    try {
        result = new OwnedList;
        WIN32_FIND_DATAW file{};
        search = FindFirstFileW((save_root + L"\\*.s7local").c_str(), &file);
        if (search == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) { delete result; return StorageError(); }
        if (search != INVALID_HANDLE_VALUE) do {
            if (file.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
            const wchar_t* p = file.cFileName;
            uint32_t slot = 0;
            unsigned digits = 0;
            while (*p >= L'0' && *p <= L'9' && digits < 5) { slot = slot * 10 + *p++ - L'0'; ++digits; }
            if (!digits || wcscmp(p, L".s7local") != 0 || std::to_wstring(slot) + L".s7local" != file.cFileName) continue;
            SaveHandle item;
            if (!LoadSlot(slot, item, false)) continue;
            if (result->entries.size() == MaxSaveList) { FindClose(search); search = INVALID_HANDLE_VALUE; delete result; return StorageError(); }
            result->entries.push_back({slot, nullptr, item.listed_size});
            result->names.push_back(item.name);
        } while (FindNextFileW(search, &file));
        if (search != INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError(); FindClose(search); search = INVALID_HANDLE_VALUE;
            if (error != ERROR_NO_MORE_FILES) { delete result; return StorageError(); }
        }
        for (size_t i = 0; i < result->entries.size(); ++i) {
            result->entries[i].name = result->names[i].c_str();
            result->pointers.push_back(&result->entries[i]);
        }
        result->exposed.count = static_cast<uint32_t>(result->entries.size());
        result->exposed.entries = result->pointers.data();
        lists.emplace(&result->exposed, result);
        Complete(operation, 0);
        *output = &result->exposed;
        return 1;
    } catch (...) {
        if (search != INVALID_HANDLE_VALUE) FindClose(search);
        if (result) { lists.erase(&result->exposed); delete result; }
        return StorageError();
    }
}

extern "C" void __cdecl UPLAY_SAVE_ReleaseGameList(void* list) {
    StateLock lock;
    auto found = lists.find(list);
    if (found == lists.end()) return;
    delete found->second;
    lists.erase(found);
}
