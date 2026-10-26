// Synthetic ABI/storage checks. Build x86 with local_platform.cpp, without the
// game, network guard or bootstrap; the two prerequisites below are test fakes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "local_platform.h"

static bool allow_guard = true;
static bool allow_bootstrap = true;
static int guard_calls = 0;
static int bootstrap_calls = 0;
static int pump_calls = 0;
bool InstallOfflineNetworkGuard() { ++guard_calls; return allow_guard; }
bool InitializeOfflineBootstrap() { ++bootstrap_calls; return allow_bootstrap; }
void PumpOfflineBootstrap() {
    ++pump_calls;
    // This acquires the platform lock and would deadlock if Update retained it.
    UPLAY_FRIENDS_Init(0);
}
void ReportLocalStatus(const char*) {}

static int checks = 0;
static int failures = 0;
static void Check(bool passed, const char* fixed_label) {
    ++checks;
    if (!passed) { ++failures; std::printf("FAIL %s\n", fixed_label); }
}
static void Completed(void* op, uint32_t expected) {
    uint32_t result = 99;
    Check(UPLAY_HasOverlappedOperationCompleted(op) == 1, "completion ready");
    Check(UPLAY_GetOverlappedOperationResult(op, &result) == 1 && result == expected, "completion result");
    Check(UPLAY_HasOverlappedOperationCompleted(op) == 0, "completion consumed");
}
struct Entry { uint32_t slot; const char* name; uint32_t size; };
struct List { uint32_t count; Entry** entries; };

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const wchar_t* root = argv[1];
    constexpr char Id[] = "5b093c02-3bbc-4669-91b0-1f5303e40773";
    constexpr char Ticket[] = "local-s7:5b093c02-3bbc-4669-91b0-1f5303e40773";
    unsigned char operation[16]{};
    Check(UPLAY_Update() == 0, "update before start");
    Check(pump_calls == 0, "no native pump before startup");
    Check(UPLAY_Start(1, 0) == 1, "wrong app rejected");
    Check(UPLAY_Start(11788, 1) == 1, "wrong flags rejected");
    Check(guard_calls == 0 && bootstrap_calls == 0, "invalid start has no bootstrap");
    allow_guard = false;
    Check(UPLAY_Start(11788, 0) == 1 && bootstrap_calls == 0, "guard precedes bootstrap");
    allow_guard = true; allow_bootstrap = false;
    Check(UPLAY_Start(11788, 0) == 1, "failed bootstrap rejected");
    allow_bootstrap = true;
    Check(UPLAY_Start(11788, 0) == 1, "missing config rejected");
    Check(!InitializeLocalPlatform(L"relative", Id, "LocalPlayer", Ticket), "relative storage rejected");
    Check(!InitializeLocalPlatform(root, "not-a-uuid", "LocalPlayer", Ticket), "bad uuid rejected");
    Check(!InitializeLocalPlatform(root, Id, "", Ticket), "empty name rejected");
    Check(!InitializeLocalPlatform(root, Id, "LocalPlayer", ""), "empty local ticket rejected");
    Check(InitializeLocalPlatform(root, Id, "LocalPlayer", Ticket), "configure owned storage");
    Check(InitializeLocalPlatform(root, Id, "LocalPlayer", Ticket), "configuration idempotent");
    Check(!InitializeLocalPlatform(root, Id, "ChangedName", Ticket), "configuration change rejected");
    Check(UPLAY_Start(11788, 0) == 0 && UPLAY_Update() == 1, "valid startup is zero");
    Check(pump_calls == 1, "native pump runs outside platform lock");
    int old_calls = bootstrap_calls;
    Check(UPLAY_Start(11788, 0) == 0 && bootstrap_calls == old_calls, "start idempotent");
    Check(UPLAY_USER_IsInOfflineMode() == 1, "local offline capability");
    Check(strcmp(UPLAY_USER_GetAccountIdUtf8(), Id) == 0, "configured local identity");
    Check(strcmp(UPLAY_USER_GetNameUtf8(), "LocalPlayer") == 0, "configured local name");
    Check(strcmp(UPLAY_USER_GetTicketUtf8(), Ticket) == 0, "explicit local marker");
    Check(strcmp(UPLAY_USER_GetEmailUtf8(), "") == 0, "no cloud email");
    memset(operation, 0x6a, sizeof(operation));
    Check(UPLAY_GetNextEvent(operation) == 0 && operation[0] == 0x6a, "empty events do not overwrite");
    Check(UPLAY_FRIENDS_Init(0) == 0 && UPLAY_PARTY_Init(3) == 0, "social unavailable");
    Check(UPLAY_PRESENCE_SetPresence(123, reinterpret_cast<const void*>(1)) == 0, "presence unavailable without inspecting arguments");
    char error[514]; memset(error, 0x5a, sizeof(error));
    UPLAY_GetLastError(error + 1);
    Check(error[0] == 0x5a && error[513] == 0x5a && memchr(error + 1, 0, 512), "bounded fixed error");

    void* raw_list = nullptr;
    Check(UPLAY_SAVE_GetSavegames(&raw_list, operation) == 1, "empty list accepted");
    Completed(operation, 0);
    auto list = static_cast<List*>(raw_list);
    Check(list && list->count == 0, "empty owned list layout");
    UPLAY_SAVE_ReleaseGameList(raw_list);
    UPLAY_SAVE_ReleaseGameList(raw_list); // Unknown/released pointers are ignored, never dereferenced.

    uint32_t handle = 99;
    Check(UPLAY_SAVE_Open(9, 0, &handle, operation) == 1 && handle == 0, "missing slot queues not found");
    Completed(operation, 3);
    Check(UPLAY_SAVE_Open(9, 2, &handle, operation) == 0, "unknown mode rejected");
    Check(UPLAY_SAVE_Open(100000, 1, &handle, operation) == 0, "slot policy bounded");
    Check(UPLAY_SAVE_Open(9, 1, &handle, nullptr) == 0, "null operation rejected");
    Check(UPLAY_SAVE_Open(9, 1, &handle, operation) == 1 && handle != 0, "write handle");
    uint32_t write_handle = handle;
    Check(operation[0] == 0x6a && operation[15] == 0x6a, "opaque operation untouched");
    uint32_t other = 0;
    Check(UPLAY_SAVE_Open(8, 1, &other, operation) == 0, "pending operation reuse rejected");
    Completed(operation, 0);
    Check(UPLAY_SAVE_Open(9, 0, &other, operation) == 0, "concurrent slot conflict rejected");
    Check(UPLAY_SAVE_SetName(write_handle, "Synthetic test slot") == 1, "save name before write");
    unsigned char content[] = {0x61,0x00,0xff,0x72,0x7e};
    LocalPlatformBuffer buffer{content, sizeof(content)};
    Check(UPLAY_SAVE_Write(write_handle, sizeof(content) + 1, &buffer, operation) == 0, "buffer capacity enforced");
    Check(UPLAY_SAVE_Write(write_handle, sizeof(content), &buffer, operation) == 1, "atomic persistent write");
    Completed(operation, 0);
    Check(UPLAY_SAVE_Write(write_handle, sizeof(content), &buffer, operation) == 0, "unproved repeated-write semantics rejected");
    Check(UPLAY_SAVE_SetName(write_handle, "Renamed synthetic slot") == 1, "atomic name after write");
    Check(UPLAY_SAVE_Close(write_handle) == 1 && UPLAY_SAVE_Close(write_handle) == 0, "close and reject invalid handle");
    std::wstring path = std::wstring(root) + L"\\9.s7local";
    HANDLE saved = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t header[5]{}; DWORD actual = 0;
    Check(saved != INVALID_HANDLE_VALUE && ReadFile(saved, header, sizeof(header), &actual, nullptr) && actual == sizeof(header)
        && header[0] == 0x534c3753 && header[1] == 1 && header[2] == 9 && header[3] == 22 && header[4] == sizeof(content),
        "independent persistent header vector");
    if (saved != INVALID_HANDLE_VALUE) CloseHandle(saved);

    Check(UPLAY_SAVE_GetSavegames(&raw_list, operation) == 1, "persisted list accepted");
    Completed(operation, 0); list = static_cast<List*>(raw_list);
    Check(list && list->count == 1 && list->entries && list->entries[0] && list->entries[0]->slot == 9 &&
        list->entries[0]->size == sizeof(content) && strcmp(list->entries[0]->name, "Renamed synthetic slot") == 0,
        "independent pointer-array layout");
    UPLAY_SAVE_ReleaseGameList(raw_list);
    Check(UPLAY_SAVE_Open(9, 0, &handle, operation) == 1, "read persisted slot"); Completed(operation, 0);
    unsigned char destination[8]; memset(destination, 0xcc, sizeof(destination));
    LocalPlatformBuffer out{destination + 1, 5}; uint32_t bytes_read = 99;
    Check(UPLAY_SAVE_Read(handle, 5, 0, &out, &bytes_read, operation) == 1 && bytes_read == 5 &&
        memcmp(destination + 1, content, 5) == 0 && destination[0] == 0xcc && destination[6] == 0xcc,
        "persistent roundtrip with buffer sentinels"); Completed(operation, 0);
    Check(UPLAY_SAVE_Read(handle, 5, 3, &out, &bytes_read, operation) == 1 && bytes_read == 2 &&
        destination[1] == 0x72 && destination[2] == 0x7e, "offset and short read"); Completed(operation, 0);
    Check(UPLAY_SAVE_Read(handle, 5, 6, &out, &bytes_read, operation) == 0 && bytes_read == 0, "offset outside file rejected");
    Check(UPLAY_SAVE_Remove(9, operation) == 0, "open slot cannot be removed");
    Check(UPLAY_SAVE_Close(handle) == 1, "read handle close");
    Check(UPLAY_SAVE_Remove(9, operation) == 1, "remove owned slot"); Completed(operation, 0);
    Check(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES, "persistent remove verified");
    Check(UPLAY_SAVE_Remove(9, operation) == 1, "missing remove queued"); Completed(operation, 3);
    Check(UPLAY_GetOverlappedOperationResult(operation, &bytes_read) == 0, "unknown operation rejected");

    Check(UPLAY_SAVE_Open(7, 1, &handle, operation) == 1, "pending operation before quit");
    UPLAY_Quit();
    Check(UPLAY_Update() == 0 && UPLAY_HasOverlappedOperationCompleted(operation) == 0 && UPLAY_SAVE_Close(handle) == 0,
          "quit clears handles and completions");
    std::printf("%s %d local platform checks\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
