#pragma once

// Narrow, locally implemented ABI for the verified x86 History Edition.
// This is not the Ubisoft SDK and never loads it. Unimplemented exports stop
// the process rather than inventing a return contract or reporting success.
#include <stdint.h>

#if !defined(_WIN32) || !defined(_M_IX86)
#error The verified platform ABI requires Windows x86.
#endif

struct LocalPlatformBuffer {
    void* data;
    uint32_t size;
};
static_assert(sizeof(LocalPlatformBuffer) == 8, "x86 buffer ABI");

// Called by the trusted bundle bootstrap, before UPLAY_Start succeeds. These
// are explicit bundle-local values, never loaded from Ubisoft accounts/caches.
bool InitializeLocalPlatform(const wchar_t* storage_root, const char* profile_id,
                             const char* display_name, const char* local_ticket);

extern "C" {
int __cdecl UPLAY_Start(uint32_t application_id, uint32_t flags);
void __cdecl UPLAY_Quit();
int __cdecl UPLAY_Update();
int __cdecl UPLAY_GetNextEvent(void* event_record);
void __cdecl UPLAY_GetLastError(char* buffer_512);
int __cdecl UPLAY_USER_IsInOfflineMode();
const char* __cdecl UPLAY_USER_GetNameUtf8();
const char* __cdecl UPLAY_USER_GetAccountIdUtf8();
const char* __cdecl UPLAY_USER_GetEmailUtf8();
const char* __cdecl UPLAY_USER_GetTicketUtf8();
int __cdecl UPLAY_FRIENDS_Init(uint32_t flags);
int __cdecl UPLAY_PARTY_Init(uint32_t flags);
int __cdecl UPLAY_PRESENCE_SetPresence(uint32_t presence_id, const void* parameters);
int __cdecl UPLAY_SetLanguage(uint32_t language);
int __cdecl UPLAY_USER_SetGameSession(uint64_t session_id,
                                    const LocalPlatformBuffer* data, uint32_t flags);
void __cdecl UPLAY_USER_ClearGameSession();
int __cdecl UPLAY_HasOverlappedOperationCompleted(const void* operation);
int __cdecl UPLAY_GetOverlappedOperationResult(const void* operation, uint32_t* result);

// Bounded persistent local saves. Mode0 reads; mode1 accepts one complete write
// per handle. Repeated-write/append semantics remain unsupported. The opaque
// operation address is tracked privately; no guessed SDK fields are written.
int __cdecl UPLAY_SAVE_GetSavegames(void** game_list, void* operation);
int __cdecl UPLAY_SAVE_Open(uint32_t slot, uint32_t mode, uint32_t* handle, void* operation);
int __cdecl UPLAY_SAVE_Read(uint32_t handle, uint32_t size, uint32_t offset,
                          LocalPlatformBuffer* buffer, uint32_t* bytes_read, void* operation);
int __cdecl UPLAY_SAVE_Write(uint32_t handle, uint32_t size,
                           const LocalPlatformBuffer* buffer, void* operation);
int __cdecl UPLAY_SAVE_SetName(uint32_t handle, const char* name);
int __cdecl UPLAY_SAVE_Close(uint32_t handle);
int __cdecl UPLAY_SAVE_Remove(uint32_t slot, void* operation);
void __cdecl UPLAY_SAVE_ReleaseGameList(void* game_list);
}
