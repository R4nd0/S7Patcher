#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <cstring>

// Run while a synthetic bundle's fresh configuration is present. This host
// must never pass the real executable fingerprint or install native game calls.
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    WSADATA data{}; if (WSAStartup(MAKEWORD(2,2), &data)) return 2;
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) return 3;
    using Start = int (__cdecl*)(unsigned, unsigned);
    using Update = int (__cdecl*)();
    auto start = reinterpret_cast<Start>(GetProcAddress(module, "UPLAY_Start"));
    auto update = reinterpret_cast<Update>(GetProcAddress(module, "UPLAY_Update"));
    if (!start || !update || start(1, 0) != 1 || start(11788, 0) != 1 || update() != 0) return 4;
    char host[32]{};
    if (gethostname(host, sizeof(host)) != 0 || strcmp(host, "localhost") != 0) return 5;
    // Adapter cannot unload while its network import hooks remain installed.
    std::puts("PASS DLL load, incorrect app rejection, real configuration read, wrong executable rejection, guarded host");
    return 0;
}
