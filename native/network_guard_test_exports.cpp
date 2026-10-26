// Separate DLL so the synthetic host's import table can be patched without
// recursively redirecting the guard's own operating-system calls.
#include "network_guard.h"
extern "C" __declspec(dllexport) bool __cdecl S7TestInstallGuard() {
    return InstallOfflineNetworkGuard();
}
extern "C" __declspec(dllexport) bool __cdecl S7TestEndpoint(const sockaddr* address, int length) {
    return IsOfflineEndpointAllowed(address, length);
}
