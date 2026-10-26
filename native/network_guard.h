#pragma once
#include <winsock2.h>

// First offline prototype is loopback-only. LAN routing is a separate capability.
bool IsOfflineEndpointAllowed(const sockaddr* address, int length);
bool InstallOfflineNetworkGuard();
// Startup-only, immutable explicit two-peer mode. Does not permit general LAN access.
bool ConfigureLanNetworkGuard(const char* local, const char* peer);
