#pragma once
#include <winsock2.h>

// First offline prototype is loopback-only. LAN routing is a separate capability.
bool IsOfflineEndpointAllowed(const sockaddr* address, int length);
bool InstallOfflineNetworkGuard();
