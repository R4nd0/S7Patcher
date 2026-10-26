#pragma once

#if !defined(_WIN32) || !defined(_M_IX86)
#error The verified offline bootstrap requires Windows x86.
#endif

struct OfflineBootstrapConfig {
    unsigned short udp_port;
    const char* public_key_base64;
    const char* local_ticket;
};

// Startup only, before the relevant game constructors execute. Copies inputs.
// Does not perform network operations, initialize game objects or launch a game.
// Repeated initialization is rejected; the adapter must remain loaded afterward.
bool InitializeOfflineBootstrap(const OfflineBootstrapConfig& config);

// Fixed diagnostic text only; never contains config, identity or native values.
const char* GetOfflineBootstrapError();
