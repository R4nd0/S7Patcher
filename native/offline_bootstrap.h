#pragma once

#if !defined(_WIN32) || !defined(_M_IX86)
#error The verified offline bootstrap requires Windows x86.
#endif

struct OfflineBootstrapConfig {
    unsigned short udp_port;
    const char* public_key_base64;
    const char* local_ticket;
    bool local_connect_probe = false;
    const char* server_address = "127.0.0.1";
};

// Startup only, before the relevant game constructors execute. Copies inputs.
// Does not perform network operations, initialize game objects or launch a game.
// Repeated initialization is rejected; the adapter must remain loaded afterward.
bool InitializeOfflineBootstrap(const OfflineBootstrapConfig& config);

// Optional local-connect experiment: use the startup thread's platform tick
// while the normal game network tick is absent. Never retains game pointers.
void PumpOfflineBootstrap();

// Fixed diagnostic text only; never contains config, identity or native values.
const char* GetOfflineBootstrapError();
