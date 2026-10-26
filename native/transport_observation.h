#pragma once
#include <cstdint>

// Fixed categories only. No payload, descriptor, identity or address is logged.
namespace transport_observation {
enum : uint32_t {
    denied = 1u, bind_failed = 2u, port_3074 = 4u, port_6200 = 8u,
    port_9103 = 16u, other_port = 32u, target_self = 64u,
    target_peer = 128u, target_loopback = 256u, target_other = 512u,
    sent = 1024u, pending = 2048u, access_denied = 4096u,
    other_error = 8192u, received = 16384u
};
inline uint32_t Send(uint32_t target, uint16_t port, uint32_t local, uint32_t peer,
    bool allowed, bool bound, bool success, bool is_pending, bool is_access_denied) {
    // The coordinator uses this port; distinguish it from the native game link.
    if (port == 9111) return 0;
    uint32_t bits = !allowed ? denied : !bound ? bind_failed : 0u;
    bits |= port == 3074 ? port_3074 : port == 6200 ? port_6200
        : port == 9103 ? port_9103 : other_port;
    bits |= target == local ? target_self : target == peer ? target_peer
        : (target >> 24) == 127 ? target_loopback : target_other;
    bits |= success ? sent : is_pending ? pending : is_access_denied ? access_denied : other_error;
    return bits;
}
inline bool Receive(uint32_t source, uint16_t source_port, uint16_t local_port, uint32_t peer) {
    return source == peer && (source_port == 3074 || source_port == 6200 || source_port == 9103
        || local_port == 3074 || local_port == 6200 || local_port == 9103);
}
}
