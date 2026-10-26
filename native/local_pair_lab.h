#pragma once
#ifdef S7_LOCAL_PAIR_LAB
#include <atomic>
#include <cstdint>
// Set only after a complete known laboratory executable hash matches.
// Host-order IPv4; the two copies can independently bind the same UDP ports.
inline std::atomic<uint32_t> local_pair_bind{0x7f000001u};
#endif
