#pragma once
#include <cstdint>
#include <cstring>

// Canonical RFC1918 dotted decimal only. No DNS, abbreviated numbers or subnet allowlist.
inline bool ParsePrivateLanAddress(const char* text, uint32_t& host_order) {
    host_order = 0;
    if (!text) return false;
    const char* cursor = text;
    for (int part = 0; part < 4; ++part) {
        const char* begin = cursor;
        unsigned value = 0;
        while (*cursor >= '0' && *cursor <= '9') {
            if (cursor - begin >= 3) return false;
            value = value * 10 + *cursor++ - '0';
        }
        if (begin == cursor || value > 255 || (cursor - begin > 1 && *begin == '0')) return false;
        host_order = (host_order << 8) | value;
        if (part < 3) { if (*cursor++ != '.') return false; }
        else if (*cursor != '\0' || value == 0 || value == 255) return false;
    }
    return (host_order >> 24) == 10 || (host_order >> 20) == 0xac1
        || (host_order >> 16) == 0xc0a8;
}

inline bool ValidLanPair(const char* local, const char* peer) {
    uint32_t left = 0, right = 0;
    return ParsePrivateLanAddress(local, left) && ParsePrivateLanAddress(peer, right) && left != right;
}
