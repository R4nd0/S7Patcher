#pragma once
#include <stdint.h>

// Native result codes: 1 = operation accepted/already connected, 2 = pending.
// They do not assert that a server response or login has succeeded.
constexpr int32_t LocalConnectUnavailable = -1000000;
template<class StartJob>
int32_t BeginLocalConnect(bool ready, unsigned char& connected, unsigned char& pending, StartJob start) {
    if (!ready) return LocalConnectUnavailable;
    if (connected) return 1;
    if (!pending) {
        pending = 1; // Native callbacks must see pending before the job starts.
        start();
    }
    return 2;
}
template<class Connect>
int32_t RequestLocalConnect(bool ready, unsigned char& requested, Connect connect) {
    if (!ready) return LocalConnectUnavailable;
    if (!requested) {
        requested = 1;
        int32_t result = connect();
        if (result < 0) { requested = 0; return result; }
    }
    return 1;
}
