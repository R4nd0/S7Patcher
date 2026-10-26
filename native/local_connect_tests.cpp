#include "local_connect_policy.h"
#include <cstdio>
int main() {
    int failed = 0, checks = 0, calls = 0;
    auto check = [&](bool ok) { ++checks; if (!ok) ++failed; };
    unsigned char connected = 0, pending = 0, requested = 0;
    auto start = [&]() { ++calls; check(pending == 1 && connected == 0); };
    check(BeginLocalConnect(false, connected, pending, start) == LocalConnectUnavailable);
    check(pending == 0 && connected == 0 && calls == 0);
    check(BeginLocalConnect(true, connected, pending, start) == 2);
    check(calls == 1 && pending == 1 && connected == 0);
    check(BeginLocalConnect(true, connected, pending, start) == 2 && calls == 1);
    connected = 1;
    check(BeginLocalConnect(true, connected, pending, start) == 1 && calls == 1);
    connected = 0; pending = 0; // Real completion/failure callback resets state, not this policy.
    check(RequestLocalConnect(false, requested, [&](){ ++calls; return 2; }) == LocalConnectUnavailable);
    check(requested == 0 && calls == 1);
    check(RequestLocalConnect(true, requested, [&](){ check(requested == 1); return LocalConnectUnavailable; }) == LocalConnectUnavailable);
    check(requested == 0);
    check(RequestLocalConnect(true, requested, [&](){ return BeginLocalConnect(true, connected, pending, start); }) == 1);
    check(requested == 1 && pending == 1 && connected == 0 && calls == 2);
    check(RequestLocalConnect(true, requested, [&](){ ++calls; return 2; }) == 1 && calls == 2);
    pending = 0; // Native reconnect timer can retry a completed failed attempt.
    check(BeginLocalConnect(true, connected, pending, start) == 2 && calls == 3);
    std::printf("%s %d local connect state checks\n", failed ? "FAIL" : "PASS", checks);
    return failed ? 1 : 0;
}
