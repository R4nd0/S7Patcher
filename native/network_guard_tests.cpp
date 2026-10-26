#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include "lan_address.h"
#include "transport_observation.h"
#include <cstdio>
#include <cstring>
#include <initializer_list>

extern "C" __declspec(dllimport) bool __cdecl S7TestInstallGuard();
extern "C" __declspec(dllimport) bool __cdecl S7TestEndpoint(const sockaddr*, int);
extern "C" __declspec(dllimport) bool __cdecl S7TestConfigureLan(const char*, const char*);
#ifdef S7_LOCAL_NETWORK_PUMP
extern "C" __declspec(dllimport) unsigned int __cdecl S7TestTransportObservations();
#endif
#ifdef S7_LOCAL_PAIR_LAB
extern "C" __declspec(dllimport) void __cdecl S7TestLabAddress(unsigned long);
#endif
static int checks = 0, failures = 0;
static void Check(bool result, const char* label) {
    ++checks; if (!result) { ++failures; std::printf("FAIL %s\n", label); }
}
static sockaddr_in Address(unsigned long number, unsigned short port = 0) {
    sockaddr_in value{}; value.sin_family = AF_INET;
    value.sin_addr.s_addr = htonl(number); value.sin_port = htons(port); return value;
}
static int Bound(SOCKET socket, sockaddr_in& address) {
    int length = sizeof(address); return getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length);
}
int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    {
        using namespace transport_observation;
        constexpr uint32_t local = 0xc0a80a0a, peer = 0xc0a80a14;
        Check(Send(peer, 3074, local, peer, true, true, true, false, false)
            == (port_3074 | target_peer | sent), "classify successful direct game send");
        Check(Send(local, 6200, local, peer, true, true, false, true, false)
            == (port_6200 | target_self | pending), "classify pending self send");
        Check(Send(0x7f000001, 9103, local, peer, true, false, false, false, true)
            == (port_9103 | target_loopback | bind_failed | access_denied), "classify loopback source failure");
        Check(Send(0xc0a80a15, 5555, local, peer, false, false, false, false, true)
            == (other_port | target_other | denied | access_denied), "classify rejected outside-pair destination");
        Check(Send(peer, 9111, local, peer, true, true, true, false, false) == 0,
            "coordinator packets cannot imply game transport");
        Check(Send(peer, 3074, local, peer, true, true, false, false, false)
            == (port_3074 | target_peer | other_error), "classify other socket failure");
        Check(Receive(peer, 3074, 5555, peer), "peer source game port receive");
        Check(Receive(peer, 5555, 3074, peer), "peer local game port receive");
        Check(!Receive(peer, 9111, 5555, peer), "coordinator receive is not game receive");
        Check(!Receive(local, 3074, 3074, peer), "self receive is not remote peer proof");
        Check(!Receive(0xc0a80a15, 3074, 3074, peer), "unrelated receive is not peer proof");
    }
    uint32_t parsed = 0;
    for (const char* invalid : {"", "10", "10.0.0", "010.0.0.1", "10.0.0.256", "10.0.0.1.", "10.0.0.0", "10.0.0.255", "127.0.0.1", "8.8.8.8", "172.15.1.1", "172.32.1.1", "192.169.1.1"})
        Check(!ParsePrivateLanAddress(invalid, parsed), "reject invalid LAN address");
    Check(ParsePrivateLanAddress("192.168.10.20", parsed) && parsed == 0xc0a80a14, "canonical LAN address");
    Check(!ValidLanPair("192.168.10.20", "192.168.10.20"), "reject identical LAN peers");
    WSADATA data{}; if (WSAStartup(MAKEWORD(2,2), &data) != 0) return 2;
    auto loopback = Address(0x7f000001), remote = Address(0xc0000201, 443); // RFC5737 documentation address.
    Check(!S7TestEndpoint(nullptr, 0), "null address rejected");
    Check(!S7TestEndpoint(reinterpret_cast<sockaddr*>(&loopback), 2), "short address rejected");
    Check(S7TestEndpoint(reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), "IPv4 loopback");
    Check(!S7TestEndpoint(reinterpret_cast<sockaddr*>(&remote), sizeof(remote)), "nonlocal address rejected");
    sockaddr_in6 ipv6{}; ipv6.sin6_family = AF_INET6; ipv6.sin6_addr = in6addr_loopback;
    Check(S7TestEndpoint(reinterpret_cast<sockaddr*>(&ipv6), sizeof(ipv6)), "IPv6 loopback");
    InetPtonA(AF_INET6, "::ffff:127.0.0.1", &ipv6.sin6_addr);
    Check(S7TestEndpoint(reinterpret_cast<sockaddr*>(&ipv6), sizeof(ipv6)), "IPv4 mapped loopback");
    InetPtonA(AF_INET6, "2001:db8::1", &ipv6.sin6_addr);
    Check(!S7TestEndpoint(reinterpret_cast<sockaddr*>(&ipv6), sizeof(ipv6)), "nonlocal IPv6 rejected");
    if (!S7TestInstallGuard()) { std::puts("FAIL guard install"); return 1; }
    Check(S7TestInstallGuard(), "install idempotent");
    char preflight[32]{};
    int preflight_result = gethostname(preflight, sizeof(preflight));
    std::printf("Preflight result=%d local=%d\n", preflight_result, strcmp(preflight, "localhost") == 0);
    if (preflight_result != 0 || strcmp(preflight, "localhost") != 0) return 3;
    addrinfo* info = nullptr;
    Check(getaddrinfo("example.invalid", "80", nullptr, &info) == EAI_NONAME && !info, "external DNS denied");
    Check(getaddrinfo("localhost", "80", nullptr, &info) == 0 && info, "local name resolution");
    if (info) freeaddrinfo(info);
    Check(gethostbyname("example.invalid") == nullptr, "legacy external DNS denied");
    Check(gethostbyname("localhost") != nullptr, "legacy local DNS");
    char host[32]{};
    Check(gethostname(host, sizeof(host)) == 0 && strcmp(host, "localhost") == 0, "local hostname");
    Check(gethostbyaddr(reinterpret_cast<char*>(&remote.sin_addr), 4, AF_INET) == nullptr, "external reverse DNS denied");
    Check(getnameinfo(reinterpret_cast<sockaddr*>(&remote), sizeof(remote), host, sizeof(host), nullptr, 0, 0) == EAI_NONAME,
          "external nameinfo denied");
    SOCKET server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DWORD timeout = 1000; setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    auto wildcard = Address(INADDR_ANY);
    Check(bind(server, reinterpret_cast<sockaddr*>(&wildcard), sizeof(wildcard)) == 0, "wildcard bind accepted locally");
    sockaddr_in bound{};
    Check(Bound(server, bound) == 0 && bound.sin_addr.s_addr == loopback.sin_addr.s_addr, "wildcard rewritten to loopback");
    Check(sendto(client, "abc", 3, 0, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == SOCKET_ERROR && WSAGetLastError() == WSAEACCES,
          "external UDP denied before transmission");
    Check(sendto(client, "abc", 3, 0, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 3, "local UDP send");
    sockaddr_in client_bound{};
    Check(Bound(client, client_bound) == 0 && client_bound.sin_addr.s_addr == loopback.sin_addr.s_addr, "implicit UDP sender binds locally");
    char buffer[16]{};
    Check(recvfrom(server, buffer, sizeof(buffer), 0, nullptr, nullptr) == 3 && memcmp(buffer, "abc", 3) == 0, "local UDP roundtrip");
    WSABUF packet{3, const_cast<char*>("xyz")}; DWORD sent = 0;
    Check(WSASendTo(client, &packet, 1, &sent, 0, reinterpret_cast<sockaddr*>(&remote), sizeof(remote), nullptr, nullptr) == SOCKET_ERROR
          && WSAGetLastError() == WSAEACCES, "overlapped external UDP denied");
    Check(WSASendTo(client, &packet, 1, &sent, 0, reinterpret_cast<sockaddr*>(&bound), sizeof(bound), nullptr, nullptr) == 0 && sent == 3,
          "WSASendTo local");
    Check(recvfrom(server, buffer, sizeof(buffer), 0, nullptr, nullptr) == 3 && memcmp(buffer, "xyz", 3) == 0, "WSASendTo roundtrip");
    DWORD returned = 0;
    Check(WSAIoctl(client, SIO_GET_EXTENSION_FUNCTION_POINTER, nullptr, 0, nullptr, 0, &returned, nullptr, nullptr) == SOCKET_ERROR
          && WSAGetLastError() == WSAEOPNOTSUPP, "unwrapped extension pointers denied");
    closesocket(client); closesocket(server);
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Check(bind(listener, reinterpret_cast<sockaddr*>(&wildcard), sizeof(wildcard)) == 0 && listen(listener, 1) == 0 && Bound(listener, bound) == 0,
          "local TCP listener");
    Check(connect(tcp, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == SOCKET_ERROR && WSAGetLastError() == WSAEACCES,
          "external TCP denied");
    bool connected = connect(tcp, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0;
    Check(connected, "local TCP connect");
    if (connected) {
        SOCKET accepted = accept(listener, nullptr, nullptr);
        Check(accepted != INVALID_SOCKET, "local TCP accept");
        if (accepted != INVALID_SOCKET) {
            setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            Check(send(tcp, "tcp", 3, 0) == 3 && recv(accepted, buffer, sizeof(buffer), 0) == 3 && memcmp(buffer, "tcp", 3) == 0,
                  "local TCP send roundtrip");
            closesocket(accepted);
        }
    }
    closesocket(tcp); closesocket(listener);
    HINTERNET session = WinHttpOpen(L"S7 synthetic test", WINHTTP_ACCESS_TYPE_NAMED_PROXY, L"example.invalid:8080", nullptr, 0);
    Check(session != nullptr, "WinHTTP opens with forced no proxy");
    Check(WinHttpConnect(session, L"example.invalid", 80, 0) == nullptr && GetLastError() == ERROR_ACCESS_DENIED, "external HTTP denied");
    HINTERNET connection = WinHttpConnect(session, L"localhost", 1, 0);
    Check(connection != nullptr, "local HTTP connection handle");
    Check(WinHttpOpenRequest(connection, L"GET", L"http://example.invalid/", nullptr, nullptr, nullptr, 0) == nullptr,
          "absolute external HTTP object denied");
    HINTERNET request = WinHttpOpenRequest(connection, L"GET", L"/", nullptr, nullptr, nullptr, 0);
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS, length = sizeof(redirect);
    Check(request && WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)), "redirect setting intercepted");
    Check(request && WinHttpQueryOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, &length) && redirect == WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
          "redirect remains disabled");
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
    Check(reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "open", "https://example.invalid/", nullptr, nullptr, SW_HIDE)) == SE_ERR_ACCESSDENIED,
          "external shell ANSI denied");
    Check(reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", L"https://example.invalid/", nullptr, nullptr, SW_HIDE)) == SE_ERR_ACCESSDENIED,
          "external shell Unicode denied");
#ifdef S7_LOCAL_PAIR_LAB
    S7TestLabAddress(0x7f000002);
    SOCKET left = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    auto bind_address = Address(0);
    Check(bind(left, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) == 0, "lab wildcard bind");
    sockaddr_in left_address{};
    Check(Bound(left, left_address) == 0 && ntohl(left_address.sin_addr.s_addr) == 0x7f000002, "lab A address");
    S7TestLabAddress(0x7f000003);
    SOCKET right = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    bind_address = Address(0x7f000001, ntohs(left_address.sin_port));
    Check(bind(right, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) == 0, "lab same port independent bind");
    sockaddr_in right_address{};
    Check(Bound(right, right_address) == 0 && ntohl(right_address.sin_addr.s_addr) == 0x7f000003, "lab B address");
    DWORD lab_timeout = 2000;
    setsockopt(left, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&lab_timeout), sizeof(lab_timeout));
    Check(sendto(right, "pair", 4, 0, reinterpret_cast<sockaddr*>(&left_address), sizeof(left_address)) == 4, "lab cross-address send");
    char lab_buffer[8]{};
    Check(recv(left, lab_buffer, sizeof(lab_buffer), 0) == 4 && memcmp(lab_buffer, "pair", 4) == 0, "lab cross-address receive");
    SOCKET automatic = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Check(sendto(automatic, "pair", 4, 0, reinterpret_cast<sockaddr*>(&left_address), sizeof(left_address)) == 4, "lab unbound send");
    sockaddr_in automatic_address{};
    Check(Bound(automatic, automatic_address) == 0 && ntohl(automatic_address.sin_addr.s_addr) == 0x7f000003, "lab automatic source address");
    closesocket(automatic); closesocket(right); closesocket(left);
    S7TestLabAddress(0x7f000001);
#endif
    Check(!S7TestConfigureLan("192.168.10.10", "8.8.8.8"), "invalid LAN configuration rejected");
    Check(S7TestConfigureLan("192.168.10.10", "192.168.10.20"), "explicit LAN configuration accepted");
    auto lan_peer = Address(0xc0a80a14), unrelated = Address(0xc0a80a15);
    Check(S7TestEndpoint(reinterpret_cast<sockaddr*>(&lan_peer), sizeof(lan_peer)), "exact peer allowed");
    Check(!S7TestEndpoint(reinterpret_cast<sockaddr*>(&unrelated), sizeof(unrelated)), "other LAN address rejected");
    Check(!S7TestConfigureLan("192.168.10.10", "192.168.10.21"), "LAN policy immutable");
    Check(gethostname(host, sizeof(host)) == 0 && strcmp(host, "192.168.10.10") == 0, "LAN hostname advertises local IP");
    auto* lan_host = gethostbyname("192.168.10.20");
    Check(lan_host && memcmp(lan_host->h_addr_list[0], &lan_peer.sin_addr, 4) == 0, "legacy DNS preserves explicit peer IP");
    Check(gethostbyname("192.168.10.21") == nullptr, "other LAN DNS rejected");
#ifdef S7_LOCAL_NETWORK_PUMP
    SOCKET diagnostic = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    unrelated.sin_port = htons(3074);
    const auto before = S7TestTransportObservations();
    Check(sendto(diagnostic, "x", 1, 0, reinterpret_cast<sockaddr*>(&unrelated), sizeof(unrelated)) == SOCKET_ERROR
        && WSAGetLastError() == WSAEACCES, "LAN send diagnostic preserves denial and last error");
    Check(S7TestTransportObservations() > before, "LAN diagnostic callback executed");
    const auto observed = S7TestTransportObservations();
    Check(WSASendTo(diagnostic, &packet, 1, &sent, 0, reinterpret_cast<sockaddr*>(&unrelated), sizeof(unrelated), nullptr, nullptr) == SOCKET_ERROR
        && WSAGetLastError() == WSAEACCES, "LAN overlapped diagnostic preserves denial and last error");
    Check(S7TestTransportObservations() == observed, "LAN labels bounded to once per category");
    closesocket(diagnostic);
#endif
    WSACleanup();
    std::printf("%s %d network guard checks\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
