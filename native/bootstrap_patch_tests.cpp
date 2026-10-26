// Exercise the actual patch writer/validator against owned synthetic memory.
// No game file is loaded and no native game function is ever called.
#include "offline_bootstrap.cpp"
#include <cstdio>
void ReportLocalStatus(const char*) {}
namespace {
std::vector<char> pump_trace;
unsigned char* pump_network = nullptr;
unsigned char* pump_owner = nullptr;
int pump_mode = 0;
int network_getter_calls = 0;
void* __cdecl FakeNetworkGetter() { ++network_getter_calls; return pump_network; }
void __fastcall FakeOwnerUpdate(void*, void*) {
    pump_trace.push_back('O');
    if (pump_mode == 8) *Native<unsigned char**>(0x1379E14) = nullptr;
}
void __fastcall FakeMasterUpdate(void*, void*) {
    pump_trace.push_back('M');
    PumpOfflineBootstrap(); // Recursive bridge entry must be ignored.
    if (pump_mode == 2) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 3) *reinterpret_cast<void**>(pump_network + 0xa18) = nullptr;
    if (pump_mode == 4) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
}
NativeResult* __fastcall FakeCoreUpdate(void*, void*, NativeResult* result, unsigned int phase) {
    pump_trace.push_back(phase == 3 ? 'C' : '!');
    if (pump_mode == 1 || pump_mode == 8) UpdateLocalGame(pump_owner, nullptr);
    if (pump_mode == 5) *Native<unsigned char**>(0x1379E14) = nullptr;
    if (pump_mode == 6) *reinterpret_cast<void**>(pump_network + 0xa18) = nullptr;
    if (pump_mode == 7) *reinterpret_cast<void**>(pump_network + 0x2c) = nullptr;
    result->code = 1; result->detail = 0;
    return result;
}
bool FakeJump(uintptr_t address, const void* target) {
    auto* bytes = Native<unsigned char*>(address);
    DWORD old = 0;
    if (!VirtualProtect(bytes, 5, PAGE_EXECUTE_READWRITE, &old)) return false;
    bytes[0] = 0xe9;
    uint32_t relative = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(target)) -
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(bytes) + 5);
    memcpy(bytes + 1, &relative, 4);
    return FlushInstructionCache(GetCurrentProcess(), bytes, 5) != FALSE;
}
}
int main() {
    int failures = 0, checks = 0;
    auto check = [&](bool result) { ++checks; if (!result) ++failures; };
    auto* memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, ExpectedImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return 2;
    image_base = reinterpret_cast<uintptr_t>(memory);
    local_connect_probe = true;
    std::vector<const Patch*> selected;
    for (const auto& patch : Patches) selected.push_back(&patch);
    for (const auto& patch : ConnectPatches) selected.push_back(&patch);
    for (const auto* patch : selected) {
        auto* at = PatchAddress(*patch);
        const size_t length = patch->pointer_slot ? 4 : 5;
        at[-1] = 0xa5; at[length] = 0x5a;
        if (patch->pointer_slot) {
            uint32_t original = OriginalPointer(*patch); memcpy(at, &original, 4);
        } else memcpy(at, patch->original, length);
    }
    DWORD old = 0;
    if (!VirtualProtect(memory, ExpectedImageSize, PAGE_READONLY, &old)) return 2;
    check(Install());
    for (const auto* patch : selected) {
        auto* at = PatchAddress(*patch);
        const size_t length = patch->pointer_slot ? 4 : 5;
        check(at[-1] == 0xa5 && at[length] == 0x5a);
        uint32_t actual = 0;
        if (patch->pointer_slot) memcpy(&actual, at, 4);
        else { check(at[0] == 0xe8); memcpy(&actual, at + 1, 4); actual += static_cast<uint32_t>(reinterpret_cast<uintptr_t>(at) + 5); }
        check(actual == reinterpret_cast<uintptr_t>(patch->replacement));
        MEMORY_BASIC_INFORMATION info{};
        check(VirtualQuery(at, &info, sizeof(info)) && info.Protect == PAGE_READONLY);
        check(WritePatch(*patch, true));
        if (patch->pointer_slot) { memcpy(&actual, at, 4); check(actual == OriginalPointer(*patch)); }
        else check(memcmp(at, patch->original, length) == 0);
    }
    // Change the last pointer guard: the preflight must fail before any earlier
    // CALL is rewritten, regardless of which optional patches were selected.
    const Patch& last = *selected.back();
    auto* at = PatchAddress(last);
    VirtualProtect(at, 4, PAGE_READWRITE, &old);
    uint32_t bad = 0; memcpy(at, &bad, 4);
    DWORD ignored = 0; VirtualProtect(at, 4, old, &ignored);
    check(!Install() && error_code == ChangedCallsite);
    for (const auto& patch : Patches) check(memcmp(PatchAddress(patch), patch.original, 5) == 0);
    // Baseline mode ignores the opt-in table and keeps its original three hooks.
    local_connect_probe = false;
    check(Install());
    memcpy(&bad, at, 4); check(bad == 0);
    for (const auto& patch : Patches) check(WritePatch(patch, true));
    // Pump gating must not call any game function on the disabled path, a
    // foreign thread, recursion, a resumed natural tick or incomplete objects.
    initialization = 2;
    bootstrap_thread = GetCurrentThreadId();
    PumpOfflineBootstrap(); check(!pump_active);
    local_connect_probe = true;
    bootstrap_thread = 0;
    PumpOfflineBootstrap(); check(!pump_active);
    bootstrap_thread = GetCurrentThreadId();
    pump_active = true;
    PumpOfflineBootstrap(); check(pump_active);
    pump_active = false; natural_updates_seen = true;
    PumpOfflineBootstrap(); check(!pump_active);
    natural_updates_seen = false;
    PumpOfflineBootstrap(); check(!pump_active); // Null network.
    VirtualProtect(memory, ExpectedImageSize, PAGE_READWRITE, &old);
    // The local-start decision is scoped to its exact platform instance,
    // thread and explicit opt-in. It never changes the platform's offline bit.
    alignas(4) unsigned char policy[0x84]{};
    *Native<void**>(0x13789D0) = policy;
    check(SkipLocalNetworkStartup(nullptr, nullptr));
    check(SkipLocalNetworkStartup(policy, nullptr)); // Unknown platform type.
    *reinterpret_cast<uintptr_t*>(policy) = image_base + 0x112BE3C - PreferredBase;
    policy[0x80] = 1;
    check(!SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 1);
    local_connect_probe = false;
    check(SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 1);
    local_connect_probe = true; initialization = 1;
    check(SkipLocalNetworkStartup(policy, nullptr));
    initialization = 2; bootstrap_thread = 0;
    check(SkipLocalNetworkStartup(policy, nullptr));
    bootstrap_thread = GetCurrentThreadId();
    *Native<void**>(0x13789D0) = nullptr;
    check(SkipLocalNetworkStartup(policy, nullptr));
    *Native<void**>(0x13789D0) = policy;
    policy[0x80] = 0;
    check(!SkipLocalNetworkStartup(policy, nullptr) && policy[0x80] == 0);
    *Native<void**>(0x13789D0) = nullptr;
    alignas(4) unsigned char network[0xa1c]{};
    alignas(4) unsigned char owner[0x2a8]{};
    *Native<unsigned char**>(0x1379E14) = network;
    PumpOfflineBootstrap(); check(!pump_active); // Null owner.
    *reinterpret_cast<unsigned char**>(network + 0xa18) = owner;
    PumpOfflineBootstrap(); check(!pump_active); // Wrong owner table.
    *reinterpret_cast<uintptr_t*>(owner) = image_base + 0x10919BC - PreferredBase;
    PumpOfflineBootstrap(); check(!pump_active); // Wrong RV table.
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = image_base + 0x109C9D8 - PreferredBase;
    PumpOfflineBootstrap(); check(!pump_active); // Missing facade.
    *reinterpret_cast<void**>(owner + 0xa4) = owner;
    PumpOfflineBootstrap(); check(!pump_active); // Missing update dependencies.
    alignas(4) unsigned char facade[0x24]{};
    *reinterpret_cast<void**>(owner + 0xa4) = facade;
    check(!LocalConnectionReady(nullptr) && !LocalConnectionReady(owner));
    check(!LocalConnectionReady(network)); // Disconnected.
    owner[0x88] = 1; owner[0x98] = 1;
    check(!LocalConnectionReady(network)); // Pending cannot claim readiness.
    owner[0x98] = 0;
    check(LocalConnectionReady(network));
    local_connect_probe = false;
    check(!LocalConnectionReady(network));
    local_connect_probe = true; initialization = 1;
    check(!LocalConnectionReady(network));
    initialization = 2;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!LocalConnectionReady(network)); // Borrowed Ubi facade is not local.
    *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = 0;
    check(!LocalConnectionReady(network));
    *reinterpret_cast<uintptr_t*>(owner + 0x50) = image_base + 0x109C9D8 - PreferredBase;
    *reinterpret_cast<uintptr_t*>(owner) = 0;
    check(!LocalConnectionReady(network));

    // Exercise the production pump against synthetic native objects and x86
    // trampoline stubs. This verifies actual calling conventions, dispatch
    // order, fallback suppression and callback-driven teardown, without S7.
    *reinterpret_cast<uintptr_t*>(owner) = image_base + 0x10919BC - PreferredBase;
    *reinterpret_cast<void**>(owner + 0x100) = owner;
    *reinterpret_cast<void**>(owner + 0x104) = owner;
    *reinterpret_cast<void**>(owner + 0x110) = owner;
    owner[0x78] = 1; // A real connection is already requested in this fixture.
    pump_network = network; pump_owner = owner;
    check(FakeJump(0xE82240, reinterpret_cast<const void*>(&FakeNetworkGetter)));
    check(FakeJump(0xC956C0, reinterpret_cast<const void*>(&FakeOwnerUpdate)));
    check(FakeJump(0xED3BA0, reinterpret_cast<const void*>(&FakeMasterUpdate)));
    check(FakeJump(0xCBC710, reinterpret_cast<const void*>(&FakeCoreUpdate)));
    auto trace_is = [&](const char* expected) {
        return pump_trace.size() == strlen(expected) &&
            (pump_trace.empty() || memcmp(pump_trace.data(), expected, pump_trace.size()) == 0);
    };
    PumpOfflineBootstrap(); check(trace_is("O") && !pump_active);
    alignas(4) unsigned char core[0x24]{};
    alignas(4) unsigned char implementation[8]{};
    *reinterpret_cast<void**>(network + 0x2c) = core;
    check(!LocalUpdateCore(network)); // Unknown core type.
    *reinterpret_cast<uintptr_t*>(core) = image_base + 0x10940A0 - PreferredBase;
    check(!LocalUpdateCore(network)); // Master not constructed.
    *reinterpret_cast<uintptr_t*>(network + 0x5c) = image_base + 0x1091E3C - PreferredBase;
    check(!LocalUpdateCore(network)); // Master not registered with the core.
    *reinterpret_cast<void**>(network + 0x5c + 0x4c0) = core;
    check(!LocalUpdateCore(network)); // Missing implementation.
    *reinterpret_cast<void**>(core + 0x20) = implementation;
    check(!LocalUpdateCore(network)); // Unknown implementation type.
    *reinterpret_cast<uintptr_t*>(implementation) = image_base + 0x1099548 - PreferredBase;
    check(!LocalUpdateCore(network)); // Missing scheduler.
    *reinterpret_cast<void**>(implementation + 4) = implementation;
    check(LocalUpdateCore(network) == core);
    udp_port = 10001;
    check(!LocalSessionSearchReady(network)); // No successful native startup.
    network[0x5c + 0x4c4] = 1;
    owner[0x18] = 1; owner[0x38] = 1;
    *reinterpret_cast<int32_t*>(owner + 0x28) = 1;
    check(!LocalSessionSearchReady(network)); // Missing search helper.
    *reinterpret_cast<void**>(owner + 0x108) = owner;
    check(LocalSessionSearchReady(network) && owner[0x3a] == 0);
    for (auto* flag : {network + 0x5c + 0x4c4, owner + 0x18, owner + 0x38, owner + 0x88}) {
        *flag = 0; check(!LocalSessionSearchReady(network)); *flag = 1;
    }
    for (int32_t result : {-1, 0, 2}) {
        *reinterpret_cast<int32_t*>(owner + 0x28) = result;
        check(!LocalSessionSearchReady(network));
    }
    *reinterpret_cast<int32_t*>(owner + 0x28) = 1;
    owner[0x249] = 1; check(!LocalSessionSearchReady(network)); owner[0x249] = 0;
    owner[0x98] = 1; check(!LocalSessionSearchReady(network)); owner[0x98] = 0;
    udp_port = 0; check(!LocalSessionSearchReady(network)); udp_port = 10001;
    local_connect_probe = false; check(!LocalSessionSearchReady(network)); local_connect_probe = true;
    bootstrap_thread = 0; check(!LocalSessionSearchReady(network)); bootstrap_thread = GetCurrentThreadId();
    *reinterpret_cast<void**>(network + 0x2c) = nullptr;
    check(!LocalSessionSearchReady(network)); *reinterpret_cast<void**>(network + 0x2c) = core;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!LocalSessionSearchReady(network)); *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    check(!LocalSessionSearchReady(nullptr) && !LocalSessionSearchReady(owner));
    check(LocalSessionSearchReady(network) && owner[0x3a] == 0);
    // Check the returned native small-string layout, surrounding stack memory
    // and thiscall/fastcall callee cleanup through the actual patched target.
    struct SandboxFixture { uint32_t before; NativeSmallString value; uint32_t after; } sandbox;
    memset(&sandbox, 0xa5, sizeof(sandbox));
    using SandboxGetter = NativeSmallString* (__thiscall*)(void*, NativeSmallString*);
    check(FakeJump(0xD43F50, reinterpret_cast<const void*>(&GetLocalSearchSandbox)));
    for (int iteration = 0; iteration < 3; ++iteration) {
        check(Native<SandboxGetter>(0xD43F50)(owner + 0x50, &sandbox.value) == &sandbox.value);
        check(sandbox.before == 0xa5a5a5a5 && sandbox.after == 0xa5a5a5a5);
        check(sandbox.value.length == 0 && sandbox.value.capacity == 15 &&
            sandbox.value.inline_data[0] == 0 && sandbox.value.inline_data[15] == 0);
    }
    const auto unchanged = sandbox;
    check(!ConstructLocalSearchSandbox(nullptr, &sandbox.value));
    check(!ConstructLocalSearchSandbox(owner, &sandbox.value));
    check(!ConstructLocalSearchSandbox(owner + 0x50, nullptr));
    bootstrap_thread = 0;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    bootstrap_thread = GetCurrentThreadId(); local_connect_probe = false;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    local_connect_probe = true; initialization = 1;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    initialization = 2; owner[0x98] = 1;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    owner[0x98] = 0; *reinterpret_cast<void**>(facade + 0x0c) = owner;
    check(!ConstructLocalSearchSandbox(owner + 0x50, &sandbox.value));
    *reinterpret_cast<void**>(facade + 0x0c) = nullptr;
    check(memcmp(&sandbox, &unchanged, sizeof(sandbox)) == 0);
    for (int mode = 0; mode <= 8; ++mode) {
        pump_mode = mode; pump_trace.clear(); network_getter_calls = 0;
        *Native<unsigned char**>(0x1379E14) = network;
        *reinterpret_cast<void**>(network + 0xa18) = owner;
        *reinterpret_cast<void**>(network + 0x2c) = core;
        PumpOfflineBootstrap();
        check(trace_is(mode < 2 || mode == 8 ? "MCO" : mode < 5 ? "M" : "MC"));
        check(!pump_active && !natural_updates_seen);
        if (mode == 8) check(network_getter_calls == 1); // No post-destruction owner work.
    }
    *Native<unsigned char**>(0x1379E14) = network;
    *reinterpret_cast<void**>(network + 0xa18) = owner;
    *reinterpret_cast<void**>(network + 0x2c) = core;
    pump_mode = 0;
    pump_trace.clear(); natural_updates_seen = true;
    PumpOfflineBootstrap(); check(trace_is(""));
    natural_updates_seen = false; bootstrap_thread = 0;
    PumpOfflineBootstrap(); check(trace_is(""));
    bootstrap_thread = GetCurrentThreadId(); local_connect_probe = false;
    PumpOfflineBootstrap(); check(trace_is(""));
    local_connect_probe = true;
    *reinterpret_cast<void**>(facade + 0x0c) = owner;
    PumpOfflineBootstrap(); check(trace_is("")); // Never pump a borrowed Ubi facade.
    *Native<unsigned char**>(0x1379E14) = nullptr;
    VirtualFree(memory, 0, MEM_RELEASE);
    std::printf("%s %d bootstrap patch checks\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
