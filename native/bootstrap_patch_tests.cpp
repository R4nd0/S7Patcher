// Exercise the actual patch writer/validator against owned synthetic memory.
// No game file is loaded and no native game function is ever called.
#include "offline_bootstrap.cpp"
#include <cstdio>
void ReportLocalStatus(const char*) {}
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
    VirtualFree(memory, 0, MEM_RELEASE);
    std::printf("%s %d bootstrap patch checks\n", failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
