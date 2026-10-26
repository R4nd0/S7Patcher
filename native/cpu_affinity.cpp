// Upstream AFF patch uses SetProcessAffinityMask and removes the main-thread
// CPU-0 pin. Resolve physical cores here instead of its signed 8-bit constant.
#define WIN32_LEAN_AND_MEAN
#include "cpu_affinity.h"
#include <algorithm>
#include <cstring>

DWORD_PTR SelectLocalCpuMask(std::vector<LocalCpuCore> cores, DWORD_PTR allowed) {
    DWORD_PTR seen = 0;
    for (const auto& core : cores) {
        if (!core.mask || (seen & core.mask)) return 0;
        seen |= core.mask;
    }
    // On hybrid CPUs Windows assigns higher classes to faster cores.
    std::stable_sort(cores.begin(), cores.end(), [](const auto& a, const auto& b) {
        return a.efficiency > b.efficiency;
    });
    DWORD_PTR selected = 0;
    unsigned count = 0;
    for (const auto& core : cores) {
        DWORD_PTR eligible = core.mask & allowed;
        if (eligible) {
            selected |= eligible & (~eligible + 1); // One logical CPU per core.
            if (++count == 4) break;
        }
    }
    return selected;
}

bool ApplyLocalCpuAffinity() {
    HANDLE process = GetCurrentProcess();
    DWORD_PTR previous = 0, system = 0;
    if (!GetProcessAffinityMask(process, &previous, &system)) return false;
    USHORT groups = 1, group = 0;
    if (!GetProcessGroupAffinity(process, &groups, &group) || groups != 1) return false;
    DWORD length = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || !length || length > 1024 * 1024) return false;
    std::vector<unsigned char> bytes(length);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(bytes.data()), &length)) return false;
    std::vector<LocalCpuCore> cores;
    size_t offset = 0;
    while (offset < length) {
        if (length - offset < 8) return false;
        auto* item = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(bytes.data() + offset);
        const size_t prefix = offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor.GroupMask);
        if (item->Relationship != RelationProcessorCore || item->Size < prefix || item->Size > length - offset)
            return false;
        const auto& cpu = item->Processor;
        if (!cpu.GroupCount || cpu.GroupCount > (item->Size - prefix) / sizeof(GROUP_AFFINITY)) return false;
        for (WORD i = 0; i < cpu.GroupCount; ++i) {
            if (cpu.GroupMask[i].Group == group && cpu.GroupMask[i].Mask)
                cores.push_back({cpu.GroupMask[i].Mask, cpu.EfficiencyClass});
        }
        offset += item->Size;
    }
    DWORD_PTR selected = SelectLocalCpuMask(cores, previous & system);
    if (!selected || !SetProcessAffinityMask(process, selected)) return false;
    DWORD_PTR old_thread = SetThreadAffinityMask(GetCurrentThread(), selected);
    DWORD_PTR actual = 0, ignored = 0;
    if (old_thread && GetProcessAffinityMask(process, &actual, &ignored) && actual == selected) return true;
    // Restore the process first so restoring a previously wider thread mask is valid.
    SetProcessAffinityMask(process, previous);
    if (old_thread) SetThreadAffinityMask(GetCurrentThread(), old_thread);
    return false;
}
