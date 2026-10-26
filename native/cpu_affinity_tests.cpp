#define WIN32_LEAN_AND_MEAN
#include "cpu_affinity.h"
#include <cstdio>

int main() {
    unsigned checks = 0, failures = 0;
    auto check = [&](bool result) { ++checks; if (!result) ++failures; };
    check(SelectLocalCpuMask({}, 0xffff) == 0);
    check(SelectLocalCpuMask({{0,0}}, 0xffff) == 0);
    check(SelectLocalCpuMask({{3,0},{2,0}}, 0xffff) == 0);
    check(SelectLocalCpuMask({{3,0},{12,0},{48,0},{192,0},{768,0}}, 0xffff) == 0x55);
    check(SelectLocalCpuMask({{3,0},{12,0}}, 0xffff) == 5);
    check(SelectLocalCpuMask({{3,0},{12,0}}, 0x0a) == 0x0a);
    check(SelectLocalCpuMask({{3,0}}, 0) == 0);
    check(SelectLocalCpuMask({{1,0},{2,0},{4,0},{8,0},{16,0}}, 0xffff) == 15);
    check(SelectLocalCpuMask({{3,0},{12,1},{48,1},{192,1},{768,1}}, 0xffff) == 0x154);
    check(SelectLocalCpuMask({{0x80000000u,0}}, 0xffffffffu) == 0x80000000u);
    // This standalone child changes only its own affinity, never another process.
    DWORD_PTR before = 0, system = 0, after = 0;
    check(GetProcessAffinityMask(GetCurrentProcess(), &before, &system) != FALSE);
    check(ApplyLocalCpuAffinity());
    check(GetProcessAffinityMask(GetCurrentProcess(), &after, &system) != FALSE);
    unsigned count = 0;
    for (DWORD_PTR mask = after; mask; mask &= mask - 1) ++count;
    check(count >= 1 && count <= 4 && (after & ~before) == 0);
    std::printf("CPU affinity: %u checks, %u failures; %u selected logical CPUs, mask 0x%lx\n",
        checks, failures, count, static_cast<unsigned long>(after));
    return failures ? 1 : 0;
}
