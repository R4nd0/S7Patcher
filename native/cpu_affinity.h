#pragma once
#include <windows.h>
#include <vector>

struct LocalCpuCore { DWORD_PTR mask; unsigned char efficiency; };
DWORD_PTR SelectLocalCpuMask(std::vector<LocalCpuCore> cores, DWORD_PTR allowed);
bool ApplyLocalCpuAffinity();
