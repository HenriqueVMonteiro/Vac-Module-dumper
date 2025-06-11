#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include "vacstructs.h"

bool DecryptVacModule(uint8_t* base, size_t imgSize, const uint8_t key[8]);
bool DumpVacModule(VacModuleInfo_t* m, const std::wstring& dumpDir = L"C:\\Lumina");
void FixVacModule(DWORD pImage, DWORD pModule);
DWORD GetAllocationSize(DWORD startAddress);
