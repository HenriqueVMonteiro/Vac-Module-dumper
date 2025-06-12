#pragma once
/// \file
/// \brief Helper functions for dumping and decrypting VAC modules.
#include <Windows.h>
#include <cstdint>
#include <vector>
#include "vacstructs.h"
#include <string>

/** Decrypts VAC module sections using the ICE key. */
bool DecryptVacModule(uint8_t* base, size_t imgSize, const uint8_t key[8]);

/** Writes the given module to disk. */
bool DumpVacModule(VacModuleInfo_t* m, const std::wstring& dumpDir = L"C:\\Lumina");

/** Fixes PE headers after dumping a module from memory. */
void FixVacModule(DWORD pImage, DWORD pModule);

/** Returns the total committed region size starting from an address. */
size_t GetAllocationSize(void* startAddress);
