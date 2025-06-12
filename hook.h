#pragma once
/// \file
/// \brief Hook helpers and global hook state.

using GetEntryPointFn = char(__stdcall*)(VacModuleInfo_t*, char);
GetEntryPointFn oGetEntryPoint = nullptr;

using Call_t = VacModuleResult_t(__fastcall*)(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unID, int nC, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize);
Call_t oCall = nullptr;

using PFN_LoadLibraryExW = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
static PFN_LoadLibraryExW oLoadLibraryExW = nullptr;

/** Simple RAII wrapper around the MinHook API. */
class MinHookGuard {
public:
    MinHookGuard() : initialized(MH_Initialize() == MH_OK) {}
    ~MinHookGuard() { if (initialized) MH_Uninitialize(); }
    bool ok() const { return initialized; }
private:
    bool initialized;
};
static MinHookGuard g_MinHook;
