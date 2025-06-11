#include "hooks.h"
#include "util.h"
#include "icekey.h"
#include "vacstructs.h"
#include "module_utils.h"
#include <MinHook.h>
#include <array>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <format>
#include <iostream>
#include <cwchar>

#if _WIN64
#pragma comment(lib,"libMinHook.x64.lib")
#else
#pragma comment(lib,"libMinHook.x86.lib")
#endif

using RunFunc_t = int(__stdcall*)(int, void*, unsigned int, void*, unsigned int*);
static RunFunc_t oRunFunc = nullptr;
using GetEntryPointFn = char(__stdcall*)(VacModuleInfo_t*, char);
static GetEntryPointFn oGetEntryPoint = nullptr;
using Call_t = VacModuleResult_t(__fastcall*)(void*, void*, unsigned int, unsigned char, int, int, unsigned int, int, void*, unsigned int, void*, unsigned int*);
static Call_t oCall = nullptr;
using PFN_LoadLibraryExW = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
static PFN_LoadLibraryExW oLoadLibraryExW = nullptr;

static std::unordered_map<uint32_t, std::array<uint8_t, 16>> g_IceKeys;
static std::unordered_set<uint32_t> g_Dumped;
static std::unordered_set<uint32_t> g_SavedKeys;
static std::mutex g_Mtx;

std::string dumpPath = "C:\\Lumina";

char __stdcall hkGetEntryPoint(VacModuleInfo_t* pModule, char flags)
{
    bool bOriginalReturn = oGetEntryPoint(pModule, flags);
    printf("--------------------------------------");
    printf("[+] GetVacModuleEntrypointHook : start");
    printf("[+] : iFlags\t%d\n", flags);
    printf("[+] : m_unCRC32\t%p\n", pModule->m_unCRC32);
    printf("[+] : m_pRunFunc\t%p\n", pModule->m_pRunFunc);
    printf("[+] : m_nModuleSize\t%p\n", pModule->m_nModuleSize);
    printf("[+] : m_pRawModule\t%p\n", pModule->m_pRawModule);
    printf("[+] : m_nLastResult\t%d\n", pModule->m_nLastResult);
    printf("[+] : m_nUnknFlag_0\t%d\n", pModule->m_nUnknFlag_0);
    printf("[+] : m_nUnknFlag_1\t%d\n", pModule->m_nUnknFlag_1);
    if (pModule->m_pModule != nullptr) {
        printf("[+] : m_pModule->m_pIAT\t%p\n", pModule->m_pModule->m_pIAT);
        printf("[+] : m_pNTHeaders->m_pOldIAT\t%p\n", pModule->m_pModule->m_pNTHeaders->OptionalHeader.DataDirectory[13].VirtualAddress);
        printf("[+] : m_pModule->m_pModuleBase\t%p\n", pModule->m_pModule->m_pModuleBase);
        printf("[+] : m_pModule->m_pNTHeaders\t%p\n", pModule->m_pModule->m_pNTHeaders);
        printf("[+] : m_pModule->m_nImportedLibraryCount\t%p\n", pModule->m_pModule->m_nImportedLibraryCount);
        printf("[+] : m_pModule->m_nRunFuncExportFunctionOrdinal\t%p\n", pModule->m_pModule->m_nRunFuncExportFunctionOrdinal);
        printf("[+] : m_pModule->m_nRunFuncExportModuleOrdinal\t%p\n", pModule->m_pModule->m_nRunFuncExportModuleOrdinal);
    }
    printf("--------------------------------------\n");
    if (bOriginalReturn && pModule->m_pRunFunc) {
        //DumpVacModule(pModule);
    }
    return bOriginalReturn;
}

VacModuleResult_t __fastcall hkCall(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unActionID, int nC, void* pInData,
                                   unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize)
{
    unFlags &= ~0x02;
    unsigned char* pIn = reinterpret_cast<unsigned char*>(pInData);
    if (pIn) {
        auto Keys = g_IceKeys.find(unHash);
        if (Keys == g_IceKeys.end()) {
            auto vKeys = std::array<unsigned char, 16>();
            memcpy(vKeys.data(), pIn + 0x10, 16);
            printf(" -> FKey        = %02X %02X %02X %02X %02X %02X %02X %02X\n", vKeys[0], vKeys[1], vKeys[2], vKeys[3], vKeys[4], vKeys[5], vKeys[6], vKeys[7]);
            printf(" -> SKey        = %02X %02X %02X %02X %02X %02X %02X %02X\n", vKeys[8], vKeys[9], vKeys[10], vKeys[11], vKeys[12], vKeys[13], vKeys[14], vKeys[15]);
            g_IceKeys.insert(std::pair<unsigned int, std::array<unsigned char, 16>>(unHash, std::move(vKeys)));
            std::filesystem::create_directories(dumpPath);
            std::ofstream f(std::format("{}\\icekey_{:08X}.txt", dumpPath, unHash));
            for (int i = 0; i < 8; ++i)
                f << std::format("{:02X}{}", vKeys[i], i == 7 ? "" : " ");
            f << '\n';
        } else {
            memcpy(Keys->second.data(), pIn + 0x10, 16);
        }
    }
    VacModuleResult_t unResult = oCall(pThis, pEDX, unHash, unFlags, nA, nB, unActionID, nC, pInData, unInDataSize, pOutData, pOutDataSize);
    printf("[DumpVAC] PostCallFunctionAsyncInternal\n");
    printf(" -> (this)      = 0x%08X\n", reinterpret_cast<unsigned int>(pThis));
    printf(" -> Hash        = 0x%08X\n", unHash);
    printf(" -> Flags       = 0x%02X\n", unFlags);
    printf(" -> ActionID    = 0x%08X\n", unActionID);
    printf(" -> InData      = 0x%08X\n", reinterpret_cast<unsigned int>(pInData));
    printf(" -> InDataSize  = 0x%08X\n", unInDataSize);
    printf(" -> OutData     = 0x%08X\n", reinterpret_cast<unsigned int>(pOutData));
    printf(" -> OutDataSize = 0x%08X\n", pOutDataSize ? *pOutDataSize : 0x00000000ui32);
    printf(" -> Result      = 0x%08X\n", unResult);
    return unResult;
}

HMODULE WINAPI LoadLibraryExWHk(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    if (wcsstr(lpLibFileName, L".tmp"))
    {
        wchar_t dst[MAX_PATH];
        const wchar_t* fname = wcsrchr(lpLibFileName, L'\\');
        fname = fname ? fname + 1 : lpLibFileName;
        const wchar_t* under = wcsrchr(fname, L'_');
        unsigned crc = 0xDEADBEEF;
        if (under && wcslen(under) >= 5)
            crc = std::wcstoul(under + 1, nullptr, 16);
        else {
            wchar_t tmp[5]{};
            wcsncpy_s(tmp, fname, 4);
            crc = std::wcstoul(tmp, nullptr, 16);
        }
        swprintf_s(dst, L"%hs\\vac_%08X.dll", dumpPath.c_str(), crc);
        std::filesystem::create_directories(dumpPath);
        if (!CopyFileW(lpLibFileName, dst, FALSE))
            wprintf(L"[!] CopyFile falhou (%u) %ls → %ls\n", GetLastError(), lpLibFileName, dst);
    }
    return oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

DWORD WINAPI InitHook(LPVOID)
{
    uintptr_t entry = util::get_sig("steamservice.dll", "55 8B EC 83 EC 24 53 56 8B 75 08 8B D9");
    if (!entry)
    {
        std::cout << "[!] entry não encontrado!\n";
        return 1;
    }
    std::cout << "[*] entry encontrado em: 0x" << std::hex << entry << std::endl;
    uintptr_t call_hook = util::get_sig("steamservice.dll", "55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC ? 53 56 57 89 65 ? 8B F9");
    if (!call_hook)
    {
        std::cout << "[!] call_hook não encontrado!\n";
        return 1;
    }
    std::cout << "[*] call_hook encontrado em: 0x" << std::hex << call_hook << std::endl;
    if (MH_Initialize() != MH_OK)
        return 1;
    if (MH_CreateHook(reinterpret_cast<void*>(entry), &hkGetEntryPoint, reinterpret_cast<void**>(&oGetEntryPoint)) != MH_OK)
        return 1;
    if (MH_EnableHook(reinterpret_cast<void*>(entry)) != MH_OK)
        return 1;
    if (MH_CreateHook(reinterpret_cast<void*>(call_hook), &hkCall, reinterpret_cast<void**>(&oCall)) != MH_OK)
        return 1;
    if (MH_EnableHook(reinterpret_cast<void*>(call_hook)) != MH_OK)
        return 1;
    MH_CreateHookApi(L"kernel32", "LoadLibraryExW", &LoadLibraryExWHk, (void**)&oLoadLibraryExW);
    MH_EnableHook(MH_ALL_HOOKS);
    printf("[+] Hook instalado: LoadLibraryExW\n");
    std::cout << "[+] Hook instalado: GetEntryPoint @ 0x" << std::hex << entry << std::endl;
    std::cout << "[+] Hook instalado: CClientModuleManager::LoadModule @ 0x" << std::hex << call_hook << std::endl;
    return 0;
}

void OpenDebugConsole()
{
    if (AllocConsole())
    {
        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        std::ios::sync_with_stdio();
        std::cout.clear();
        std::clog.clear();
        std::cerr.clear();
        std::cin.clear();
        std::cout << "[+] Console inicializado.\n";
    }
    else
    {
        MessageBoxA(nullptr, "Erro ao alocar console!", "Erro", MB_ICONERROR);
    }
}
