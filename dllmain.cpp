// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include <iostream>
#include <cstdint>
#include <array>            
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <iterator>
#include <filesystem>
#include <fstream>
#include <format>
#include <assert.h>
#include <thread>

#include "util.h"
#include "icekey.h"
#include "vacstructs.h"
#include "module_utils.h"
#include <MinHook.h>

#if _WIN64
#pragma comment(lib,"libMinHook.x64.lib")
#else
#pragma comment(lib,"libMinHook.x86.lib")
#endif

using RunFunc_t = int(__stdcall*)(
	int stage,
	void* pHdr,            //  a2  (VacCtxHeader*)
	unsigned int len,      //  a3
	void* pBuf,            //  a4
	unsigned int* pOut);   //  a5
RunFunc_t oRunFunc = nullptr;

// função original
using GetEntryPointFn = char(__stdcall*)(VacModuleInfo_t*, char);
GetEntryPointFn oGetEntryPoint = nullptr;

using Call_t = VacModuleResult_t(__fastcall*)(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unID, int nC, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize);
Call_t oCall = nullptr;

using PFN_LoadLibraryExW = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
static PFN_LoadLibraryExW oLoadLibraryExW = nullptr;

std::unordered_map<uint32_t, std::array<uint8_t, 16>> g_IceKeys;

static const std::filesystem::path g_dumpPath = L"C:\\VacDump";

class MinHookGuard {
public:
    MinHookGuard() : initialized(MH_Initialize() == MH_OK) {}
    ~MinHookGuard() { if (initialized) MH_Uninitialize(); }
    bool ok() const { return initialized; }
private:
    bool initialized;
};
static MinHookGuard g_MinHook;

char __stdcall hkGetEntryPoint(VacModuleInfo_t* pModule, char flags)
{
	bool bOriginalReturn = oGetEntryPoint(pModule, flags);

	printf("--------------------------------------\n");
	printf("[ ModuleEntryPoint ] ");
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

	if (bOriginalReturn && pModule->m_pRunFunc)
	{
		//DumpVacModule(pModule);
	}
	return bOriginalReturn;
}

VacModuleResult_t __fastcall hkCall(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags, int nA, int nB, unsigned int unActionID, int nC, void* pInData,
	unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize)

{
	/* 1) força o vac usar LoadLibrary (clear bit 0x02) */
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

                        std::filesystem::create_directories(g_dumpPath);
                        std::ofstream f(std::filesystem::path(g_dumpPath) / std::format(L"icekey_{:08X}.txt", unHash));
			for (int i = 0; i < 8; ++i)
				f << std::format("{:02X}{}", vKeys[i], i == 7 ? "" : " ");

			f << '\n';
		}
		else {
			memcpy(Keys->second.data(), pIn + 0x10, 16);
		}
	}

	VacModuleResult_t unResult = oCall(pThis, pEDX, unHash, unFlags, nA, nB, unActionID, nC, pInData, unInDataSize, pOutData, pOutDataSize);

	printf("[ CClientModuleManager::LoadModule ]\n");
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

HMODULE WINAPI LoadLibraryExWHk(LPCWSTR lpLibFileName,
	HANDLE  hFile,
	DWORD   dwFlags)
{
	// 1) Se parecer vac_xxxx.tmp, copie imediatamente
        if (wcsstr(lpLibFileName, L".tmp"))
        {

		// tenta achar '_' antes da extensão; se não houver, usa o próprio nome
		const wchar_t* fname = wcsrchr(lpLibFileName, L'\\');
		fname = fname ? fname + 1 : lpLibFileName;        // só o arquivo

		const wchar_t* under = wcsrchr(fname, L'_');
		unsigned crc = 0xDEADBEEF;                        // fallback

		if (under && wcslen(under) >= 5)                  // "_XXXX.tmp"
			crc = std::wcstoul(under + 1, nullptr, 16);
		else {
			// usa quatro primeiros dígitos do nome (2304.tmp → 0x2304)
			wchar_t tmp[5]{};
			wcsncpy_s(tmp, fname, 4);
			crc = std::wcstoul(tmp, nullptr, 16);
		}

                auto dstPath = std::filesystem::path(g_dumpPath) / std::format(L"vac_{:08X}.dll", crc);
                std::filesystem::create_directories(g_dumpPath);
                if (!CopyFileW(lpLibFileName, dstPath.c_str(), FALSE))
                        wprintf(L"[!] CopyFile falhou (%u) %ls → %ls\n",
                                GetLastError(), lpLibFileName, dstPath.c_str());
	}

	// 2) chama a API original
	return oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}


void InitHook()
{
	if (!g_MinHook.ok())
		return;

	// @xref: pModule->m_pModule == NULL
	uintptr_t entry = util::get_sig("steamservice.dll", "55 8B EC 83 EC 24 53 56 8B 75 08 8B D9");

	if (!entry)
	{
		std::cout << "[!] entry não encontrado!\n";
		return;
	}
	std::cout << "[*] entry encontrado em: 0x" << std::hex << entry << std::endl;

	// @xref: pModule->m_nLastResult != k_ECallResultNone
	uintptr_t call_hook = util::get_sig("steamservice.dll", "55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC ? 53 56 57 89 65 ? 8B F9");

	if (!call_hook)
	{
		std::cout << "[!] call_hook não encontrado!\n";
		return;
	}
	std::cout << "[*] call_hook encontrado em: 0x" << std::hex << call_hook << std::endl;

	//auto target_func = util::resolve_relative_address(reinterpret_cast<uint8_t*>(call_instr), 1, 5);

	if (MH_CreateHook(reinterpret_cast<void*>(entry), &hkGetEntryPoint, reinterpret_cast<void**>(&oGetEntryPoint)) != MH_OK)
		return;

	if (MH_EnableHook(reinterpret_cast<void*>(entry)) != MH_OK)
		return;

	if (MH_CreateHook(reinterpret_cast<void*>(call_hook), &hkCall, reinterpret_cast<void**>(&oCall)) != MH_OK)
		return;

	if (MH_EnableHook(reinterpret_cast<void*>(call_hook)) != MH_OK)
		return;

	MH_CreateHookApi(L"kernel32", "LoadLibraryExW", &LoadLibraryExWHk, (void**)&oLoadLibraryExW);
	MH_EnableHook(MH_ALL_HOOKS);

	printf("[+] Hook instalado: LoadLibraryExW\n");

	std::cout << "[+] Hook instalado: GetEntryPoint @ 0x"
		<< std::hex << entry << std::endl;

	std::cout << "[+] Hook instalado: CClientModuleManager::LoadModule @ 0x"
		<< std::hex << call_hook << std::endl;
}

void OpenDebugConsole()
{
	// Aloca um console para o processo
	if (AllocConsole())
	{
		// Redireciona saída padrão (C e C++)
		FILE* fDummy;
		freopen_s(&fDummy, "CONOUT$", "w", stdout);
		freopen_s(&fDummy, "CONOUT$", "w", stderr);
		freopen_s(&fDummy, "CONIN$", "r", stdin);

		// Configura streams do C++
		std::ios::sync_with_stdio();

		std::cout.clear();
		std::clog.clear();
		std::cerr.clear();
		std::cin.clear();

		// Pode usar cores e formatação
		std::cout << "[+] Console inicializado.\n";
	}
	else
	{
		MessageBoxA(nullptr, "Erro ao alocar console!", "Erro", MB_ICONERROR);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
                std::thread([] {
                        OpenDebugConsole();
                        InitHook();
                }).detach();
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

