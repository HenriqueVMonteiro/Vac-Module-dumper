/// \file
/// \brief DLL entry point and hook initialization for dumping VAC modules.
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

#include "detours.h"
#include "util.h"
#include "icekey.h"
#include "vacstructs.h"
#include <MinHook.h>
#include "hook.h"

#define LOG(fmt, ...)  printf("[VACDBG] " fmt "\n", ##__VA_ARGS__)
#define FAIL(msg)      do { LOG("!! %s", msg); goto cleanup; } while (0)

#define MOV_EAX_IMM32 0xB8      /* mov eax, imm32 (B8+reg) */
#define JMP           0xEB		/* jmp  rel8               */
#define RET           0xC3      /* ret                     */

using namespace Detours;

#if _WIN64
#pragma comment(lib,"libMinHook.x64.lib")
#else
#pragma comment(lib,"libMinHook.x86.lib")
#endif

std::unordered_map<uint32_t, std::array<uint8_t, 16>> g_IceKeys;
std::vector<unsigned int> g_KnowHashes;
std::unordered_map<HMODULE, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>> g_ImportingModules;

static const std::filesystem::path g_dumpPath = L"C:\\VacDump";
bool bCallOriginal = false;

fnRunFunc RunFunc = nullptr;
VacModuleResult_t __stdcall RunFunc_Hook(unsigned int unID, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize) {
	if (!bCallOriginal) {
		bCallOriginal = true;
		LOG(" RunFunc ID=%08X\n", unID);
		VacModuleResult_t unResult = RunFunc(unID, pInData, unInDataSize, pOutData, pOutDataSize);
		LOG("RunFunc og called");
		return unResult;
	}

	LOG("RunFunc ID=%08X", unID);
	LOG("RunFunc blocked.");

	if (unID == 4) {
		return VacModuleResult_t::SUCCESS;
	}

	return VacModuleResult_t::FAIL_INITIALIZE;
}

/**
 * @brief Hook for the VAC module entry point.
 *
 * Logs module information and optionally dumps the module when loaded.
 * @param pModule Pointer to the module info structure.
 * @param flags   Flags passed by the loader.
 * @return Original function return value.
 */
char __stdcall hkGetEntryPoint(VacModuleInfo_t* pModule, unsigned char flags)
{
	printf("--------------------------------------\n");
	printf("PreLoadModuleStandard\n");
	printf( " -> ModuleInfo = 0x%08X\n", reinterpret_cast<unsigned int>(pModule));
	if (pModule) {
		printf( "    -> m_unHash       = 0x%08X\n", pModule->m_unCRC32);
		printf( "    -> m_hModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_hModule));
		printf( "    -> m_pModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule));
		if (pModule->m_pModule) {
			printf( "       -> m_unRunFuncExportFunctionOrdinal = 0x%04X\n", pModule->m_pModule->m_unRunFuncExportFunctionOrdinal);
			printf( "       -> m_unRunFuncExportModuleOrdinal   = 0x%04X\n", pModule->m_pModule->m_unRunFuncExportModuleOrdinal);
			printf( "       -> m_pModuleBase                    = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pModuleBase));
			printf( "       -> m_pNTHs                          = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pNTHs));
			printf( "       -> m_unImportedLibraryCount         = 0x%08X\n", pModule->m_pModule->m_unImportedLibraryCount);
			printf( "       -> m_pIAT                           = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pIAT));
		}
		printf( "    -> m_pRunFunc     = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pRunFunc));
		printf( "    -> m_unLastResult = 0x%08X\n", pModule->m_nLastResult);
		printf( "    -> m_unModuleSize = 0x%08X\n", pModule->m_nModuleSize);
		printf( "    -> m_pRawModule   = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pRawModule));
	}
	printf( " -> unFlags    = 0x%02X\n", flags);

	printf("--------------------------------------\n");

	bool bOriginalReturn = oGetEntryPoint(pModule, flags);
	if (!pModule) {
		return bOriginalReturn;
	}

	printf("--------------------------------------\n");
	printf( "PostLoadModuleStandard\n");
	printf( " -> ModuleInfo = 0x%08X\n", reinterpret_cast<unsigned int>(pModule));
	if (pModule) {
		printf( "    -> m_unHash       = 0x%08X\n", pModule->m_unCRC32);
		printf( "    -> m_hModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_hModule));
		printf( "    -> m_pModule      = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule));
		if (pModule->m_pModule) {
			printf( "       -> m_unRunFuncExportFunctionOrdinal = 0x%04X\n", pModule->m_pModule->m_unRunFuncExportFunctionOrdinal);
			printf( "       -> m_unRunFuncExportModuleOrdinal   = 0x%04X\n", pModule->m_pModule->m_unRunFuncExportModuleOrdinal);
			printf( "       -> m_pModuleBase                    = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pModuleBase));
			printf( "       -> m_pNTHs                          = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pNTHs));
			printf( "       -> m_unImportedLibraryCount         = 0x%08X\n", pModule->m_pModule->m_unImportedLibraryCount);
			printf( "       -> m_pIAT                           = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pModule->m_pIAT));
		}
		printf( "    -> m_pRunFunc     = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pRunFunc));
		printf( "    -> m_unLastResult = 0x%08X\n", pModule->m_nLastResult);
		printf( "    -> m_unModuleSize = 0x%08X\n", pModule->m_nModuleSize);
		printf( "    -> m_pRawModule   = 0x%08X\n", reinterpret_cast<unsigned int>(pModule->m_pRawModule));
	}
	printf( " -> unFlags    = 0x%02X\n", flags);
	printf( " -> Result     = 0x%02X\n", bOriginalReturn);

	printf("--------------------------------------\n");

	if (pModule->m_pRunFunc) {
		if (!bCallOriginal) {
			RunFunc = pModule->m_pRunFunc;
		}
		pModule->m_pRunFunc = RunFunc_Hook;
	}

	HMODULE hModule = pModule->m_hModule;
	if (!hModule) {
		return bOriginalReturn;
	}

	const PMODULE_HEADER pMH = reinterpret_cast<PMODULE_HEADER>(hModule);
	if (pMH->m_unMagic != 0x564C56) {
		return bOriginalReturn;
	}

	unsigned int unHash = pModule->m_unCRC32;

	for (auto it = g_KnowHashes.begin(); it != g_KnowHashes.end(); ++it) {
		if (*it == unHash) {
			return bOriginalReturn;
		}
	}
	g_KnowHashes.push_back(unHash);

	auto Import = g_ImportingModules.find(hModule);
	if (Import != g_ImportingModules.end()) {

		auto Keys = g_IceKeys.find(unHash);
		if (Keys != g_IceKeys.end()) {

			const size_t unModuleSize = pModule->m_nModuleSize;

			LOG("Found VAC module\n");
			LOG("-> Base = 0x%08X\n", hModule);
			LOG("-> Size = 0x%08X\n", unModuleSize);
			LOG("-> Path = `%ws`\n", Import->second.second.get());

			if (!pModule->m_pRawModule)
			{
				LOG("m_pRawModule == nullptr");
			}
			if (!unModuleSize)
			{
				LOG("m_nModuleSize == 0");
			}

			if (pModule->m_pRawModule) {

				unsigned char* pMemory = new unsigned char[unModuleSize];
				if (!pMemory) {
					LOG("new pMemory[] failed");
					return bOriginalReturn;
				}

				memcpy(pMemory, pModule->m_pRawModule, unModuleSize);
				LOG("m_pRawModule copied");

				unsigned char* SystemInfo_Module = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x55\x8B\xEC\xB8\xF0\x43\x00\x00")));
				if (SystemInfo_Module) {	
					if (!Memory::ChangeProtection(SystemInfo_Module, 1, PAGE_READWRITE)) {
						delete[] pMemory;
						return bOriginalReturn;
					}

					SystemInfo_Module[0] = RET; // "ret" instruction opcode

					Memory::RestoreProtection(SystemInfo_Module);

					LOG("SystemInfo Module Patched.");
				}
				//																						for ( j = v35 >> 2; j < 0x422; ++j ) sub_xxx 
				unsigned char* ShuffledLcgPRNG = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x51\x53\x56\x57\x8B\xF9")));
				if (!ShuffledLcgPRNG) {
					LOG("ShuffledLcgPRNG signature not found");
					delete[] pMemory;
					return bOriginalReturn;
				}

				if (!Memory::ChangeProtection(ShuffledLcgPRNG, 6, PAGE_READWRITE)) {
					delete[] pMemory;
					return bOriginalReturn;
				}

				static const unsigned char patch[] = {
					MOV_EAX_IMM32, 0x00, 0x00, 0x00, 0x00,	 // mov eax,0
					RET										 // ret
				};

				memcpy(ShuffledLcgPRNG, patch, sizeof(patch));

				Memory::RestoreProtection(ShuffledLcgPRNG);

				LOG("ShuffledLcgPRNG patched.");
																									/* rdtsc
																									.text:10003410 83 A4 24 CC 00 00 00 00 and [esp + 2B8h + var_1EC], 0
																									*/
				unsigned char* pRDTSC = reinterpret_cast<unsigned char*>(const_cast<void*>(Scan::FindSignature(hModule, "\x0F\x31\x83\xA4\x24")));
				if (!pRDTSC) {
					LOG("pRDTSC signature not found");
					delete[] pMemory;
					return bOriginalReturn;
				}

				if (!Memory::ChangeProtection(pRDTSC, 21, PAGE_READWRITE)) {
					delete[] pMemory;
					return bOriginalReturn;
				}

				//fake timestamp (edx:eax)
				static const unsigned int kTscHi = 0x0009E9EC;
				static const unsigned int kTscLo = 0xA8423856;

				// sequência de bytes pronta – 21 bytes
				static const unsigned char kPatch[21] = {
					// and dword ptr [esp+0xCC], 0
					0x83, 0xA4, 0x24, 0xCC, 0x00, 0x00, 0x00, 0x00,

					// mov dword ptr [esp+0x1C], kTscHi
					0xC7, 0x44, 0x24, 0x1C,
						(unsigned char)(kTscHi & 0xFF),
						(unsigned char)((kTscHi >> 8) & 0xFF),
						(unsigned char)((kTscHi >> 16) & 0xFF),
						(unsigned char)((kTscHi >> 24) & 0xFF),

						// mov eax, kTscLo
						0xB8,
							(unsigned char)(kTscLo & 0xFF),
							(unsigned char)((kTscLo >> 8) & 0xFF),
							(unsigned char)((kTscLo >> 16) & 0xFF),
							(unsigned char)((kTscLo >> 24) & 0xFF)
				};

				memcpy(pRDTSC, kPatch, sizeof(kPatch));

				Memory::RestoreProtection(pRDTSC);

				LOG("RDTSC fixed.");

				char szBuffer[2048];
				memset(szBuffer, 0, sizeof(szBuffer));
				sprintf_s(szBuffer, "%sVAC_%08X.dll", "C:\\VacDump\\", unHash);
				FILE* pFile = nullptr;
				fopen_s(&pFile, szBuffer, "wb+");
				if (!pFile) {
					delete[] pMemory;
					return bOriginalReturn;
				}

				reinterpret_cast<PMODULE_HEADER>(pMemory)->m_unCrypt = 0;

				if (fwrite(pMemory, 1, unModuleSize, pFile) != unModuleSize) {
					fclose(pFile);
					delete[] pMemory;
					return bOriginalReturn;
				}

				fclose(pFile);
				delete[] pMemory;

				printf("Dumped to `%s`.\n\n", szBuffer);
			cleanup:
				return bOriginalReturn;
			}
		}
	}

	return bOriginalReturn;
}

/**
 * @brief Hook for CClientModuleManager::LoadModule.
 *
 * Captures ICE keys and logs module load parameters.
 */
VacModuleResult_t __fastcall hkCall(void* pThis, void* pEDX, unsigned int unHash, unsigned char unFlags,
        int nA, int nB, unsigned int unActionID, int nC, void* pInData,
        unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize)

{
	/* 1) força o vac usar LoadLibrary (clear bit 0x02) */
	//unFlags &= ~0x02;   

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

/**
 * @brief Intercepts LoadLibraryExW to copy temporary VAC modules.
 *
 * Copies the downloaded file to the dump directory before the real
 * LoadLibraryExW runs.
 */
HMODULE WINAPI LoadLibraryExWHk(LPCWSTR lpLibFileName,
	HANDLE  hFile,
	DWORD   dwFlags)
{

	HMODULE hModule = oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	if (!lpLibFileName) {
		return hModule;
	}

	const size_t unLength = wcsnlen_s(lpLibFileName, MAX_PATH);
	const size_t unSize = unLength * sizeof(wchar_t);

	auto Import = g_ImportingModules.find(hModule);
	if (Import == g_ImportingModules.end()) {
		std::unique_ptr<wchar_t[]> pMem(new wchar_t[unLength + 1]);
		wchar_t* pBuffer = pMem.get();
		memset(pBuffer, 0, unSize + sizeof(wchar_t));
		memcpy(pBuffer, lpLibFileName, unSize);
		pBuffer[unLength] = 0;

		g_ImportingModules.insert(std::pair<HMODULE, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>>(hModule, std::pair<HANDLE, std::unique_ptr<wchar_t[]>>(hFile, std::move(pMem))));
	}
	else {
		std::unique_ptr<wchar_t[]> pMem(new wchar_t[unLength + 1]);
		wchar_t* pBuffer = pMem.get();
		memset(pBuffer, 0, unSize + sizeof(wchar_t));
		memcpy(pBuffer, lpLibFileName, unSize);
		pBuffer[unLength] = 0;

		Import->second = std::pair<HANDLE, std::unique_ptr<wchar_t[]>>(hFile, std::move(pMem));
	}

	return oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

void ForceLoadLibrary()
{
	HMODULE hSteamService = GetModuleHandle(L"steamservice.dll");
	if (!hSteamService) {
		printf( "Unable to find `SteamService.dll` module.\n");
		return;
	}
	unsigned char* pJZ = const_cast<unsigned char*>(reinterpret_cast<const unsigned char* const>(Scan::FindData(hSteamService, reinterpret_cast<const unsigned char*>("\x74\x47\x6A\x01\x6A\x00"), 6)));
	if (!pJZ) {
		printf( "Unable to find `74 47 6A 01 6A 00` signature.\n");
		return;
	}

	if (!Memory::ChangeProtection(pJZ, 1, PAGE_EXECUTE_READWRITE)) {
		printf( "Failed to change memory protection for `74 47 6A 01 6A 00` signature.\n");
		return;
	}

	// Forces to use LoadModuleStandard. (Potential File Spam)
	pJZ[0] = JMP; // jz -> jmp

	if (!Memory::RestoreProtection(pJZ)) {
		printf( "Failed to change memory protection for `74 47 6A 01 6A 00` signature.\n");
		return;
	}

	/*  
	    (Last instructions inside hkGetEntryPoint)
		.text:10059219 89 46 20                                                        mov     [esi+20h], eax
		.text:1005921C 89 4E 24                                                        mov     [esi+24h], ecx
		.text:1005921F 74 18                                                           jz      short loc_10059239
	*/
	pJZ = const_cast<unsigned char*>(reinterpret_cast<const unsigned char* const>(Scan::FindSignature(hSteamService, "\x74\x18\xE8\x2A\x2A\x2A\x2A\x6A\x2A\xFF\x76\x18\x8B\xC8\x8B\x10\xFF\x52\x2A\xC7\x46\x18\x2A\x2A\x2A\x2A\x5E")));
	if (!pJZ) {
		
		printf( "Unable to find `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");
		return;
	}

	if (!Memory::ChangeProtection(pJZ, 1, PAGE_EXECUTE_READWRITE)) {
		
		printf( "Failed to patch `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");

		return;
	}

	// Forces to save RAW module in `MODULE_INFO`. (Potential Memory Leak?)
	pJZ[0] = JMP; // jz -> jmp

	if (!Memory::RestoreProtection(pJZ)) {
		
		printf( "Failed to change memory protection for `74 18 E8 ?? ?? ?? ?? 6A ?? FF 76 18 8B C8 8B 10 FF 52 ?? C7 46 18 ?? ?? ?? ?? 5E` signature.\n");
		return;
	}
}

/**
 * @brief Initializes MinHook and installs all required hooks.
 */
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

	ForceLoadLibrary();

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

/**
 * @brief Allocates a simple debug console for stdout/stderr logging.
 */
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

/**
 * @brief Standard DLL entry point.
 */
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

