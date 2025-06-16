#pragma once
/// \file
/// \brief VAC internal structures used by the dumper.
#include <Windows.h>

enum VacModuleResult_t {
	NOT_SET = 0x0,
	SUCCESS = 0x1,
	ALREADY_LOADED = 0x2,
	FAIL_INITIALIZE = 0x3,
	UKN1 = 0x4,
	UKN2 = 0x5,
	FAIL_TO_DECRYPT_MODULE = 0xB,
	FAIL_MODULE_SIZE_NULL = 0xC,
	UKN3 = 0xF,
	FAIL_GET_MODULE_TEMP_PATH = 0x13,
	FAIL_WRITE_MODULE = 0x15,
	FAIL_LOAD_MODULE = 0x16,
	FAIL_GET_EXPORT_RUNFUNC = 0x17,
	FAIL_GET_EXPORT_RUNFUNC_2 = 0x19
};
struct VacModuleCustomDosHeader_t {
	struct _IMAGE_DOS_HEADER m_DosHeader;
	DWORD m_ValveHeaderMagic; // 'VLV' ou 0x564C56
	DWORD m_nIsCrypted;
	DWORD m_unFileSize;
	unsigned int m_unTimeStamp;
	unsigned char m_pCryptRSASignature[0x80];
};

using fnRunFunc = VacModuleResult_t(__stdcall*)(unsigned int unID, void* pInData, unsigned int unInDataSize, void* pOutData, unsigned int* pOutDataSize);

typedef struct _MODULE {
	unsigned short m_unRunFuncExportFunctionOrdinal;
	unsigned short m_unRunFuncExportModuleOrdinal;
	void* m_pModuleBase;
	PIMAGE_NT_HEADERS m_pNTHs;
	unsigned int m_unImportedLibraryCount;
	void* m_pIAT;
} MODULE, * PMODULE;

typedef struct _MODULE_HEADER {
	IMAGE_DOS_HEADER m_DH;
	unsigned int m_unMagic;
	unsigned int m_unCrypt;
	unsigned int m_unFileSize;
	unsigned int m_unTimeStamp;
	unsigned char m_pCryptRSASignature[0x80];
} MODULE_HEADER, * PMODULE_HEADER;

/** Metadata for a VAC module as loaded by Steam. */
struct VacModuleInfo_t
{
	unsigned int m_unCRC32;
	HMODULE m_hModule;
	PMODULE m_pModule;
	fnRunFunc m_pRunFunc;
	VacModuleResult_t m_nLastResult;
	unsigned int m_nModuleSize;
	PMODULE_HEADER m_pRawModule;
	WORD unkn08;
	BYTE m_nUnknFlag_1;
	BYTE m_nUnknFlag_0;
	DWORD pCallableUnkn11;
	DWORD pCallableUnkn12;
	DWORD unkn13;
	DWORD unkn14;
	DWORD unkn15;
};

