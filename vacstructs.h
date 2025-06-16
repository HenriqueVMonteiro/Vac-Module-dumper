#pragma once
/// \file
/// \brief VAC internal structures used by the dumper.
#include <Windows.h>

/** Represents a loaded VAC module. */
struct VacModule_t {
	WORD m_nRunFuncExportFunctionOrdinal;
	WORD m_nRunFuncExportModuleOrdinal;
	DWORD m_pModuleBase;
	struct _IMAGE_NT_HEADERS* m_pNTHeaders;
	DWORD m_nImportedLibraryCount;
	DWORD m_pIAT;
};

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

typedef struct _MODULE_INFO {
	unsigned int m_unHash; // CRC32
	HMODULE m_hModule;
	PMODULE m_pModule;
	fnRunFunc m_pRunFunc;
	VacModuleResult_t m_unLastResult;
	unsigned int m_unModuleSize;
	PMODULE_HEADER m_pRawModule;
} MODULE_INFO, * PMODULE_INFO;

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

/*-----------------------------------------------------------*
 *  Contexto passado como 2º parâmetro de _runfunc@20        *
 *  (layout mínimo suficiente para extrair a ICE-key)        *
 *-----------------------------------------------------------*/
#pragma pack(push,1)
typedef struct VacRuntimeCtx
{
	void* pMgrVft;     //  0x00  ponteiro p/ v-table do manager
	uint8_t    unk0[0x0C];  //  0x04  paddings/flags que não precisamos agora
	uint8_t    iceKey[8];   //  0x10  *** 8-byte ICE key ***
	uint8_t    unk1[];      //  0x18  dados runtime variados
} VacRuntimeCtx;
#pragma pack(pop)

/*-----------------------------------------------------------*
 *  Entrada da tabela de segmentos ICE dentro do módulo      *
 *  (vista no blog do r0da como chunk table  DataDir[13]) *
 *-----------------------------------------------------------*/
typedef struct IceChunk
{
	uint32_t rva;   // offset relativo dentro do módulo
	uint32_t size;  // bytes criptografados (múltiplos de 8)
} IceChunk;

typedef struct VacCtxHeader
{
	uint32_t key_lo;          // +0x00  <- primeiro dword da ICE-key (parte 1)
	uint32_t key_hi;          // +0x04  <- segundo  dword da ICE-key (parte 2)
	uint32_t crc_inv;         // +0x08  <- ~CRC32 que será checado
	uint32_t unk_ptr;         // +0x0C  <- salvo em a3[0] / v6 (tag ou callback)
	uint8_t  encImports[160]; // +0x10  <- tabela criptografada de imports                      
} VacCtxHeader;

