#pragma once
#include <Windows.h>

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
	UKN0 = 0x5,
	FAIL_TO_DECRYPT_VAC_MODULE = 0xb,
	FAIL_MODULE_SIZE_NULL = 0xc,
	UKN1 = 0xf,
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
	DWORD m_nCryptedDataSize;
	DWORD unkn0;
	BYTE  m_CryptedRSASignature[0x80];
};

struct VacModuleInfo_t
{
	DWORD m_unCRC32;
	DWORD m_hModule;
	struct VacModule_t* m_pModule;
	DWORD m_pRunFunc;
	enum VacModuleResult_t m_nLastResult;
	DWORD m_nModuleSize;
	struct VacModuleCustomDosHeader_t* m_pRawModule;
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
 *  (vista no blog do r0da como “chunk table” – DataDir[13]) *
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
