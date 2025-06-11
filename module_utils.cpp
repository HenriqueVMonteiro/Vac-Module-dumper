#include "module_utils.h"
#include "icekey.h"
#include <fstream>
#include <filesystem>
#include <iostream>

struct IceChunk {
    uint32_t rva;
    uint32_t size;
};

void FixVacModule(DWORD pImage, DWORD pModule_)
{
    VacModuleInfo_t* pModule = (VacModuleInfo_t*)pModule_;
    PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pImage + ((PIMAGE_DOS_HEADER)pImage)->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

    std::cout << "[+] FixVacModule : Fixing PE" << std::endl;

    for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        DWORD iSectionRva = pSectionHeader->Misc.VirtualSize - pModule->m_pModule->m_pModuleBase;
        pSectionHeader->PointerToRawData = iSectionRva;
        pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;

        if (!strcmp((char*)&pSectionHeader->Name[0], ".text"))
            pNtHeader->OptionalHeader.AddressOfEntryPoint = pSectionHeader->PointerToRawData;

        ++pSectionHeader;
    }
}

DWORD GetAllocationSize(DWORD iStartAddress)
{
    MEMORY_BASIC_INFORMATION mbi{};
    DWORD iOffset = iStartAddress;
    DWORD iSize = 0;

    do {
        if (!VirtualQuery((LPCVOID)iOffset, &mbi, sizeof(mbi)))
            break;
        if (mbi.State == MEM_RESERVE)
            break;

        iSize += mbi.RegionSize;
        iOffset += mbi.RegionSize;
    } while (true);

    return iSize;
}

bool DecryptVacModule(uint8_t* base, size_t imgSize, const uint8_t key[8])
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[13];
    if (!dir.VirtualAddress || dir.Size < sizeof(IceChunk))
        return false;

    auto* tbl = reinterpret_cast<IceChunk*>(base + dir.VirtualAddress);
    size_t rows = dir.Size / sizeof(IceChunk);

    IceKey ice(1);
    ice.set(key);

    for (size_t i = 0; i < rows; ++i) {
        uint32_t rva = tbl[i].rva;
        uint32_t size = tbl[i].size;
        if (!rva || !size || rva + size > imgSize || (size & 7))
            continue;

        uint8_t* ptr = base + rva;
        for (uint32_t off = 0; off < size; off += 8)
            ice.decrypt(&ptr[off], &ptr[off]);
    }
    return true;
}

bool DumpVacModule(VacModuleInfo_t* m, const std::wstring& dumpDir)
{
    BYTE* base = nullptr; DWORD sz = 0;
    if (m->m_pModule) {
        base = (BYTE*)m->m_pModule->m_pModuleBase;
        sz = GetAllocationSize((DWORD)base);
    }
    else if (m->m_hModule) {
        base = (BYTE*)m->m_hModule;
        sz = GetAllocationSize((DWORD)base);
    }
    else if (m->m_pRawModule && m->m_nModuleSize) {
        base = (BYTE*)m->m_pRawModule;
        sz = m->m_nModuleSize;
    }
    else {
        std::cout << "[-] DumpVacModuleRaw: buffer inexistente" << std::endl;
        return false;
    }

    std::vector<BYTE> buf(sz);
    ReadProcessMemory(GetCurrentProcess(), base, buf.data(), sz, nullptr);

    if (m->m_pModule != nullptr)
        FixVacModule(reinterpret_cast<DWORD>(buf.data()), reinterpret_cast<DWORD>(m));

    std::filesystem::create_directories(dumpDir);
    std::wstring path = dumpDir + L"\\vac" + std::to_wstring(m->m_unCRC32) + L".dll";

    std::ofstream fout(path, std::ios::binary);
    if (!fout)
        return false;

    fout.write(reinterpret_cast<char*>(buf.data()), buf.size());
    fout.close();

    std::wcout << L"[+] Raw dump salvo em " << path << std::endl;
    return true;
}
