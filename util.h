#pragma once
#include <Windows.h>


inline std::string BytesToHex(const uint8_t* data, size_t len)
{
	std::ostringstream oss;
	for (size_t i = 0; i < len; ++i)
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
	return oss.str();
}

inline std::string SHA256(const void* data, size_t size)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE hash[32];
	DWORD hashLen = 32;
	std::string result;

	if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
		CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash) &&
		CryptHashData(hHash, (BYTE*)data, size, 0) &&
		CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
	{
		result = BytesToHex(hash, 32);
	}
	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);
	return result;
}

inline void DumpToFile(const std::string& path, const void* data, size_t size)
{
	std::ofstream file(path, std::ios::binary);
	file.write((const char*)data, size);
	file.close();
}

inline void WriteText(const std::string& path, const std::string& txt)
{
	std::ofstream f(path);
	f << txt;
	f.close();
}


namespace util {

	uintptr_t get_sig(std::string module_name, std::string pattern)
	{
		static auto pattern_to_byte = [](const char* pattern)
			{
				auto bytes = std::vector<int>{};
				auto start = const_cast<char*>(pattern);
				auto end = const_cast<char*>(pattern) + strlen(pattern);

				for (auto current = start; current < end; ++current)
				{
					if (*current == '?')
					{
						++current;
						if (*current == '?')
							++current;
						bytes.push_back(-1);
					}
					else
					{
						bytes.push_back(strtoul(current, &current, 16));
					}
				}
				return bytes;
			};

		const auto module = GetModuleHandleA(module_name.c_str());

		if (module)
		{
			const auto dosHeader = PIMAGE_DOS_HEADER(module);
			const auto ntHeaders = PIMAGE_NT_HEADERS(reinterpret_cast<std::uint8_t*>(module) + dosHeader->e_lfanew);

			const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
			auto patternBytes = pattern_to_byte(pattern.c_str());
			const auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

			const auto s = patternBytes.size();
			const auto d = patternBytes.data();

			for (auto i = 0ul; i < sizeOfImage - s; ++i)
			{
				auto found = true;
				for (auto j = 0ul; j < s; ++j)
				{
					if (scanBytes[i + j] != d[j] && d[j] != -1)
					{
						found = false;
						break;
					}
				}

				if (found)
					return uintptr_t(&scanBytes[i]);
			}
		}

		return 0;
	}

	/// @brief Resolve endereço absoluto a partir de uma instrução com offset relativo (x86).
	/// @param instr Ponteiro para o início da instrução (ex: call E8 ?? ?? ?? ??)
	/// @param offset_to_rel Offset do campo relativo (normalmente 1 para instruções como E8 xx xx xx xx)
	/// @param instr_size Tamanho total da instrução (normalmente 5 bytes para call/jmp)
	/// @returns Ponteiro absoluto resolvido
	inline std::uint8_t* resolve_relative_address(std::uint8_t* instr, std::uint32_t offset_to_rel, std::uint32_t instr_size)
	{
		const auto rel = *reinterpret_cast<std::int32_t*>(instr + offset_to_rel);
		return instr + instr_size + rel;
	}

}