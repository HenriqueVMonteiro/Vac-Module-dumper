#pragma once
/// \file
/// \brief Utility helpers used throughout the project.
#include <Windows.h>
#include <span> 

/** Converts a byte buffer to a hexadecimal string. */
inline std::string BytesToHex(const uint8_t* data, size_t len)
{
	std::ostringstream oss;
	for (size_t i = 0; i < len; ++i)
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
	return oss.str();
}

/** Calculates the SHA-256 hash of a data buffer. */
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

/** Writes binary data to a file. */
inline void DumpToFile(const std::string& path, const void* data, size_t size)
{
	std::ofstream file(path, std::ios::binary);
	file.write((const char*)data, size);
	file.close();
}

/** Writes text to a UTF-8 file. */
inline void WriteText(const std::string& path, const std::string& txt)
{
	std::ofstream f(path);
	f << txt;
	f.close();
}


namespace util {

	uintptr_t find_signature_in_memory(HMODULE module_handle, std::string_view pattern)
	{
		// Helper lambda para converter o padrão de string para bytes.
		// "??" ou "?" são tratados como wildcards.
		static auto pattern_to_byte = [](const char* pattern) -> std::vector<int> {
			auto bytes = std::vector<int>{};
			const char* start = pattern;
			const char* end = pattern + strlen(pattern);

			for (const char* current = start; current < end; ++current) {
				if (*current == '?') {
					++current;
					if (*current == '?')
						++current;
					bytes.push_back(-1); // Wildcard
				}
				else {
					// Converte o byte hexadecimal para um número
					bytes.push_back(static_cast<int>(strtoul(current, const_cast<char**>(&current), 16)));
				}
			}
			return bytes;
			};

		if (!module_handle) {
			return 0;
		}

		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<uint8_t*>(module_handle) + dos_header->e_lfanew
			);

		const DWORD image_size = nt_headers->OptionalHeader.SizeOfImage;
		const std::vector<int> pattern_bytes = pattern_to_byte(pattern.data());
		const std::span<const uint8_t> scan_bytes(
			reinterpret_cast<uint8_t*>(module_handle), image_size
		);

		const size_t signature_size = pattern_bytes.size();
		const int* signature_data = pattern_bytes.data();

		// Loop para varrer a memória do módulo
		for (size_t i = 0; i < image_size - signature_size; ++i)
		{
			bool found = true;
			for (size_t j = 0; j < signature_size; ++j)
			{
				// Compara o byte da memória com o byte do padrão,
				// ignorando se for um wildcard (-1).
				if (scan_bytes[i + j] != signature_data[j] && signature_data[j] != -1)
				{
					found = false;
					break;
				}
			}

			if (found) {
				return reinterpret_cast<uintptr_t>(&scan_bytes[i]);
			}
		}

		return 0;
	}

	// --- Funções de Fachada (API Pública) ---

	// SOBRECARGA 1: Aceita um HMODULE diretamente.
	// Ideal para quando você já tem o handle e quer performance.
	uintptr_t get_sig(HMODULE module_handle, std::string_view pattern)
	{
		return find_signature_in_memory(module_handle, pattern);
	}

	// SOBRECARGA 2: Aceita o nome do módulo.
	// Conveniente para quando você não tem o handle.
	uintptr_t get_sig(std::string_view module_name, std::string_view pattern)
	{
		HMODULE module_handle = GetModuleHandleA(module_name.data());
		if (!module_handle) {
			std::cerr << "Erro: Modulo '" << module_name << "' nao encontrado.\n";
			return 0;
		}
		return find_signature_in_memory(module_handle, pattern);
	}


        /// Resolve an absolute address from an instruction with a relative offset.
        /// @param instr   Pointer to the start of the instruction (e.g. call opcode).
        /// @param offset_to_rel Offset of the relative field inside the instruction.
        /// @param instr_size Total instruction size in bytes.
        /// @return Resolved absolute pointer.
	inline std::uint8_t* resolve_relative_address(std::uint8_t* instr, std::uint32_t offset_to_rel, std::uint32_t instr_size)
	{
		const auto rel = *reinterpret_cast<std::int32_t*>(instr + offset_to_rel);
		return instr + instr_size + rel;
	}
}