# Name: DeDumpVAC.py
# Version: 1.1.1
# Author: RenardDev (zeze839@gmail.com)

# Main imports
import ida_idaapi
import ida_hexrays
import ida_auto
import idc
import ida_pro
import ida_nalt
import ida_ida
import ida_search
import ida_bytes
import ida_xref
import ida_ua

# General imports
import enum
import ctypes
import datetime
import math

# General definitions

VERBOSE_LEVEL = 4

BEGIN_DATA_NAME = 'pBeginData'
IMPORT_MODULES_PREFIX = 'h'
IMPORT_FUNCTIONS_PREFIX = 'p'

BEGIN_DATA_ADDRESS_SIGNATURE = 'A1 ? ? ? ? 6A ? 6A' ##A1 ?? ?? ?? ?? 6A 00
IMPORTING_DATA_ADDRESS_SIGNATURE = 'BE ?? ?? ?? ?? C7 44 24' ## second module BE ? ? ? ? BB 
IMPORTING_DATA_ADDRESS_SIGNATURE_ALT = 'BE ?? ?? ?? ?? BB'
IMPORTING_COUNT_ADDRESS_SIGNATURE = '81 3D ?? ?? ?? ?? ?? ?? ?? ?? 0F 83 ?? 00 00 00'
IMPORTING_NAMES_ADDRESS_SIGNATURE = '8D A8 ?? ?? ?? ?? 51'
IMPORTING_NAMES_ADDRESS_SIGNATURE_ALT = '8D BA ?? ?? ?? ?? 3B C8'
IMPORTING_MODULE_ADDRESSES_SIGNATURE = '8B 1C 9D ?? ?? ?? ?? EB 57'
IMPORTING_MODULE_ADDRESSES_SIGNATURE_ALT = '39 14 8D ?? ?? ?? ?? 74'

MAGIC_DOS_SIGNATURE = 0x5A4D
MAGIC_VALVE_SIGNATURE = 0x00564C56
MAGIC_PE_SIGNATURE = 0x00004550

PE_FILE_MACHINE_32B = 0x014C
PE_FILE_MACHINE_64B = 0x8664


class PE_DATA_DIRECTORY_ENUM(enum.IntEnum):
	PE_DATA_DIRECTORY_EXPORT = 0
	PE_DATA_DIRECTORY_IMPORT = 1
	PE_DATA_DIRECTORY_RESOURCE = 2
	PE_DATA_DIRECTORY_EXCEPTION = 3
	PE_DATA_DIRECTORY_SECURITY = 4
	PE_DATA_DIRECTORY_BASERELOC = 5
	PE_DATA_DIRECTORY_DEBUG = 6
	PE_DATA_DIRECTORY_ARCHITECTURE = 7
	PE_DATA_DIRECTORY_GLOBALPTR = 8
	PE_DATA_DIRECTORY_TLS = 9
	PE_DATA_DIRECTORY_LOADCONFIG = 10
	PE_DATA_DIRECTORY_BOUNDIMPORT = 11
	PE_DATA_DIRECTORY_IAT = 12
	PE_DATA_DIRECTORY_DELAYIMPORT = 13
	PE_DATA_DIRECTORY_COMDESCRIPTOR = 14
	PE_DATA_DIRECTORY_RESERVED = 15

class DOS_HEADER(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('e_magic', ctypes.c_uint16),                  # 0x00 // Magic number
		('e_cblp', ctypes.c_uint16),                   # 0x02 // Bytes on last page of file
		('e_cp', ctypes.c_uint16),                     # 0x04 // Pages in file
		('e_crlc', ctypes.c_uint16),                   # 0x06 // Relocations
		('e_cparhdr', ctypes.c_uint16),                # 0x08 // Size of header in paragraphs
		('e_minalloc', ctypes.c_uint16),               # 0x0A // Minimum extra paragraphs needed
		('e_maxalloc', ctypes.c_uint16),               # 0x0C // Maximum extra paragraphs needed
		('e_ss', ctypes.c_uint16),                     # 0x0E // Initial (relative) SS value
		('e_sp', ctypes.c_uint16),                     # 0x10 // Initial SP value
		('e_csum', ctypes.c_uint16),                   # 0x12 // Checksum
		('e_ip', ctypes.c_uint16),                     # 0x14 // Initial IP value
		('e_cs', ctypes.c_uint16),                     # 0x16 // Initial (relative) CS value
		('e_lfarlc', ctypes.c_uint16),                 # 0x18 // File address of relocation table
		('e_ovno', ctypes.c_uint16),                   # 0x1A // Overloay number
		('e_res', ctypes.ARRAY(ctypes.c_uint16, 4)),   # 0x1C // Reserved
		('e_oemid', ctypes.c_uint16),                  # 0x24 // OEM identifier (for e_oeminfo)
		('e_oeminfo', ctypes.c_uint16),                # 0x26 // OEM information; e_oemid specific
		('e_res2', ctypes.ARRAY(ctypes.c_uint16, 10)), # 0x28 // Reserved
		('e_lfanew', ctypes.c_uint32)                  # 0x3C // Offset to start of PE header
	]

class VALVE_DOS_HEADER(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('v_dh', DOS_HEADER),                       # 0x00 // DOS header
		('v_magic', ctypes.c_uint32),               # 0x40 // Magic number
		('v_c', ctypes.c_uint32),                   # 0x44 // Encryption
		('v_fs', ctypes.c_uint32),                  # 0x48 // File size (in bytes)
		('v_ts', ctypes.c_uint32),                  # 0x4C // The low 32 bits of the time stamp of the file
		('v_cs', ctypes.ARRAY(ctypes.c_ubyte, 128)) # 0x4C // Encrypted RSA signature
	]

class PE_FILE_HEADER(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Machine', ctypes.c_uint16),              # 0x04 // The architecture type of the computer
		('NumberOfSections', ctypes.c_uint16),     # 0x06 // The number of sections
		('TimeDateStamp', ctypes.c_uint32),        # 0x08 // The low 32 bits of the time stamp of the image
		('PointerToSymbolTable', ctypes.c_uint32), # 0x0C // The offset of the symbol table, in bytes, or zero if no COFF symbol table exists
		('NumberOfSymbols', ctypes.c_uint32),      # 0x10 // The number of symbols in the symbol table
		('SizeOfOptionalHeader', ctypes.c_uint16), # 0x14 // The size of the optional header, in bytes. This value should be 0 for object files
		('Characteristics', ctypes.c_uint16)       # 0x16 // The characteristics of the image
	]

class PE_DATA_DIRECTORY(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('VirtualAddress', ctypes.c_uint32), # 0x00 // The relative virtual address of the table
		('Size', ctypes.c_uint32)            # 0x04 // The size of the table, in bytes
	]

class PE_DATA_DEBUG_DIRECTORY(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Characteristics', ctypes.c_uint32),  # 0x00 // Reserved
		('TimeDateStamp', ctypes.c_uint32),    # 0x04 // The low 32 bits of the time stamp of the debugging information
		('MajorVersion', ctypes.c_uint16),     # 0x08 // The major version number of the debugging information format
		('MinorVersion', ctypes.c_uint16),     # 0x0A // The minor version number of the debugging information format
		('Type', ctypes.c_uint32),             # 0x0C // The format of the debugging information
		('SizeOfData', ctypes.c_uint32),       # 0x10 // The size of the debugging information, in bytes
		('AddressOfRawData', ctypes.c_uint32), # 0x14 // The address of the debugging information when the image is loaded, relative to the image base
		('PointerToRawData', ctypes.c_uint32)  # 0x18 // A file pointer to the debugging information
	]

class PE_OPTIONAL_HEADER32(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Magic', ctypes.c_uint16),                             # 0x00 // The state of the image file
		('MajorLinkerVersion', ctypes.c_uint8),                 # 0x02 // The major version number of the linker
		('MinorLinkerVersion', ctypes.c_uint8),                 # 0x03 // The minor version number of the linker
		('SizeOfCode', ctypes.c_uint32),                        # 0x04 // The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections
		('SizeOfInitializedData', ctypes.c_uint32),             # 0x08 // The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections
		('SizeOfUninitializedData', ctypes.c_uint32),           # 0x0C // The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections
		('AddressOfEntryPoint', ctypes.c_uint32),               # 0x10 // A pointer to the entry point function, relative to the image base address
		('BaseOfCode', ctypes.c_uint32),                        # 0x14 // A pointer to the beginning of the code section, relative to the image base
		('BaseOfData', ctypes.c_uint32),                        # 0x18 // A pointer to the beginning of the data section, relative to the image base
		('ImageBase', ctypes.c_uint32),                         # 0x1C // The preferred address of the first byte of the image when it is loaded in memory
		('SectionAlignment', ctypes.c_uint32),                  # 0x20 // The alignment of sections loaded in memory, in bytes
		('FileAlignment', ctypes.c_uint32),                     # 0x24 // The alignment of the raw data of sections in the image file, in bytes
		('MajorOperatingSystemVersion', ctypes.c_uint16),       # 0x28 // The major version number of the required operating system
		('MinorOperatingSystemVersion', ctypes.c_uint16),       # 0x2A // The minor version number of the required operating system
		('MajorImageVersion', ctypes.c_uint16),                 # 0x2C // The major version number of the image
		('MinorImageVersion', ctypes.c_uint16),                 # 0x2E // The minor version number of the image
		('MajorSubsystemVersion', ctypes.c_uint16),             # 0x30 // The major version number of the subsystem
		('MinorSubsystemVersion', ctypes.c_uint16),             # 0x32 // The minor version number of the subsystem
		('Win32VersionValue', ctypes.c_uint32),                 # 0x34 // Reserved and must be 0
		('SizeOfImage', ctypes.c_uint32),                       # 0x38 // The size of the image, in bytes, including all headers
		('SizeOfHeaders', ctypes.c_uint32),                     # 0x3C // The combined size
		('CheckSum', ctypes.c_uint32),                          # 0x40 // The image file checksum
		('Subsystem', ctypes.c_uint16),                         # 0x42 // The subsystem required to run this image
		('DllCharacteristics', ctypes.c_uint16),                # 0x44 // The DLL characteristics of the image
		('SizeOfStackReserve', ctypes.c_uint32),                # 0x48 // The number of bytes to reserve for the stack
		('SizeOfStackCommit', ctypes.c_uint32),                 # 0x4C // The number of bytes to commit for the stack
		('SizeOfHeapReserve', ctypes.c_uint32),                 # 0x50 // The number of bytes to reserve for the local heap
		('SizeOfHeapCommit', ctypes.c_uint32),                  # 0x54 // The number of bytes to commit for the local heap
		('LoaderFlags', ctypes.c_uint32),                       # 0x58 // Outdated
		('NumberOfRvaAndSizes', ctypes.c_uint32),               # 0x5C // The number of directory entries in the remainder of the optional header
		('DataDirectory', ctypes.ARRAY(PE_DATA_DIRECTORY, 16)), # 0x60 // Data directory
	]

class PE_HEADERS32(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Signature', ctypes.c_uint32),          # 0x00 // Magic number
		('FileHeader', PE_FILE_HEADER),          # 0x04 // The file header
		('OptionalHeader', PE_OPTIONAL_HEADER32) # 0x1C // The optional file header
	]

class PE_OPTIONAL_HEADER64(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Magic', ctypes.c_uint16),                             # 0x00 // The state of the image file
		('MajorLinkerVersion', ctypes.c_uint8),                 # 0x02 // The major version number of the linker
		('MinorLinkerVersion', ctypes.c_uint8),                 # 0x03 // The minor version number of the linker
		('SizeOfCode', ctypes.c_uint32),                        # 0x04 // The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections
		('SizeOfInitializedData', ctypes.c_uint32),             # 0x08 // The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections
		('SizeOfUninitializedData', ctypes.c_uint32),           # 0x0C // The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections
		('AddressOfEntryPoint', ctypes.c_uint32),               # 0x10 // A pointer to the entry point function, relative to the image base address
		('BaseOfCode', ctypes.c_uint32),                        # 0x14 // A pointer to the beginning of the code section, relative to the image base
		('BaseOfData', ctypes.c_uint32),                        # 0x18 // A pointer to the beginning of the data section, relative to the image base
		('ImageBase', ctypes.c_uint64),                         # 0x1C // The preferred address of the first byte of the image when it is loaded in memory
		('SectionAlignment', ctypes.c_uint32),                  # 0x24 // The alignment of sections loaded in memory, in bytes
		('FileAlignment', ctypes.c_uint32),                     # 0x28 // The alignment of the raw data of sections in the image file, in bytes
		('MajorOperatingSystemVersion', ctypes.c_uint16),       # 0x2C // The major version number of the required operating system
		('MinorOperatingSystemVersion', ctypes.c_uint16),       # 0x2E // The minor version number of the required operating system
		('MajorImageVersion', ctypes.c_uint16),                 # 0x30 // The major version number of the image
		('MinorImageVersion', ctypes.c_uint16),                 # 0x32 // The minor version number of the image
		('MajorSubsystemVersion', ctypes.c_uint16),             # 0x34 // The major version number of the subsystem
		('MinorSubsystemVersion', ctypes.c_uint16),             # 0x36 // The minor version number of the subsystem
		('Win32VersionValue', ctypes.c_uint32),                 # 0x38 // Reserved and must be 0
		('SizeOfImage', ctypes.c_uint32),                       # 0x3C // The size of the image, in bytes, including all headers
		('SizeOfHeaders', ctypes.c_uint32),                     # 0x40 // The combined size
		('CheckSum', ctypes.c_uint32),                          # 0x44 // The image file checksum
		('Subsystem', ctypes.c_uint16),                         # 0x48 // The subsystem required to run this image
		('DllCharacteristics', ctypes.c_uint16),                # 0x4A // The DLL characteristics of the image
		('SizeOfStackReserve', ctypes.c_uint64),                # 0x4C // The number of bytes to reserve for the stack
		('SizeOfStackCommit', ctypes.c_uint64),                 # 0x54 // The number of bytes to commit for the stack
		('SizeOfHeapReserve', ctypes.c_uint64),                 # 0x5C // The number of bytes to reserve for the local heap
		('SizeOfHeapCommit', ctypes.c_uint64),                  # 0x64 // The number of bytes to commit for the local heap
		('LoaderFlags', ctypes.c_uint32),                       # 0x6C // Outdated
		('NumberOfRvaAndSizes', ctypes.c_uint32),               # 0x70 // The number of directory entries in the remainder of the optional header
		('DataDirectory', ctypes.ARRAY(PE_DATA_DIRECTORY, 16)), # 0x74 // Data directory
	]

class PE_HEADERS64(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Signature', ctypes.c_uint32),          # 0x00 // Magic number
		('FileHeader', PE_FILE_HEADER),          # 0x04 // The file header
		('OptionalHeader', PE_OPTIONAL_HEADER64) # 0x1C // The optional file header
	]

class PE_SECTION_HEADER_MISC(ctypes.Union):
	_pack_ = 1
	_fields_ = [
		('PhysicalAddress', ctypes.c_uint32), # 0x00 // The file address
		('VirtualSize', ctypes.c_uint32)      # 0x00 // The total size of the section when loaded into memory, in bytes. If this value is greater than the SizeOfRawData member, the section is filled with zeroes. This field is valid only for executable images and should be set to 0 for object files
	]

class PE_SECTION_HEADER(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('Name', ctypes.ARRAY(ctypes.c_ubyte, 8)), # 0x00 // An 8-byte, null-padded UTF-8 string
		('Misc', PE_SECTION_HEADER_MISC),          # 0x08 // Misc
		('VirtualAddress', ctypes.c_uint32),       # 0x0C // The address of the first byte of the section when loaded into memory, relative to the image base. For object files, this is the address of the first byte before relocation is applied
		('SizeOfRawData', ctypes.c_uint32),        # 0x10 // The size of the initialized data on disk, in bytes
		('PointerToRawData', ctypes.c_uint32),     # 0x14 // A file pointer to the first page within the COFF file
		('PointerToRelocations', ctypes.c_uint32), # 0x18 // A file pointer to the beginning of the relocation entries for the section
		('PointerToLinenumbers', ctypes.c_uint32), # 0x1C // A file pointer to the beginning of the line-number entries for the section
		('NumberOfRelocations', ctypes.c_uint16),  # 0x20 // The number of relocation entries for the section
		('NumberOfLinenumbers', ctypes.c_uint16),  # 0x22 // The number of line-number entries for the section
		('Characteristics', ctypes.c_uint32),      # 0x26 // The characteristics of the section
	]

class VALVE_PE_SECTION_HEADER(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('ValveSectionSize', ctypes.c_uint32),     # 0x00 // The size of the section data on disk, in bytes
		('ValveSectionStart', ctypes.c_uint32),    # 0x04 // A pointer to the section, relative to the image base address
		('Misc', PE_SECTION_HEADER_MISC),          # 0x08 // Misc
		('VirtualAddress', ctypes.c_uint32),       # 0x0C // The address of the first byte of the section when loaded into memory, relative to the image base. For object files, this is the address of the first byte before relocation is applied
		('SizeOfRawData', ctypes.c_uint32),        # 0x10 // The size of the initialized data on disk, in bytes
		('PointerToRawData', ctypes.c_uint32),     # 0x14 // A file pointer to the first page within the COFF file
		('PointerToRelocations', ctypes.c_uint32), # 0x18 // A file pointer to the beginning of the relocation entries for the section
		('PointerToLinenumbers', ctypes.c_uint32), # 0x1C // A file pointer to the beginning of the line-number entries for the section
		('NumberOfRelocations', ctypes.c_uint16),  # 0x20 // The number of relocation entries for the section
		('NumberOfLinenumbers', ctypes.c_uint16),  # 0x22 // The number of line-number entries for the section
		('Characteristics', ctypes.c_uint16),      # 0x26 // The characteristics of the section
	]

def IsNotValidAddress(nAddress):
	if (nAddress == 0) | (nAddress == ida_idaapi.BADADDR):
		return True
	return False

_DeDumpVAC = None

nRegisterForBeginData = ida_idaapi.BADADDR
nRegisterForBeginData2 = ida_idaapi.BADADDR

class Optimizer(ida_hexrays.minsn_visitor_t):
	global nRegisterForBeginData

	nChangesCount = 0

	def visit_minsn(self):
		global nRegisterForBeginData

		if _DeDumpVAC == None:
			return 0
		if _DeDumpVAC._bIsReadyToDecompiling != True:
			return 0

		ins = self.curins

		if ins.opcode == ida_hexrays.m_mov:
			if ins.l.t == ida_hexrays.mop_v:
				if ins.d.t == ida_hexrays.mop_r:
					if ins.l.g == _DeDumpVAC._nBeginDataAddress:
						nRegisterForBeginData = ins.d.r
						return 0

		if nRegisterForBeginData != ida_idaapi.BADADDR:
			if ins.opcode == ida_hexrays.m_icall:
				if ins.l.t == ida_hexrays.mop_r:
					if ins.r.t == ida_hexrays.mop_d:
						if ins.d.t == ida_hexrays.mop_z:
							r1_ins = ins.r.d
							if r1_ins.opcode == ida_hexrays.m_ldx:
								if r1_ins.l.t == ida_hexrays.mop_r:
									if r1_ins.r.t == ida_hexrays.mop_d:
										if r1_ins.d.t == ida_hexrays.mop_z:
											r2_ins = r1_ins.r.d
											if r2_ins.opcode == ida_hexrays.m_add:
												if r2_ins.l.t == ida_hexrays.mop_r:
													if r2_ins.r.t == ida_hexrays.mop_n:
														if r2_ins.d.t == ida_hexrays.mop_z:
															if r2_ins.l.r == nRegisterForBeginData:
																#print('icall {}:[{}+{:X}]'.format(ida_hexrays.get_mreg_name(r1_ins.l.r, r1_ins.l.size), ida_hexrays.get_mreg_name(r2_ins.l.r, r2_ins.l.size), r2_ins.r.nnn.value))
																if ins.l.has_side_effects() != True:
																	ins.opcode = ida_hexrays.m_call
																	ins.l.make_gvar(_DeDumpVAC._nImportingAddresses + r2_ins.r.nnn.value)
																	ins.r = ida_hexrays.mop_t()
																	r1_ins.opcode = ida_hexrays.m_nop
																	r1_ins.l = ida_hexrays.mop_t()
																	r1_ins.r = ida_hexrays.mop_t()
																	r2_ins.opcode = ida_hexrays.m_nop
																	r2_ins.l = ida_hexrays.mop_t()
																	r2_ins.r = ida_hexrays.mop_t()
																	self.nChangesCount += 3
																	return 0

		return 0

'''
typedef uint8 mopt_t;
const mopt_t
  mop_z   = 0,  ///< none
  mop_r   = 1,  ///< register (they exist until MMAT_LVARS)
  mop_n   = 2,  ///< immediate number constant
  mop_str = 3,  ///< immediate string constant
  mop_d   = 4,  ///< result of another instruction
  mop_S   = 5,  ///< local stack variable (they exist until MMAT_LVARS)
  mop_v   = 6,  ///< global variable
  mop_b   = 7,  ///< micro basic block (mblock_t)
  mop_f   = 8,  ///< list of arguments
  mop_l   = 9,  ///< local variable
  mop_a   = 10, ///< mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
  mop_h   = 11, ///< helper function
  mop_c   = 12, ///< mcases
  mop_fn  = 13, ///< floating point constant
  mop_p   = 14, ///< operand pair
  mop_sc  = 15; ///< scattered
'''

ida_version = float(idaapi.get_kernel_version())
python_version = sys.version_info

if ida_version < 9.0:
  # For IDA versions under 9.0, use additional imports
  import ida_search

def search_for_bytes(prologue_bytes, ea, segment_end):
  if ida_version < 9.0:
    # For IDA versions under 9.0, use idc.search_bytes
    return ida_search.find_binary(ea, segment_end, prologue_bytes, 0x10, ida_search.SEARCH_DOWN)
  else:
    # For IDA versions 9.0 and above, use ida_bytes.search
    return idc.find_bytes(prologue_bytes, ea, range_end=segment_end)

class MicroCodeOptimizer(ida_hexrays.optinsn_t):
	def func(self, blk, ins, optflags):
		if _DeDumpVAC == None:
			return 0
		if _DeDumpVAC._bIsReadyToDecompiling != True:
			return 0
		opt = Optimizer()
		ins.for_all_insns(opt)
		if opt.nChangesCount != 0:
			blk.mba.verify(True)
		return opt.nChangesCount

import ida_typeinf
def make_import_struct(name: str, members: list[str]):
    """
    Cria ou recria uma struct ‘name’ com os membros dados.
    Retorna o tid da struct.
    """
    # apaga se já existir
    sid = idc.get_struc_id(name)
    if sid != idc.BADADDR:
        idc.del_struc(sid)

    ptr_sz  = 8 if ida_ida.inf_is_64bit() else 4
    flag_sz = idc.FF_QWORD if ptr_sz == 8 else idc.FF_DWORD

    sid = idc.add_struc(-1, name, 0)        # agora via idc
    offset = 0
    for m in members:
        err = idc.add_struc_member(sid, m, offset, flag_sz, -1, ptr_sz)
        if err != 0:                         # TERR_* em IDA 9
            print(f"add_struc_member('{m}') falhou: {err}")
        offset += ptr_sz
    return sid

class DeDumpVAC(ida_idaapi.plugin_t):

	flags = ida_idaapi.PLUGIN_MOD
	wanted_name = 'DeDumpVAC'
	wanted_hotkey = 'Ctrl+Shift+V'
	comment = 'DeDumpVAC - VAC module auto decoding/fixing.\n'
	help = ''

	_bIsReadyToDecompiling = False

	_MicroCodeOptimizer = None

	_szInputFilePath = None
	_pInputFileData = None
	_nInputFileDataSize = 0

	_nMinEA = ida_idaapi.BADADDR
	_nMaxEA = ida_idaapi.BADADDR

	_nBeginDataAddressRAW = ida_idaapi.BADADDR
	_nBeginDataAddress = ida_idaapi.BADADDR

	_nImportingDataAddressRAW = ida_idaapi.BADADDR
	_nImportingNameOffsets = ida_idaapi.BADADDR
	_nImportingAddresses = ida_idaapi.BADADDR

	_nImportingCountAddressRAW = ida_idaapi.BADADDR
	_nImportingCount = 0

	_nImportingNamesAddressRAW = ida_idaapi.BADADDR
	_nImportingNamesAddress = ida_idaapi.BADADDR

	_nImportingModuleAddressesRAW = ida_idaapi.BADADDR
	_nImportingModuleAddresses = ida_idaapi.BADADDR

	_ImportingFunctions = list()

	def init(self):
		idc.msg('[DeDumpVAC] Info: Loading...\n')
		if ida_pro.IDA_SDK_VERSION < 750:
			idc.msg('[DeDumpVAC] Error: Optimal IDA version for DeDumpVAC is 7.5.\n')
			return ida_idaapi.PLUGIN_SKIP
		if ida_hexrays.init_hexrays_plugin():
			if self._MicroCodeOptimizer == None:
				self._MicroCodeOptimizer = MicroCodeOptimizer()
				self._MicroCodeOptimizer.install()
		idc.msg('[DeDumpVAC] Info: Loading successful.\n')
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		idc.msg('[DeDumpVAC] Info: Unloading...\n')
		self._bIsReadyToDecompiling = False
		if self._MicroCodeOptimizer:
			self._MicroCodeOptimizer.remove()
			self._MicroCodeOptimizer = None
		idc.msg('[DeDumpVAC] Info: Unloaded successful.\n')

	def run(self, arg = None):
		if ida_auto.auto_is_ok() != True:
			idc.msg('[DeDumpVAC] Error: The analysis is not finished.\n')
			return

		idc.msg('[DeDumpVAC] Info: Running...\n')

		if self._pInputFileData == None:
			self._szInputFilePath = ida_nalt.get_input_file_path()
			if len(self._szInputFilePath):
				hFile = open(self._szInputFilePath, 'rb')
				self._pInputFileData = bytearray(hFile.read())
				hFile.close()
				self._nInputFileDataSize = len(self._pInputFileData)

		if (self._pInputFileData == None) | (self._nInputFileDataSize == 0):
			idc.msg('[DeDumpVAC] Error: Unable to read input file.\n')
			return

		if self._nInputFileDataSize < ctypes.sizeof(DOS_HEADER):
			idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
			return

		pDH = DOS_HEADER.from_buffer_copy(self._pInputFileData)
		if (pDH.e_magic != MAGIC_DOS_SIGNATURE):
			idc.msg('[DeDumpVAC] Error: Invalid DOS magic signature.\n')
			return

		if self._nInputFileDataSize < ctypes.sizeof(VALVE_DOS_HEADER):
			idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
			return

		pVH = VALVE_DOS_HEADER.from_buffer_copy(self._pInputFileData)
		if (pVH.v_magic != MAGIC_VALVE_SIGNATURE):
			idc.msg('[DeDumpVAC] Error: Invalid VALVE magic signature. Ignoring...\n')
			return

		if VERBOSE_LEVEL >= 3:
			idc.msg('[DeDumpVAC] Verbose:\n')
			idc.msg(' > DOS_HEADER\n')
			idc.msg('  > e_magic = 0x{:04X}\n'.format(pDH.e_magic))
			idc.msg('  > e_cblp = 0x{:04X}\n'.format(pDH.e_cblp))
			idc.msg('  > e_cp = 0x{:04X}\n'.format(pDH.e_cp))
			idc.msg('  > e_crlc = 0x{:04X}\n'.format(pDH.e_crlc))
			idc.msg('  > e_cparhdr = 0x{:04X}\n'.format(pDH.e_cparhdr))
			idc.msg('  > e_minalloc = 0x{:04X}\n'.format(pDH.e_minalloc))
			idc.msg('  > e_maxalloc = 0x{:04X}\n'.format(pDH.e_maxalloc))
			idc.msg('  > e_ss = 0x{:04X}\n'.format(pDH.e_ss))
			idc.msg('  > e_sp = 0x{:04X}\n'.format(pDH.e_sp))
			idc.msg('  > e_csum = 0x{:04X}\n'.format(pDH.e_csum))
			idc.msg('  > e_ip = 0x{:04X}\n'.format(pDH.e_ip))
			idc.msg('  > e_cs = 0x{:04X}\n'.format(pDH.e_cs))
			idc.msg('  > e_lfarlc = 0x{:04X}\n'.format(pDH.e_lfarlc))
			idc.msg('  > e_ovno = 0x{:04X}\n'.format(pDH.e_ovno))
			if VERBOSE_LEVEL >= 4:
				idc.msg('  > e_res = [ ')
				for i in range(4):
					idc.msg('0x{:04X} '.format(i, pDH.e_res[i]))
				idc.msg(']\n')
			idc.msg('  > e_oemid = 0x{:04X}\n'.format(pDH.e_oemid))
			idc.msg('  > e_oeminfo = 0x{:04X}\n'.format(pDH.e_oeminfo))
			if VERBOSE_LEVEL >= 4:
				idc.msg('  > e_res2 = [ ')
				for i in range(10):
					idc.msg('0x{:04X} '.format(i, pDH.e_res2[i]))
				idc.msg(']\n')
			idc.msg('  > e_lfanew = 0x{:04X}\n'.format(pDH.e_lfanew))

		if VERBOSE_LEVEL >= 1:
			idc.msg('[DeDumpVAC] Verbose:\n')
			idc.msg(' > VALVE_HEADER\n')
			idc.msg('  > v_magic = 0x{:08X}\n'.format(pVH.v_magic))
			idc.msg('  > v_c = 0x{:08X} ({})\n'.format(pVH.v_c, 'Encrypted' if pVH.v_c else 'Non-Encrypted'))
			idc.msg('  > v_fs = 0x{:08X}\n'.format(pVH.v_fs))
			idc.msg('  > v_ts = 0x{:08X} ({})\n'.format(pVH.v_ts, datetime.datetime.fromtimestamp(pVH.v_ts).strftime('%Y-%m-%d %H:%M:%S')))
			if VERBOSE_LEVEL >= 2:
				idc.msg('  > v_cs = [ ')
				for i in range(128):
					idc.msg('0x{:02X} '.format(pVH.v_cs[i]))
				idc.msg(']\n')

		if pVH.v_c:
			idc.msg('[DeDumpVAC] Error: The file is encrypted.\n')
			return

		if pVH.v_fs != self._nInputFileDataSize:
			idc.msg('[DeDumpVAC] Error: The file size is not correct.\n')
			return

		if self._nInputFileDataSize < (ctypes.sizeof(VALVE_DOS_HEADER) + 4 + ctypes.sizeof(PE_FILE_HEADER)):
			idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
			return

		if int.from_bytes(self._pInputFileData[pDH.e_lfanew:pDH.e_lfanew + 4], 'little') != MAGIC_PE_SIGNATURE:
			idc.msg('[DeDumpVAC] Error: Invalid PE magic signature.\n')
			return

		pFH = PE_FILE_HEADER.from_buffer_copy(self._pInputFileData[pDH.e_lfanew + 4:])
		if pFH.Machine == PE_FILE_MACHINE_32B:
			if self._nInputFileDataSize < (ctypes.sizeof(VALVE_DOS_HEADER) + ctypes.sizeof(PE_HEADERS32)):
				idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
				return
			pNTHs = PE_HEADERS32.from_buffer_copy(self._pInputFileData[pDH.e_lfanew:])
		elif pFH.Machine == PE_FILE_MACHINE_64B:
			if self._nInputFileDataSize < (ctypes.sizeof(VALVE_DOS_HEADER) + ctypes.sizeof(PE_HEADERS64)):
				idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
				return
			pNTHs = PE_HEADERS64.from_buffer_copy(self._pInputFileData[pDH.e_lfanew:])
		else:
			idc.msg('[DeDumpVAC] Error: The processor architecture is not supported for this PE.\n')
			return
		del pFH

		if VERBOSE_LEVEL >= 3:
			idc.msg('[DeDumpVAC] Verbose:\n')
			idc.msg(' > PE_HEADERS\n')
			idc.msg('  > Signature = 0x{:08X}\n'.format(pNTHs.Signature))
			idc.msg('  > PE_FILE_HEADER\n')
			idc.msg('   > Machine = 0x{:04X}\n'.format(pNTHs.FileHeader.Machine))
			idc.msg('   > NumberOfSections = 0x{:04X}\n'.format(pNTHs.FileHeader.NumberOfSections))
			idc.msg('   > TimeDateStamp = 0x{:08X} ({})\n'.format(pNTHs.FileHeader.TimeDateStamp, datetime.datetime.fromtimestamp(pNTHs.FileHeader.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')))
			idc.msg('   > PointerToSymbolTable = 0x{:08X}\n'.format(pNTHs.FileHeader.PointerToSymbolTable))
			idc.msg('   > NumberOfSymbols = 0x{:08X}\n'.format(pNTHs.FileHeader.NumberOfSymbols))
			idc.msg('   > SizeOfOptionalHeader = 0x{:04X}\n'.format(pNTHs.FileHeader.SizeOfOptionalHeader))
			idc.msg('   > Characteristics = 0x{:04X}\n'.format(pNTHs.FileHeader.Characteristics))
			idc.msg('  > PE_OPTIONAL_HEADER\n')
			idc.msg('   > Magic = 0x{:04X}\n'.format(pNTHs.OptionalHeader.Magic))
			idc.msg('   > MajorLinkerVersion = 0x{:02X}\n'.format(pNTHs.OptionalHeader.MajorLinkerVersion))
			idc.msg('   > MinorLinkerVersion = 0x{:02X}\n'.format(pNTHs.OptionalHeader.MinorLinkerVersion))
			idc.msg('   > SizeOfCode = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SizeOfCode))
			idc.msg('   > SizeOfInitializedData = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SizeOfInitializedData))
			idc.msg('   > SizeOfUninitializedData = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SizeOfUninitializedData))
			idc.msg('   > AddressOfEntryPoint = 0x{:08X}\n'.format(pNTHs.OptionalHeader.AddressOfEntryPoint))
			idc.msg('   > BaseOfCode = 0x{:08X}\n'.format(pNTHs.OptionalHeader.BaseOfCode))
			idc.msg('   > BaseOfData = 0x{:08X}\n'.format(pNTHs.OptionalHeader.BaseOfData))
			idc.msg('   > ImageBase = 0x{:X}\n'.format(pNTHs.OptionalHeader.ImageBase))
			idc.msg('   > SectionAlignment = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SectionAlignment))
			idc.msg('   > FileAlignment = 0x{:08X}\n'.format(pNTHs.OptionalHeader.FileAlignment))
			idc.msg('   > MajorOperatingSystemVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MajorOperatingSystemVersion))
			idc.msg('   > MinorOperatingSystemVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MinorOperatingSystemVersion))
			idc.msg('   > MajorImageVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MajorImageVersion))
			idc.msg('   > MajorImageVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MinorImageVersion))
			idc.msg('   > MajorSubsystemVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MajorSubsystemVersion))
			idc.msg('   > MinorSubsystemVersion = 0x{:04X}\n'.format(pNTHs.OptionalHeader.MinorSubsystemVersion))
			idc.msg('   > Win32VersionValue = 0x{:08X}\n'.format(pNTHs.OptionalHeader.Win32VersionValue))
			idc.msg('   > SizeOfImage = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SizeOfImage))
			idc.msg('   > SizeOfHeaders = 0x{:08X}\n'.format(pNTHs.OptionalHeader.SizeOfHeaders))
			idc.msg('   > CheckSum = 0x{:08X}\n'.format(pNTHs.OptionalHeader.CheckSum))
			idc.msg('   > Subsystem = 0x{:04X}\n'.format(pNTHs.OptionalHeader.Subsystem))
			idc.msg('   > DllCharacteristics = 0x{:04X}\n'.format(pNTHs.OptionalHeader.DllCharacteristics))
			idc.msg('   > SizeOfStackReserve = 0x{:X}\n'.format(pNTHs.OptionalHeader.SizeOfStackReserve))
			idc.msg('   > SizeOfStackCommit = 0x{:X}\n'.format(pNTHs.OptionalHeader.SizeOfStackCommit))
			idc.msg('   > SizeOfHeapReserve = 0x{:X}\n'.format(pNTHs.OptionalHeader.SizeOfHeapReserve))
			idc.msg('   > SizeOfHeapCommit = 0x{:X}\n'.format(pNTHs.OptionalHeader.SizeOfHeapCommit))
			idc.msg('   > LoaderFlags = 0x{:08X}\n'.format(pNTHs.OptionalHeader.LoaderFlags))
			idc.msg('   > NumberOfRvaAndSizes = 0x{:08X}\n'.format(pNTHs.OptionalHeader.NumberOfRvaAndSizes))
			if VERBOSE_LEVEL >= 4:
				idc.msg('   > DataDirectory\n')
				for i in range(pNTHs.OptionalHeader.NumberOfRvaAndSizes):
					idc.msg('    > {}\n'.format(PE_DATA_DIRECTORY_ENUM(i).name))
					idc.msg('     > VirtualAddress = 0x{:08X}\n'.format(pNTHs.OptionalHeader.DataDirectory[i].VirtualAddress))
					idc.msg('     > Size = 0x{:08X}\n'.format(pNTHs.OptionalHeader.DataDirectory[i].Size))

		if self._nInputFileDataSize < (ctypes.sizeof(VALVE_DOS_HEADER) + ctypes.sizeof(pNTHs) + ctypes.sizeof(PE_SECTION_HEADER) * pNTHs.FileHeader.NumberOfSections):
			idc.msg('[DeDumpVAC] Error: The file size is too small. Ignoring...\n')
			return

		pSections = ctypes.ARRAY(PE_SECTION_HEADER, pNTHs.FileHeader.NumberOfSections).from_buffer_copy(self._pInputFileData[pDH.e_lfanew + ctypes.sizeof(pNTHs) - ctypes.sizeof(pNTHs.OptionalHeader) + pNTHs.FileHeader.SizeOfOptionalHeader:])
		if VERBOSE_LEVEL >= 4:
			idc.msg('[DeDumpVAC] Verbose:\n')
			idc.msg(' > PE_SECTION_HEADER\n')
			for i in range(pNTHs.FileHeader.NumberOfSections):
				idc.msg('  > [{}]\n'.format(i))
				idc.msg('   > Name = `{}`\n'.format(ctypes.cast(pSections[i].Name, ctypes.c_char_p).value.decode('latin-1')))
				idc.msg('   > VirtualAddress = 0x{:08X}\n'.format(pSections[i].VirtualAddress))
				idc.msg('   > SizeOfRawData = 0x{:08X}\n'.format(pSections[i].SizeOfRawData))
				idc.msg('   > PointerToRawData = 0x{:08X}\n'.format(pSections[i].PointerToRawData))
				idc.msg('   > PointerToRelocations = 0x{:08X}\n'.format(pSections[i].PointerToRelocations))
				idc.msg('   > PointerToLinenumbers = 0x{:08X}\n'.format(pSections[i].PointerToLinenumbers))
				idc.msg('   > NumberOfRelocations = 0x{:04X}\n'.format(pSections[i].NumberOfRelocations))
				idc.msg('   > NumberOfLinenumbers = 0x{:04X}\n'.format(pSections[i].NumberOfLinenumbers))
				idc.msg('   > Characteristics = 0x{:08X}\n'.format(pSections[i].Characteristics))

		nTimeDateStamp = 0

		DebugDataDirectory = pNTHs.OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_ENUM.PE_DATA_DIRECTORY_DEBUG]
		if DebugDataDirectory.VirtualAddress & DebugDataDirectory.Size:
			nDebugCount = math.ceil(DebugDataDirectory.Size / ctypes.sizeof(PE_DATA_DEBUG_DIRECTORY))

			if (nDebugCount * ctypes.sizeof(PE_DATA_DEBUG_DIRECTORY)) != DebugDataDirectory.Size:
				idc.msg('[DeDumpVAC] Error: The debug information is corrupted.\n')
				return

			for i in range(pNTHs.FileHeader.NumberOfSections):
				if (DebugDataDirectory.VirtualAddress >= pSections[i].VirtualAddress) & (DebugDataDirectory.VirtualAddress < (pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize)):
					nDelta = pSections[i].VirtualAddress - pSections[i].PointerToRawData
					pDebugDataDirectories = ctypes.ARRAY(PE_DATA_DEBUG_DIRECTORY, nDebugCount).from_buffer_copy(self._pInputFileData[DebugDataDirectory.VirtualAddress - nDelta:])
					for i in range(nDebugCount):
						if nTimeDateStamp < pDebugDataDirectories[i].TimeDateStamp:
							nTimeDateStamp = pDebugDataDirectories[i].TimeDateStamp					
					break

		if nTimeDateStamp:
			idc.msg('[DeDumpVAC] Info: Date and time of compilation: {}\n'.format(datetime.datetime.fromtimestamp(nTimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')))

		self._nMinEA = ida_ida.inf_get_min_ea()
		self._nMaxEA = ida_ida.inf_get_max_ea()

		bFoundRunFunction = False
		AllFunctions = list()
		nFunctionAddress = idc.get_next_func(self._nMinEA)
		while IsNotValidAddress(nFunctionAddress) != True:
			AllFunctions.append(nFunctionAddress)
			if (bFoundRunFunction != True) & (idc.get_func_name(nFunctionAddress) == '_runfunc@20'):
				idc.msg('[DeDumpVAC] Info: Found `_runfunc@20` at 0x{:X} address.\n'.format(nFunctionAddress))
				bFoundRunFunction = True
			nFunctionAddress = idc.get_next_func(nFunctionAddress)

		if bFoundRunFunction != True:
			idc.msg('[DeDumpVAC] Error: Not found `_runfunc@20` address.\n')
			return

		self._nBeginDataAddressRAW = search_for_bytes(BEGIN_DATA_ADDRESS_SIGNATURE, self._nMinEA, self._nMaxEA)
		if IsNotValidAddress(self._nBeginDataAddressRAW):
			idc.msg('[DeDumpVAC] Error: Signature `{}` (BEGIN_DATA_ADDRESS_SIGNATURE) not found.\n'.format(BEGIN_DATA_ADDRESS_SIGNATURE))
			return

		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			self._nBeginDataAddress = ida_bytes.get_qword(self._nBeginDataAddressRAW + 1)
		else:
			self._nBeginDataAddress = ida_bytes.get_dword(self._nBeginDataAddressRAW + 1)

		if IsNotValidAddress(self._nBeginDataAddress):
			idc.msg('[DeDumpVAC] Error: Invalid `{}` address.'.format(BEGIN_DATA_NAME))
			return

		idc.set_name(self._nBeginDataAddress, BEGIN_DATA_NAME, idc.SN_NOWARN)
		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			idc.set_name(self._nBeginDataAddress + 8, '{}{}'.format(IMPORT_FUNCTIONS_PREFIX, 'InternalGetProcAddress'), idc.SN_NOWARN)
			ida_bytes.create_dword(self._nBeginDataAddress + 4, 4)
		else:
			idc.set_name(self._nBeginDataAddress + 4, '{}{}'.format(IMPORT_FUNCTIONS_PREFIX, 'InternalGetProcAddress'), idc.SN_NOWARN)
			ida_bytes.create_qword(self._nBeginDataAddress + 8, 8)

		bIsAlt = False

		self._nImportingDataAddressRAW = search_for_bytes(IMPORTING_DATA_ADDRESS_SIGNATURE, self._nMinEA, self._nMaxEA)
		if IsNotValidAddress(self._nImportingDataAddressRAW):
			idc.msg('[DeDumpVAC] Warning: Signature `{}` (IMPORTING_DATA_ADDRESS_SIGNATURE) not found.\n'.format(IMPORTING_DATA_ADDRESS_SIGNATURE))
			bIsAlt = True
			self._nImportingDataAddressRAW = search_for_bytes(IMPORTING_DATA_ADDRESS_SIGNATURE_ALT, self._nMinEA, self._nMaxEA)
			if IsNotValidAddress(self._nImportingDataAddressRAW):
				idc.msg('[DeDumpVAC] Error: Signature `{}` (IMPORTING_DATA_ADDRESS_SIGNATURE_ALT) not found.\n'.format(IMPORTING_DATA_ADDRESS_SIGNATURE_ALT))
				return

		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			self._nImportingNameOffsets = ida_bytes.get_qword(self._nImportingDataAddressRAW + 1)
		else:
			self._nImportingNameOffsets = ida_bytes.get_dword(self._nImportingDataAddressRAW + 1)

		if IsNotValidAddress(self._nImportingNameOffsets):
			idc.msg('[DeDumpVAC] Error: Invalid address of importing function name offsets.\n')
			return

		if bIsAlt:
			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				self._nImportingAddresses = ida_bytes.get_qword(self._nImportingDataAddressRAW + 6)
			else:
				self._nImportingAddresses = ida_bytes.get_dword(self._nImportingDataAddressRAW + 6)
		else:
			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				self._nImportingAddresses = ida_bytes.get_qword(self._nImportingDataAddressRAW + 9)
			else:
				self._nImportingAddresses = ida_bytes.get_dword(self._nImportingDataAddressRAW + 9)

		if IsNotValidAddress(self._nImportingAddresses):
			idc.msg('[DeDumpVAC] Error: Invalid address of importing functions addresses.\n')
			return

		self._nImportingCountAddressRAW = search_for_bytes(IMPORTING_COUNT_ADDRESS_SIGNATURE, self._nMinEA, self._nMaxEA)
		if IsNotValidAddress(self._nImportingCountAddressRAW):
			idc.msg('[DeDumpVAC] Error: Signature `{}` (IMPORTING_COUNT_ADDRESS_SIGNATURE) not found.\n'.format(IMPORTING_COUNT_ADDRESS_SIGNATURE))
			return

		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			self._nImportingCount = ida_bytes.get_qword(self._nImportingCountAddressRAW + 6)
		else:
			self._nImportingCount = ida_bytes.get_dword(self._nImportingCountAddressRAW + 6)

		if self._nImportingCount:
			idc.msg('[DeDumpVAC] Info: Count of imported functions is {}\n'.format(self._nImportingCount))

		bIsAlt = False

		self._nImportingNamesAddressRAW = search_for_bytes(IMPORTING_NAMES_ADDRESS_SIGNATURE, self._nMinEA, self._nMaxEA)
		if IsNotValidAddress(self._nImportingNamesAddressRAW):
			idc.msg('[DeDumpVAC] Warning: Signature `{}` (IMPORTING_NAMES_ADDRESS_SIGNATURE) not found.\n'.format(IMPORTING_NAMES_ADDRESS_SIGNATURE))
			self._nImportingNamesAddressRAW = search_for_bytes(IMPORTING_NAMES_ADDRESS_SIGNATURE_ALT, self._nMinEA, self._nMaxEA)
			if IsNotValidAddress(self._nImportingNamesAddressRAW):
				idc.msg('[DeDumpVAC] Error: Signature `{}` (IMPORTING_NAMES_ADDRESS_SIGNATURE_ALT) not found.\n'.format(IMPORTING_NAMES_ADDRESS_SIGNATURE_ALT))
				return

		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			self._nImportingNamesAddress = ida_bytes.get_qword(self._nImportingNamesAddressRAW + 2)
		else:
			self._nImportingNamesAddress = ida_bytes.get_dword(self._nImportingNamesAddressRAW + 2)

		if IsNotValidAddress(self._nImportingNamesAddress):
			idc.msg('[DeDumpVAC] Error: Invalid address of importing functions names.\n')
			return

		ImportingFunctions = list()
		nImportingNameOffsets = self._nImportingNameOffsets
		nImportingAddresses = self._nImportingAddresses
		nCount = 0
		while nCount < self._nImportingCount:
			nImportingModuleNameAddress = ida_idaapi.BADADDR
			szImportingModuleName = None
			nImportingFunctionNameAddress = ida_idaapi.BADADDR
			szImportingFunctionName = None

			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				nImportingModuleNameAddress = self._nImportingNamesAddress + ida_bytes.get_qword(nImportingNameOffsets)
			else:
				nImportingModuleNameAddress = self._nImportingNamesAddress + ida_bytes.get_dword(nImportingNameOffsets)

			if IsNotValidAddress(nImportingModuleNameAddress):
				break

			try:
				szImportingModuleName = ida_bytes.get_strlit_contents(nImportingModuleNameAddress, -1, -1).decode()
			except:
				break

			if szImportingModuleName.isascii() != True:
				break

			ida_bytes.create_strlit(nImportingModuleNameAddress, len(szImportingModuleName), 0)

			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				nImportingFunctionNameAddress = self._nImportingNamesAddress + ida_bytes.get_qword(nImportingNameOffsets + 8)
			else:
				nImportingFunctionNameAddress = self._nImportingNamesAddress + ida_bytes.get_dword(nImportingNameOffsets + 4)

			if IsNotValidAddress(nImportingFunctionNameAddress):
				break

			try:
				szImportingFunctionName = ida_bytes.get_strlit_contents(nImportingFunctionNameAddress, -1, -1).decode()
			except:
				break

			if szImportingFunctionName.isascii() != True:
				break

			ida_bytes.create_strlit(nImportingFunctionNameAddress, len(szImportingFunctionName), 0)

			bFoundSameModule = False
			for ImportingFunction in ImportingFunctions:
				if ImportingFunction['szImportingModuleName'] == szImportingModuleName:
					bFoundSameModule = True
					break

			if bFoundSameModule != True:
				ImportingFunction = dict()
				ImportingFunction['szImportingModuleName'] = szImportingModuleName
				ImportingFunction['nImportingModuleAddress'] = ida_idaapi.BADADDR
				ImportingFunction['Functions'] = dict()

			ImportingFunction['Functions'].update({ nImportingAddresses: szImportingFunctionName })

			if bFoundSameModule != True:
				ImportingFunctions.append(ImportingFunction)

			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				nImportingNameOffsets += 16
			else:
				nImportingNameOffsets += 8

			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				nImportingAddresses += 8
			else:
				nImportingAddresses += 4

			nCount += 1

		bIsAlt = False

		self._nImportingModuleAddressesRAW = search_for_bytes(IMPORTING_MODULE_ADDRESSES_SIGNATURE, self._nMinEA, self._nMaxEA)
		if IsNotValidAddress(self._nImportingModuleAddressesRAW):
			idc.msg('[DeDumpVAC] Warning: Signature `{}` (IMPORTING_MODULE_ADDRESSES_SIGNATURE) not found.\n'.format(IMPORTING_MODULE_ADDRESSES_SIGNATURE))
			self._nImportingModuleAddressesRAW = search_for_bytes(IMPORTING_MODULE_ADDRESSES_SIGNATURE_ALT, self._nMinEA, self._nMaxEA)
			if IsNotValidAddress(self._nImportingModuleAddressesRAW):
				idc.msg('[DeDumpVAC] Error: Signature `{}` (IMPORTING_MODULE_ADDRESSES_SIGNATURE_ALT) not found.\n'.format(IMPORTING_MODULE_ADDRESSES_SIGNATURE_ALT))
				return

		if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
			self._nImportingModuleAddresses = ida_bytes.get_qword(self._nImportingModuleAddressesRAW + 3)
		else:
			self._nImportingModuleAddresses = ida_bytes.get_dword(self._nImportingModuleAddressesRAW + 3)

		nImportingModuleAddresses = self._nImportingModuleAddresses
		for _ImportingFunctions in ImportingFunctions:
			_ImportingFunctions['nImportingModuleAddress'] = nImportingModuleAddresses
			szImportingModuleName = _ImportingFunctions['szImportingModuleName']
			idc.set_name(nImportingModuleAddresses, '{}{}'.format(IMPORT_MODULES_PREFIX, szImportingModuleName.replace('.dll', '').upper()), idc.SN_NOWARN)
			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				ida_bytes.create_qword(nImportingModuleAddresses, 8)
			else:
				ida_bytes.create_dword(nImportingModuleAddresses, 4)
			if VERBOSE_LEVEL >= 2:
				idc.msg('Module [ 0x{:X} ]: {}\n'.format(nImportingModuleAddresses, szImportingModuleName))
			for nFunctionAddress in _ImportingFunctions['Functions'].keys():
				szImportingFunctionName = _ImportingFunctions['Functions'][nFunctionAddress]
				idc.set_name(nFunctionAddress, '{}{}'.format(IMPORT_FUNCTIONS_PREFIX, szImportingFunctionName), idc.SN_NOWARN)
				if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
					ida_bytes.create_qword(nFunctionAddress, 8)
				else:
					ida_bytes.create_dword(nFunctionAddress, 4)
				if VERBOSE_LEVEL >= 2:
					idc.msg(' > Function [ 0x{:X} ]: {}\n'.format(nFunctionAddress, szImportingFunctionName))
			if pNTHs.FileHeader.Machine == PE_FILE_MACHINE_64B:
				nImportingModuleAddresses += 8
			else:
				nImportingModuleAddresses += 4

			nReferenceAddress = ida_xref.get_first_dref_to(self._nBeginDataAddress)
			while IsNotValidAddress(nReferenceAddress) != True:
				for FunctionBegin in AllFunctions:
					FunctionEnd = idc.find_func_end(FunctionBegin)
					if (FunctionEnd >= nReferenceAddress) & (FunctionBegin <= nReferenceAddress):
						MNEM = idc.print_insn_mnem(nReferenceAddress)
						if MNEM != 'mov':
							continue
						insn = ida_ua.insn_t()
						if ida_ua.decode_insn(insn, nReferenceAddress):
							FirstOperand = insn.ops[0]
							if FirstOperand.type != ida_ua.o_reg:
								continue
							nRegisterType = FirstOperand.reg
							for nAddress in range(nReferenceAddress, FunctionEnd):
								MNEM = idc.print_insn_mnem(nAddress)
								if MNEM != 'call':
									continue
								insn = ida_ua.insn_t()
								if ida_ua.decode_insn(insn, nAddress):
									FirstOperand = insn.ops[0]
									if FirstOperand.type != ida_ua.o_displ:
										continue
									if FirstOperand.reg == nRegisterType:
										DISP = FirstOperand.addr
										for _ImportingFunctions in ImportingFunctions:
											for Function in _ImportingFunctions['Functions'].keys():
												if self._nImportingAddresses + DISP == Function:
													ida_bytes.set_forced_operand(nAddress, 0, '{}{}'.format(IMPORT_FUNCTIONS_PREFIX, _ImportingFunctions['Functions'][Function]))
				nReferenceAddress = ida_xref.get_next_dref_to(self._nBeginDataAddress, nReferenceAddress)

		for _ImportingFunctions in ImportingFunctions:
			self._ImportingFunctions.append(_ImportingFunctions)

		names = [
			fn_name
			for imp in self._ImportingFunctions
			for fn_name in imp["Functions"].values()
		]

		names = list(dict.fromkeys(names))

		make_import_struct("vac_tests", names)
		idc.msg('[DeDumpVAC] Info: Process finished.\n')
		self._bIsReadyToDecompiling = True
		return

bIsPluginMode = False
def PLUGIN_ENTRY():
	global _DeDumpVAC
	global bIsPluginMode
	if _DeDumpVAC == None:
		_DeDumpVAC = DeDumpVAC()
	bIsPluginMode = True
	idc.msg('[DeDumpVAC] Info: PluginMode activated.\n')
	return _DeDumpVAC

if __name__ == '__main__':
	if bIsPluginMode != True:
		idc.msg('[DeDumpVAC] Info: ScriptMode activated.\n')
		if ida_pro.IDA_SDK_VERSION < 750:
			idc.msg('[DeDumpVAC] Error: Optimal IDA version for DeDumpVAC is 7.5.\n')
		else:
			DeDumpVAC().run()
