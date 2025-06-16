# -*- coding: utf-8 -*-
#
#  vac_vars9x.py – Renomeia variáveis / funções VAC sem depender de
#                  find_binary do IDA (compatível com qualquer 7.x-9.x)
#
#  Uso:  File ▸ Script file…  → vac_vars9x.py
#

import ida_ida
import ida_bytes
import ida_name
import idc

# ───────────────────────── helpers low-level ──────────────────────────────
BIN_BEGIN = ida_ida.inf_get_min_ea()
BIN_END   = ida_ida.inf_get_max_ea()

def parse_pattern(pat: str):
    """
    Converte "AA BB ? ?" → (b'\xAA\xBB\x00\x00', b'\xFF\xFF\x00\x00')
    onde mask[i]==0 é wildcard.
    """
    tokens = pat.strip().split()
    data = bytearray()
    mask = bytearray()
    for t in tokens:
        if t == '?' or t == '??':
            data.append(0x00)
            mask.append(0x00)
        else:
            data.append(int(t, 16))
            mask.append(0xFF)
    return bytes(data), bytes(mask)

def my_find_binary(pat: str, start=BIN_BEGIN, end=BIN_END) -> int:
    data, mask = parse_pattern(pat)
    size       = len(data)
    ea         = start
    CHUNK      = 0x1000

    while ea + size <= end:
        chunk = ida_bytes.get_bytes(ea, CHUNK)
        if not chunk:
            ea += CHUNK
            continue

        # pesquisa dentro do chunk (janela deslizante)
        limit = min(len(chunk) - size + 1, CHUNK)
        for off in range(limit):
            if all((chunk[off+i] ^ data[i]) & mask[i] == 0 for i in range(size)):
                return ea + off
        ea += CHUNK
    return -1  # não achou

def get_dw(ea): return ida_bytes.get_wide_dword(ea)
def rename(ea, nm): ida_name.set_name(ea, nm, ida_name.SN_NOWARN)

# ───────────────────────────── tabelas ────────────────────────────────────
known_vars = [
    ("g_stdin",                   "A3 ? ? ? ? 47",                   1),
    ("g_stdout",                  "A3 ? ? ? ? 89 3D ? ? ? ? FF",     1),
    ("g_stderr",                  "A3 ? ? ? ? 89 3D ? ? ? ? E8",     1),
    ("ice_sboxes_initialised",    "89 3D ? ? ? ? 89",                2),
    ("ice_keyrot",                "68 ? ? ? ? 56 8D",                1),
    ("g_initial_ice_key",         "8B 35 ? ? ? ? 89",                2),
    ("g_primary_ice_key",         "A3 ? ? ? ? C7",                   1, 0x10),
    ("g_encrypted_imports",       "B9 ? ? ? ? 68",                   1),
    ("g_initialize_imports",      "83 3D ? ? ? ? ? 74 14",           2),
]

known_funcs = [
    ("malloc",              "51 6A 00 FF 15 ? ? ? ? 50 FF 15 ? ? ? ? C3 51 6A"),
    ("free",                "51 6A 00 FF 15 ? ? ? ? 50 FF 15 ? ? ? ? C3 51 53"),
    ("free",                "51 6A 00 FF 15 ? ? ? ? 50 FF 15 ? ? ? ? C3 52"),
    ("realloc",             "52 85"),
    ("memset",              "8B 4C 24 0C 85"),
    ("InitializeImports",   "83 3D ? ? ? ? ? 74 14"),
    ("DecryptSection",      "55 8B EC 83 EC 0C 53 56 57 8B D9"),
    ("IceKey::IceKey",      "56 57 33 FF"),
    ("ice_sboxes_init",     "53 56 57 33"),
    ("IceKey::set",         "83 EC 0C 53 55"),
    ("IceKey::scheduleBuild","83 EC 14 53 55 56 33"),
    ("IceKey::decrypt",     "8B 54 24 04 53 55 8B E9 0F"),
    ("IceKey::encrypt",     "55 8B EC 8B"),
    ("gf_exp7",             "56 8B F1 57 8B FA"),
    ("gf_mult",             "53 56 57 8B FA"),
    ("ice_perm32",          "33 C0 BA"),
    ("ice_f",               "53 55 56 8B F1 BD"),
    ("IceKey::~IceKey",     "53 33 DB 56 8B F3"),
    ("_CompareStringW@24",  "FF 74 24 04"),
]

# ───────────────────────────── execução ───────────────────────────────────
print("─── variáveis ─────────────────────────────")
for item in known_vars:
    name, sig, disp, *extra = item
    ea_sig = my_find_binary(sig)
    if ea_sig == -1:
        print(f"[!] {name:<26} não encontrado")
        continue

    target = get_dw(ea_sig + disp)
    if extra:
        target += extra[0]

    rename(target, name)
    print(f"[+] {name:<26} @ {target:08X}")

print("\n─── funções ───────────────────────────────")
for name, sig in known_funcs:
    ea = my_find_binary(sig)
    if ea == -1:
        print(f"[!] {name:<26} não encontrado")
        continue
    rename(ea, name)
    print(f"[+] {name:<26} @ {ea:08X}")

print("\n[FIM] Tudo concluído!")
