#!/usr/bin/env python3
"""ARM64 ABL module annotation helpers for the ZenFone 10 portability study.

Module VA convention: module = payload[0xC8:], VA == offset within module
(same convention as work/disasm.py for the ZF8 module).

dis()/describe() print a linear disassembly with:
  - adrp/add pairs resolved to string literals or data addresses
  - bl targets annotated with the first string literal the callee references
  - known command-handler table entries from the ZF10 dispatcher tables
"""
import capstone, struct, sys

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True


def load_module(payload_path, base=0xC8):
    return open(payload_path, 'rb').read()[base:]


def ascii_at(mod, va, maxlen=60):
    if va <= 0 or va >= len(mod) - 4:
        return None
    e = mod.find(b'\x00', va, va + maxlen)
    if e < 0:
        return None
    s = mod[va:e]
    if len(s) >= 3 and all(32 <= c < 127 for c in s):
        return s.decode()
    # utf16?
    return None


def utf16_at(mod, va, maxlen=60):
    if va <= 0 or va >= len(mod) - 8:
        return None
    out = []
    i = va
    while i < va + maxlen and i + 1 < len(mod):
        c = mod[i] | (mod[i + 1] << 8)
        if c == 0:
            break
        if not (32 <= c < 127):
            return None
        out.append(chr(c))
        i += 2
    return ''.join(out) if len(out) >= 3 else None


def first_strings(mod, fn, maxins=60, maxrefs=4):
    """Scan the first maxins instructions of fn for adrp+add string refs."""
    refs = []
    adrp = {}
    try:
        for insn in md.disasm(mod[fn:fn + maxins * 4], fn):
            if insn.mnemonic == 'ret' and len(refs) >= 1 and insn.address > fn:
                break
            ops = insn.operands
            if insn.mnemonic == 'adrp':
                adrp[insn.reg_name(ops[0].reg)] = ops[1].imm
            elif insn.mnemonic == 'add' and len(ops) == 3 and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                rd = insn.reg_name(ops[0].reg)
                if rd in adrp:
                    va = adrp[rd] + ops[2].imm
                    s = ascii_at(mod, va) or utf16_at(mod, va)
                    if s and (not refs or refs[-1][0] != s):
                        refs.append((s, va))
                        if len(refs) >= maxrefs:
                            break
    except Exception:
        pass
    return refs


def bl_annotation(mod, target, cache={}):
    if target in cache:
        return cache[target]
    refs = first_strings(mod, target)
    ann = '' if not refs else '  ; fn-> ' + ' | '.join(f'"{s}"' for s, _ in refs)
    cache[target] = ann
    return ann


def dis(mod, start, end, show_bl_strings=True, maxdepth=0):
    adrp = {}
    for insn in md.disasm(mod[start:end], start):
        ops = insn.operands
        note = ''
        if insn.mnemonic == 'adrp':
            adrp[insn.reg_name(ops[0].reg)] = ops[1].imm
        elif insn.mnemonic == 'add' and len(ops) == 3 and ops[2].type == capstone.arm64.ARM64_OP_IMM:
            rd = insn.reg_name(ops[0].reg)
            if rd in adrp:
                va = adrp[rd] + ops[2].imm
                s = ascii_at(mod, va) or utf16_at(mod, va)
                if s:
                    note = f'  ; "{s[:56]}"'
                else:
                    note = f'  ; ={va:#x}'
        elif insn.mnemonic == 'bl' and show_bl_strings and ops and ops[0].type == capstone.arm64.ARM64_OP_IMM:
            note = bl_annotation(mod, ops[0].imm)
        print(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}')


def find_string_vas(mod, s, utf16=False):
    if utf16:
        pat = s.encode('utf-16-le')
    else:
        pat = s.encode('ascii') + b'\x00'
    out = []
    i = 0
    while True:
        i = mod.find(pat, i)
        if i < 0:
            return out
        out.append(i)
        i += 1


def adrp_add_xrefs(mod, target_va, window=0x100, tol=0):
    """All ADRP+ADD pairs resolving to target_va (module VA space)."""
    words = struct.unpack_from('<%dI' % ((len(mod) - 8) // 4), mod)
    hits = []
    adrp_hist = {}
    for i, w in enumerate(words):
        pc = i * 4
        if (w & 0x9F000000) == 0x90000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            adrp_hist[w & 0x1F] = (pc, (pc & ~0xFFF) + (imm << 12))
        elif (w & 0x9F000000) == 0x91000000:
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 3
            addv = (imm12 << 12) if sh else imm12
            rn = (w >> 5) & 0x1F
            if rn in adrp_hist and pc - adrp_hist[rn][0] < window:
                va = adrp_hist[rn][1] + addv
                if va == target_va or (target_va - tol <= va <= target_va + tol):
                    hits.append((pc, va))
    return hits


if __name__ == '__main__':
    payload = sys.argv[1]
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0) if len(sys.argv) > 3 else start + 0x200
    mod = load_module(payload)
    dis(mod, start, end)
