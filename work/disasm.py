#!/usr/bin/env python3
"""Disassemble a VA range from abl_linuxloader.efi (.text rawoff == vaddr)."""
import sys
import capstone

BASE_FILE = "/Users/smales/Development/zenfone8/work/abl_linuxloader.efi"

def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    data = open(BASE_FILE, "rb").read()[start:end]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    adrp_regs = {}
    for insn in md.disasm(data, start):
        ops = insn.operands
        note = ""
        if insn.mnemonic == "adrp":
            adrp_regs[insn.reg_name(ops[0].reg)] = ops[1].imm
        elif insn.mnemonic == "add" and len(ops) == 3 and ops[2].type == capstone.arm64.ARM64_OP_IMM:
            rd = insn.reg_name(ops[0].reg)
            if rd in adrp_regs and adrp_regs[rd] + ops[2].imm >= 0x1000:
                note = f"  ; = {adrp_regs[rd]+ops[2].imm:#x}"
        elif insn.mnemonic in ("bl", "b") and ops and ops[0].type == capstone.arm64.ARM64_OP_IMM:
            note = f"  ; -> {ops[0].imm:#x}"
        print(f"{insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}{note}")

if __name__ == "__main__":
    main()
