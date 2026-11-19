#!/usr/bin/env python3
"""
Unicorn emulation harness for ASUS ZenFone 8 ABL (LinuxLoader.efi, SM8350).

Maps the PE image (rawoff == vaddr, identity) plus scratch memory, stubs the
frame-chain tracker (0x31480) with a code hook, and runs selected functions:

  - run_md5(data)          -> 16-byte digest   (0x3c330 Init / 0x3c370 Update / 0x3c3b0 Final)
  - run_mix1(d,c,b,a)      -> mixed 4-tuple     (0x46528)
  - run_mix2(d,c,b,a)      -> mixed 4-tuple     (0x46598)
  - run_transform(hex32)   -> 64-char response  (0x46608, key_select=1)
  - run_gen_hash(challenge, key_select) -> 64-char calc hash (0x4690c cmd_oem_gen_hash)
"""
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP,
)

EFI = "/Users/smales/Development/zenfone8/work/abl_linuxloader.efi"
MAGIC = 0x0F00D000  # fake return address: emu_start() halts here

# addresses (static, base-0 view)
FRAME_TRACKER = 0x31480
MD5_INIT, MD5_UPDATE, MD5_FINAL = 0x3C330, 0x3C370, 0x3C3B0
MIX1, MIX2 = 0x46528, 0x46598
TRANSFORM = 0x46608
GEN_HASH = 0x4690C
CHALLENGE_BUF = 0x1FE3AA
CALC_HASH_BUF = 0x1FE6CC

# scratch layout
STACK = 0x40000000
STACK_SIZE = 0x200000
STACK_TOP = 0x40080000
VSTACK = 0x60000000          # "virtual frame chain" locals area
VSTACK_SIZE = 0x100000
VSTACK_TOP = 0x60080000
G_ADDR = 0x50000800          # synthetic frame-chain global (address returned by stub)


class AblEmu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        uc = self.uc
        pe = open(EFI, "rb").read()

        # image 0x1000 .. 0x203000 (rawoff == vaddr)
        uc.mem_map(0x1000, 0x203000)
        uc.mem_write(0x1000, pe[0x1000:0x203000])

        # disable serial-DEBUG paths: flag byte at 0x7bd35 (bit1), mask at 0x7bd38
        uc.mem_write(0x7bd35, b"\x00")
        uc.mem_write(0x7bd38, b"\x00\x00\x00\x00")

        # stacks / scratch
        uc.mem_map(STACK, STACK_SIZE)
        uc.mem_map(VSTACK, VSTACK_SIZE)
        uc.mem_map(0x50000000, 0x1000)
        uc.mem_write(G_ADDR, struct.pack("<Q", VSTACK_TOP))

        # stub the frame-chain tracker: x0 = &G ; pc = lr
        def stub(uc, address, size, user_data):
            uc.reg_write(UC_ARM64_REG_X0, G_ADDR)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        uc.hook_add(UC_HOOK_CODE, stub, begin=FRAME_TRACKER, end=FRAME_TRACKER)

        # scratch i/o buffers (inside the frame-chain locals area page)
        self.io = 0x60090000  # plain scratch page for args/results

    # ---------------- low-level helpers ----------------
    def _reset_frame_chain(self):
        self.uc.mem_write(G_ADDR, struct.pack("<Q", VSTACK_TOP))

    def _call(self, entry, args=(), timeout_usec=20_000_000):
        """Call a function; args = list of (regconst, value) or plain ints for x0..x3."""
        uc = self.uc
        self._reset_frame_chain()
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3]
        for i, a in enumerate(args):
            if isinstance(a, tuple):
                rc, v = a
                uc.reg_write(rc, v)
            else:
                uc.reg_write(regs[i], a)
        uc.reg_write(UC_ARM64_REG_X30, MAGIC)
        uc.emu_start(entry, MAGIC, timeout=timeout_usec)

    # ---------------- MD5 ----------------
    def run_md5(self, data: bytes) -> bytes:
        uc = self.uc
        ctx = self.io + 0x0000   # md5 context (needs some room)
        dig = self.io + 0x0200
        src = self.io + 0x0400
        uc.mem_write(src, data)
        self._call(MD5_INIT, [ctx])
        # Update takes (ctx, data, len): x0 ctx, x1 data, x2 len
        self._call(MD5_UPDATE, [(UC_ARM64_REG_X0, ctx), (UC_ARM64_REG_X1, src),
                               (UC_ARM64_REG_X2, len(data))])
        self._call(MD5_FINAL, [(UC_ARM64_REG_X0, ctx), (UC_ARM64_REG_X1, dig)])
        return bytes(uc.mem_read(dig, 16))

    # ---------------- MIX functions ----------------
    def run_mix(self, fn, d, c, b, a):
        """MIX(x0=D, x1=C, x2=B, x3=A) in place on u16 buffers."""
        uc = self.uc
        pd, pc, pb, pa = (self.io + 0x100, self.io + 0x200,
                          self.io + 0x300, self.io + 0x400)
        uc.mem_write(pd, struct.pack("<H", d & 0xFFFF))
        uc.mem_write(pc, struct.pack("<H", c & 0xFFFF))
        uc.mem_write(pb, struct.pack("<H", b & 0xFFFF))
        uc.mem_write(pa, struct.pack("<H", a & 0xFFFF))
        self._call(fn, [pd, pc, pb, pa])
        return tuple(struct.unpack("<H", uc.mem_read(p, 2))[0]
                     for p in (pd, pc, pb, pa))

    def run_mix1(self, d, c, b, a):
        return self.run_mix(MIX1, d, c, b, a)

    def run_mix2(self, d, c, b, a):
        return self.run_mix(MIX2, d, c, b, a)

    # ---------------- transform ----------------
    def run_transform(self, hex32: str) -> str:
        assert len(hex32) == 32
        uc = self.uc
        src = self.io + 0x1000
        dst = self.io + 0x1100
        uc.mem_write(src, hex32.encode())
        # transform(w0=key_select, x1=in, x2=out)
        uc.reg_write(UC_ARM64_REG_X0, 1)
        uc.reg_write(UC_ARM64_REG_X1, src)
        uc.reg_write(UC_ARM64_REG_X2, dst)
        uc.reg_write(UC_ARM64_REG_X30, MAGIC)
        uc.reg_write(UC_ARM64_REG_SP, STACK_TOP)
        self._reset_frame_chain()
        uc.emu_start(TRANSFORM, MAGIC, timeout=20_000_000)
        return bytes(uc.mem_read(dst, 65)).split(b"\x00")[0].decode()

    # ---------------- full hash generator ----------------
    def run_gen_hash(self, challenge: str, key_select: int) -> str:
        """cmd_oem_gen_hash(key_select): reads challenge at 0x1fe3aa,
        writes 64-char calc hash to 0x1fe6cc."""
        assert len(challenge) == 32
        uc = self.uc
        uc.mem_write(CHALLENGE_BUF, challenge.encode())
        uc.mem_write(CALC_HASH_BUF, b"\x00" * 0x41)
        self._call(GEN_HASH, [(UC_ARM64_REG_X1, key_select & 0xFFFFFFFF)])
        return bytes(uc.mem_read(CALC_HASH_BUF, 0x40)).decode()


if __name__ == "__main__":
    import hashlib
    e = AblEmu()

    # 1. MD5 sanity
    data = b"The quick brown fox jumps over the lazy dog"
    emu_md5 = e.run_md5(data)
    py_md5 = hashlib.md5(data).digest()
    print("MD5 emu :", emu_md5.hex())
    print("MD5 py  :", py_md5.hex())
    print("MD5 match:", emu_md5 == py_md5)

    # 2. MIX probing
    print("MIX1(0x1234,0x5678,0x9abc,0xdef0):", [hex(x) for x in
          e.run_mix1(0x1234, 0x5678, 0x9abc, 0xdef0)])
    print("MIX2(0x1234,0x5678,0x9abc,0xdef0):", [hex(x) for x in
          e.run_mix2(0x1234, 0x5678, 0x9abc, 0xdef0)])

    # 3. transform
    t = e.run_transform("0123456789abcdef5566778899aabbcc")
    print("transform:", t, len(t))

    # 4. full gen_hash, key_select=1
    ch = "0123456789abcdef5566778899aabbcc"
    gh = e.run_gen_hash(ch, 1)
    print("gen_hash:", gh, len(gh))
    gh2 = e.run_gen_hash(ch, 2)
    print("gen_hash(k2):", gh2)
