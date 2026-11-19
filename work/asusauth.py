#!/usr/bin/env python3
"""
Standalone implementation of the ASUS ABL factory unlock response
(auth-hash family), derived from abl_linuxloader.efi static analysis:

  response = transform(md5hex(challenge || key))

  transform (FUN_00046608, key_select=1): two 16-char blocks; each block has
  two 8-char groups; chunks are 2 ASCII chars read as LE u16; group 1 mixes
  with MIX1 (FUN_00046528), group 2 with MIX2 (FUN_00046598); chunks are
  written back in reversed order [A,B,C,D]; finally %02x of all 32 bytes.

Verified against Unicorn emulation of the real ABL code (emu.py).
"""
import hashlib

M = 0xFFFF

def rol16(x, n):
    x &= M
    return ((x << n) | (x >> (16 - n))) & M

def bswap16(x):
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)

def mix1(d, c, b, a):
    """MIX1(x0=D, x1=C, x2=B, x3=A) -> (D', C', B', A')"""
    s1 = (a + d) & M
    s2 = (b + c) & M
    s3 = (a + d + c) & M
    s4 = (a + b) & M
    t1 = (rol16(s1, 2) + 6) & M
    t2 = (rol16(s3, 9) + 7) & M
    r2 = rol16(s2, 1)
    r4 = rol16(s4, 4)
    dp = t1 ^ t2
    cp = t2 ^ r2
    bp = r4 ^ r2
    ap = dp ^ r4
    return dp, cp, bp, ap

def mix2(d, c, b, a):
    """MIX2(x0=D, x1=C, x2=B, x3=A) -> (D', C', B', A')"""
    s1 = (a + d) & M
    s2 = (b + c) & M
    s3 = (a + d + c) & M
    s4 = (a + b) & M
    t1 = (rol16(s1, 6) + 3) & M
    t2 = (bswap16(s2) + 2) & M
    t3 = (rol16(s4, 3) + 3) & M
    s3c = (s3 + 9) & M
    dp = t1 ^ s3c
    cp = s3c ^ t2
    bp = t3 ^ t2
    ap = dp ^ t3
    return dp, cp, bp, ap

def transform(hex32: str) -> str:
    """FUN_00046608 with key_select=1 on a 32-char ascii-hex string."""
    assert len(hex32) == 32
    b = list(hex32.encode("ascii"))
    for blk in (0, 16):
        for off, mix in ((0, mix1), (8, mix2)):
            p = blk + off
            d = b[p] | (b[p + 1] << 8)
            c = b[p + 2] | (b[p + 3] << 8)
            bb = b[p + 4] | (b[p + 5] << 8)
            a = b[p + 6] | (b[p + 7] << 8)
            dp, cp, bp, ap = mix(d, c, bb, a)
            b[p] = ap & 0xFF; b[p + 1] = ap >> 8
            b[p + 2] = bp & 0xFF; b[p + 3] = bp >> 8
            b[p + 4] = cp & 0xFF; b[p + 5] = cp >> 8
            b[p + 6] = dp & 0xFF; b[p + 7] = dp >> 8
    return "".join("%02x" % x for x in b)

KEYS = {1: "12345678", 2: "28825252"}

def compute_response(challenge: str, key_select: int = 1) -> str:
    """64-char ascii response for a 32-char challenge (auth-hash / auth-hash_2)."""
    assert len(challenge) == 32
    key = KEYS[key_select]
    md5hex = hashlib.md5((challenge + key).encode("ascii")).hexdigest()
    return transform(md5hex)


if __name__ == "__main__":
    import random
    import sys
    sys.path.insert(0, "/Users/smales/Development/zenfone8/work")
    from emu import AblEmu

    e = AblEmu()
    random.seed(1234)  # deterministic

    ok = True

    # --- MIX1 / MIX2 ---
    for i in range(300):
        d, c, b, a = (random.getrandbits(16) for _ in range(4))
        emu1 = e.run_mix1(d, c, b, a)
        py1 = mix1(d, c, b, a)
        emu2 = e.run_mix2(d, c, b, a)
        py2 = mix2(d, c, b, a)
        if emu1 != py1:
            print(f"MIX1 MISMATCH i={i}: in=({d:#x},{c:#x},{b:#x},{a:#x}) "
                  f"emu={[hex(x) for x in emu1]} py={[hex(x) for x in py1]}")
            ok = False
            break
        if emu2 != py2:
            print(f"MIX2 MISMATCH i={i}: in=({d:#x},{c:#x},{b:#x},{a:#x}) "
                  f"emu={[hex(x) for x in emu2]} py={[hex(x) for x in py2]}")
            ok = False
            break
    else:
        print("MIX1/MIX2: 300/300 random cases match")

    # --- transform ---
    for i in range(100):
        h = hashlib.md5(str(random.random()).encode()).hexdigest()
        emu_t = e.run_transform(h)
        py_t = transform(h)
        # ABL sprintf uses %02X; cmd_oem_gen_hash lowercases the final result,
        # so compare case-insensitively here (pipeline check below is exact).
        if emu_t.lower() != py_t:
            print(f"TRANSFORM MISMATCH i={i}: in={h}\n  emu={emu_t}\n  py ={py_t}")
            ok = False
            break
    else:
        print("transform: 100/100 random cases match")

    # --- full gen_hash pipeline, key_select 1 and 2 ---
    for ks in (1, 2):
        for i in range(50):
            ch = "".join(random.choice("0123456789abcdef") for _ in range(32))
            emu_g = e.run_gen_hash(ch, ks)
            py_g = compute_response(ch, ks)
            if emu_g != py_g:
                print(f"GEN_HASH MISMATCH ks={ks} i={i}: ch={ch}\n  emu={emu_g}\n  py ={py_g}")
                ok = False
                break
        else:
            print(f"gen_hash key_select={ks}: 50/50 random challenges match")

    print("\nALL VERIFIED" if ok else "\nFAILED")
