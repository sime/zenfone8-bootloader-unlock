#!/usr/bin/env python3
"""Offline verifier for the ZF10 bootloader-unlock token (asuskey2).

Reconstructs, offline, exactly what the ZF10 ABL does when deciding
whether a device is unlocked (ZF10_PORTABILITY.md sections 5.5/5.7):

    is_unlock(0) -> read ISN (0x15-byte identity buffer, fn 0x1a010)
                 -> read token (0x100 bytes, read_asuskey 0x2c670)
                 -> SecRSAVerifySig(mode=1, keytype=3 -> hashid 1 RAW)

SecRSAVerifySig mode 1 (SecRSADxe 0x1670; EM builder 0x1840) is a strict
encode-then-compare:

    EM = 00 01 FF..FF 00 || plaintext      (raw mode: no DigestInfo)
    accept iff  s^e mod n == EM            (full-buffer compare, 0x2094)

This script takes a candidate token dump plus the AsusUnlock public key
(RSA-2048, e=3 — embedded below, or supply --cert) and recovers the
plaintext the token commits to. With an officially-unlocked donor's dump
plus that donor's ISN, it confirms the reconstruction (raw PKCS#1 v1.5
signature over the ISN-derived plaintext). It cannot forge anything: the
EM embeds the device's ISN and the bootloader compares exactly.

Usage:
  verify_token.py --token asuskey2.bin [--offset N] [--isn ASCII] [--isn-hex HEX]
  verify_token.py --token asuskey2.bin --explore [--stride N]   # locate the 0x100 blob
  verify_token.py --cert cert0.der --token t.bin ...            # non-default key
  verify_token.py --selftest                                     # synthetic e=3 key

Key provenance [F]: ABL type-0 cert at PE VA 0x121438 len 0x3dd, byte-
identical across .52 / A14 .65 / A15 .65. Re-extract from a payload.bin:
  cert0.der = payload[0xb8+0x121438 : +0x3dd]
  openssl x509 -inform DER -in cert0.der -noout -modulus
"""
import argparse
import hashlib
import secrets
import sys

K = 0x100  # RSA-2048 / token size read by read_asuskey
MIN_FF = 8  # PKCS#1 v1.5 minimum padding (SecRSADxe 0x1840 err 0x1004)

# AsusUnlock (cert type 0) RSA-2048 public key, e = 3 [F].
# sha256(00||n) = cda39824c2ef5c22bb14b6fc940c9ca4dca1896cf315b713fb5948ea715a13a8
# sha256(n)     = 49b95060b9bfb998c9123427d8e496fc55b8602f9bb9fd61debf0d4b647cae38
ASUSUNLOCK_N = bytes.fromhex(
    "C6C5841D4AF71DE2EEC55B91674D708E4C2C546BB317EAB6356A209BD810A02C"
    "50D57269AD7C0E98E3D58657AB33C9AFF6410840279E6546DA1E382DEF819E02"
    "37C343C131560BF04F88B67CD21B6AABE780845A86B3A16657F929E837FC2489"
    "708609054A00A26F5082B1924CDBE3BBBBB5C7E7B21FE1C5D972E4BF1B243B04"
    "22CB1FC5591C62B8920A8406DA3697A27E33C74C5F766222A8A67CABC18C3FDC"
    "5682463D4B3D1FD0298D351CDA3126FE00E1B8B85513422AF23D4215557F56B3"
    "EB5E5D2D352FF90F29AFDDCDE5B4C783569AFA92B3D3C650619D3372B0F17AE0"
    "1F1D6A82A8A96D14F71B63A3531ED06970DAD96D5DEFFD32142C84050D6D8885"
)
DEFAULT_KEY = (int.from_bytes(ASUSUNLOCK_N, "big"), 3)


# ---------------------------------------------------------------- DER / cert

def _tlv(b, i):
    """Parse one DER TLV at i -> (tag, content_start, content_end, next)."""
    tag = b[i]
    j = i + 1
    if b[j] & 0x80:
        nlen = b[j] & 0x7F
        ln = int.from_bytes(b[j + 1:j + 1 + nlen], "big")
        j += 1 + nlen
    else:
        ln = b[j]
        j += 1
    return tag, j, j + ln, j + ln


def _find_rsa(b, i, end, out):
    """Recursively find SEQUENCE { INTEGER n (128..512 B), INTEGER e }."""
    while i + 2 <= end:
        try:
            tag, cs, ce, nxt = _tlv(b, i)
        except Exception:
            return
        if ce > end:
            return
        if tag == 0x30:
            # direct INTEGER children?
            kids, k = [], cs
            while k + 2 <= ce:
                t2, cs2, ce2, n2 = _tlv(b, k)
                kids.append((t2, cs2, ce2))
                k = n2
            ints = [(s, e_) for (t, s, e_) in kids if t == 0x02]
            others = [t for (t, _, _) in kids if t != 0x02]
            if len(ints) == 2 and not others:
                (s1, e1), (s2, e2) = ints
                if 128 <= e1 - s1 <= 513 and 0 < e2 - s2 <= 9:
                    out.append((b[s1:e1], b[s2:e2]))
            _find_rsa(b, cs, ce, out)
        elif tag == 0x03:  # BIT STRING: descend past the unused-bits byte
            _find_rsa(b, cs + 1, ce, out)
        i = nxt


def key_from_cert(der):
    """Extract (n, e) from a DER cert blob (X.509 or the ASUS mini-cert)."""
    hits = []
    _find_rsa(der, 0, len(der), hits)
    # prefer the 2048-bit key: INTEGER may carry a 0x00 sign byte
    for nb, eb in hits:
        n = int.from_bytes(nb.lstrip(b"\x00"), "big")
        e = int.from_bytes(eb.lstrip(b"\x00"), "big")
        if n.bit_length() == 2048:
            return n, e
    if hits:
        nb, eb = hits[0]
        return int.from_bytes(nb.lstrip(b"\x00"), "big"), int.from_bytes(eb.lstrip(b"\x00"), "big")
    sys.exit("no RSA public key found in cert")


# ------------------------------------------------------------- EM machinery

def em_from_sig(sig, n, e):
    """s^e mod n, zero-padded to the modulus size (SecRSADxe 0x1670/0x1e9c)."""
    if len(sig) != K:
        raise ValueError(f"token must be {K:#x} bytes, got {len(sig):#x}")
    s = int.from_bytes(sig, "big")
    if s >= n:
        return None  # invalid signature integer
    t = pow(s, e, n)
    return t.to_bytes((n.bit_length() + 7) // 8, "big")


def parse_em(em):
    """Strict PKCS#1 v1.5 raw-mode EM parse, mirroring SecRSADxe 0x1840
    + the full-buffer memcmp in 0x1670.

    EM = 00 01 FF*([>=8]) 00 || msg, filling the buffer exactly.
    Returns (ok, reason, msg).
    """
    k = len(em)
    if k < 3 + MIN_FF + 1 + 1:
        return False, "too short", None
    if em[0] != 0x00:
        return False, f"EM[0]={em[0]:#04x} (want 00)", None
    if em[1] != 0x01:
        return False, f"EM[1]={em[1]:#04x} (want 01, block type 1)", None
    i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    nff = i - 2
    if nff < MIN_FF:
        return False, f"only {nff} padding FF bytes (min {MIN_FF})", None
    if i >= k or em[i] != 0x00:
        return False, f"no 00 separator after FF run (byte {i} = {em[i]:#04x})", None
    msg = em[i + 1:]
    if not msg:
        return False, "empty plaintext", None
    return True, f"{nff} FF padding bytes, plaintext {len(msg)} bytes", msg


def check_token(sig, n, e, expect=None):
    """Full ABL-equivalent check. Returns a result dict."""
    em = em_from_sig(sig, n, e)
    if em is None:
        return {"verdict": "REJECT", "reason": "signature integer >= modulus"}
    ok, reason, msg = parse_em(em)
    res = {"verdict": "PASS" if ok else "REJECT", "reason": reason, "msg": msg}
    if ok and expect is not None:
        cand = [expect, expect.rstrip(b"\x00")]
        if expect.startswith(b"\x00"):
            cand.append(expect.lstrip(b"\x00"))
        if not any(msg == c or msg.startswith(c) for c in cand if c):
            res["verdict"] = "PASS (plaintext != supplied ISN)"
    return res


def fmt(b):
    if b is None:
        return "-"
    printable = all(32 <= c < 127 or c == 0 for c in b)
    return f"{b.hex()} ({b!r})" if printable else b.hex()


# ------------------------------------------------------------------ explore

def explore(dump, n, e, stride=1):
    """Scan a partition dump for any 0x100 window whose recovered EM parses
    (the token may sit inside a filesystem rather than at offset 0)."""
    hits = 0
    for off in range(0, len(dump) - K + 1, stride):
        em = em_from_sig(dump[off:off + K], n, e)
        if em is None or em[0] != 0x00 or em[1] != 0x01:
            continue
        ok, reason, msg = parse_em(em)
        if ok:
            hits += 1
            print(f"  candidate @ {off:#x}: {reason}")
            print(f"    plaintext: {fmt(msg)}")
    print(f"scan: {hits} candidate(s) over {len(dump):#x} bytes (stride {stride})")


# ----------------------------------------------------------------- selftest

def _miller_rabin(n, rounds=32):
    if n % 2 == 0:
        return n == 2
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if p % 3 != 2:
            continue  # need gcd(3, p-1) = 1 for the e=3 inverse to exist
        if _miller_rabin(p):
            return p


def selftest():
    """Prove the EM logic against a synthetic RSA-2048 e=3 key: sign a
    fake ISN the way the ABL expects, verify PASS; corrupt one byte and
    a structure byte and verify REJECT."""
    print("selftest: generating synthetic RSA-2048 e=3 key ...")
    p, q = _gen_prime(1024), _gen_prime(1024)
    n, e = p * q, 3
    d = pow(e, -1, (p - 1) * (q - 1))
    isn = b"FAKEISN123456789"

    def encode(msg):  # SecRSADxe 0x1840 raw mode (hashid 1, no DigestInfo)
        return b"\x00\x01" + b"\xff" * (K - 3 - len(msg)) + b"\x00" + msg

    m = int.from_bytes(encode(isn), "big")
    sig = pow(m, d, n).to_bytes(K, "big")

    r = check_token(sig, n, e, expect=isn)
    print(f"  valid token:        {r['verdict']:12s} {r['reason']}")
    assert r["verdict"] == "PASS" and r["msg"] == isn, "valid token failed!"

    bad = bytearray(sig)
    bad[0] ^= 1
    r = check_token(bytes(bad), n, e, expect=isn)
    print(f"  corrupted token:    {r['verdict']:12s} {r['reason']}")
    assert r["verdict"] == "REJECT", "corrupted token passed!"

    # a Bleichenbacher-style high-bits-only blob (digest-loose forgery)
    # must also fail: the FF fill + exact buffer are enforced
    r = check_token((pow(m, d, n) ^ (1 << 1599)).to_bytes(K, "big"), n, e)
    print(f"  loose-padding blob: {r['verdict']:12s} {r['reason']}")
    assert r["verdict"] == "REJECT", "loose blob passed!"

    print("selftest: OK (EM logic matches the strict encoder; "
          "tampering is rejected)")


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Offline ZF10 asuskey2 token verifier (see ZF10_PORTABILITY.md 5.5/5.7)")
    ap.add_argument("--token", help="token / asuskey2 dump file")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="offset of the 0x100 signature blob (default 0)")
    ap.add_argument("--isn", help="expected ISN, ASCII")
    ap.add_argument("--isn-hex", help="expected ISN, hex")
    ap.add_argument("--cert", help="DER cert blob to take the key from "
                    "(default: embedded AsusUnlock type-0 key)")
    ap.add_argument("--explore", action="store_true",
                    help="scan the whole dump for a valid token blob")
    ap.add_argument("--stride", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.token:
        ap.error("--token is required (or --selftest)")

    n, e = key_from_cert(open(args.cert, "rb").read()) if args.cert else DEFAULT_KEY
    print(f"key: RSA-{n.bit_length()} e={e} "
          f"(sha256(n) {hashlib.sha256(n.to_bytes(256, 'big')).hexdigest()[:16]}…)")

    dump = open(args.token, "rb").read()
    if args.explore:
        explore(dump, n, e, args.stride)
        return
    if len(dump) < args.offset + K:
        sys.exit(f"dump too small for a token at {args.offset:#x} "
                 f"(need {args.offset + K:#x}, have {len(dump):#x})")

    expect = None
    if args.isn:
        expect = args.isn.encode()
    elif args.isn_hex:
        expect = bytes.fromhex(args.isn_hex)

    sig = dump[args.offset:args.offset + K]
    r = check_token(sig, n, e, expect=expect)
    print(f"token @ {args.offset:#x}: {r['verdict']}")
    print(f"  detail:    {r['reason']}")
    print(f"  plaintext: {fmt(r.get('msg'))}")
    if r["verdict"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
