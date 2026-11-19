#!/usr/bin/env python3
"""Generic ASUS/Qualcomm ABL extraction: abl.elf -> LZMA payload -> inner PE32 images.

Validated against the ZenFone 8 A12 abl.elf (raw/abl.elf), reproducing
work/abl_payload.bin byte-for-byte.

Usage:
    python3 extract_abl.py <abl.elf | abl.img> [outdir]

Writes <outdir>/payload.bin (LZMA-decompressed FV payload) and one file per
PE32+ image found inside it (app_<n>.efi<.name>), plus prints a scan summary
for the ASUS factor fastboot protocol markers.
"""
import sys, os, re, struct, lzma

def find_lzma_sections(data: bytes):
    """Find plausible raw LZMA streams (props byte + 4-byte size)."""
    hits = []
    for m in re.finditer(rb'\x5d\x00{3,4}', data):
        off = m.start()
        if off % 4:  # aligned streams in practice
            pass
        # LZMA_ALONE header: 1 props + 4 uncompressed size (often 0xFFFFFFFF..)
        size = struct.unpack_from('<I', data, off + 1)[0]
        if size in (0xFFFFFFFF, 0) or 0 < size < 0x2000000:
            hits.append((off, size))
    return hits

def try_decompress(data: bytes, off: int):
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        out = dec.decompress(data[off:])
    except Exception:
        return None
    return out if len(out) > 0x10000 else None

def carve_payload(elf: bytes):
    # Try plain ELF first (abl.elf). If input is a raw abl partition image,
    # just scan the whole blob for LZMA streams.
    cands = find_lzma_sections(elf)
    best = None
    for off, size in cands:
        out = try_decompress(elf, off)
        if out and (best is None or len(out) > len(best[1])):
            best = (off, out)
    return best

def find_pe_images(payload: bytes):
    """Yield (offset, size, name) for PE/PE32+ images carved from the payload.

    EFI FFs-backed payload has FFS files; quick & dirty: locate MZ headers with
    a sane PE signature and take until the next MZ / end-of-used data.
    """
    pes = []
    for m in re.finditer(rb'MZ', payload):
        off = m.start()
        try:
            e_lfanew = struct.unpack_from('<I', payload, off + 0x3c)[0]
        except struct.error:
            continue
        if not (0x40 <= e_lfanew < 0x400):
            continue
        if payload[off + e_lfanew:off + e_lfanew + 4] != b'PE\x00\x00':
            continue
        pes.append(off)
    out = []
    for i, off in enumerate(pes):
        end = pes[i + 1] if i + 1 < len(pes) else len(payload)
        blob = payload[off:end]
        # Name heuristics: trailing/leading ASCII names in the FFS header region
        name = b''
        nm = re.search(rb'[ -~]{4,32}\x00', payload[max(0, off - 0x60):off])
        if nm:
            name = nm.group(0).strip()
        out.append((off, end - off, name))
    return out

PROTOCOL_MARKERS = [
    # (what, byte pattern, note)
    (b'gen-random',        'command: challenge generator'),
    (b'auth-hash',         'command: response verifier'),
    (b'auth-hash_2',       'command: second verifier'),
    (b'get-imeiauth',      'command: imei auth'),
    (b'asuskey2',          'special flash target'),
    (b'Random Num = ',     'challenge print format'),
    (b'Authorized Result', 'PASS/FAIL print format'),
    (b'Dungle',            'internal name for the factory unlock'),
    (b'12345678',          'key_select 1 key'),
    (b'28825252',          'key_select 2 key'),
    (b'receive asuskey2',  'CmdFlash log string'),
    (b'rt_unlocked',       'getvar name'),
    (b'rd_unlocked',       'getvar name'),
    (b'mask_unlocked',     'getvar name'),
    (b'asus.authorized',   'kernel-arg naming for the auth flag'),
]

def utf16le(s: bytes) -> bytes:
    return b''.join(bytes([c, 0]) for c in s)

def scan(name: str, blob: bytes):
    print(f'--- scan {name} ({len(blob)} bytes)')
    found = {}
    for pat, note in PROTOCOL_MARKERS:
        pats = [pat, utf16le(pat)]
        for i, p in enumerate(pats):
            offs = [m.start() for m in re.finditer(re.escape(p), blob)]
            if offs:
                enc = 'utf16' if i else 'ascii'
                # report once per pattern
                if pat in found:
                    found[pat] = (found[pat][0] + offs, enc)
                else:
                    found[pat] = (offs, enc)
    for pat, note in PROTOCOL_MARKERS:
        if pat in found:
            offs, enc = found[pat]
            o = ', '.join(hex(x) for x in offs[:6]) + (' ...' if len(offs) > 6 else '')
            print(f'  HIT  {pat.decode():20s} ({enc}) @ {o}  [{note}]')
        else:
            print(f'  miss {pat.decode():20s} [{note}]')
    return found

def main():
    src = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else (os.path.splitext(src)[0] + '.x')
    os.makedirs(outdir, exist_ok=True)
    data = open(src, 'rb').read()
    r = carve_payload(data)
    if not r:
        print('no LZMA payload found; input may already be a flat image')
        return 1
    off, payload = r
    print(f'LZMA stream @ {off:#x} -> {len(payload)} bytes')
    pbin = os.path.join(outdir, 'payload.bin')
    open(pbin, 'wb').write(payload)
    print(f'wrote {pbin}')
    scan(src + ' (compressed container)', data)
    scan(pbin, payload)
    for off, size, name in find_pe_images(payload):
        nm = name.decode(errors='replace').strip() or f'app{off:x}'
        out = os.path.join(outdir, f'app_{off:x}_{nm}.efi'.replace('://', '_'))
        blob = payload[off:off + size]
        open(out, 'wb').write(blob)
        print(f'PE image @ {off:#x} size {size} name {nm!r} -> {out}')
        scan(os.path.basename(out), blob)
    return 0

if __name__ == '__main__':
    sys.exit(main())
