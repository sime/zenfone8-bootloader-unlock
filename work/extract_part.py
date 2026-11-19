#!/usr/bin/env python3
"""Extract one partition image from an ASUS A/B OTA (payload.bin, stored).

Reuses the manifest parser in payload_manifest.py. Ops are ASUS-fork
REPLACE_XZ (multi-stream XZ) blobs; concatenation of op outputs must
hash-match PartitionInfo.new.

Usage:
    python3 extract_part.py <ota.zip|payload.bin> <partition_name> [out.bin]
"""
import sys, os, io, struct, hashlib, zipfile, lzma

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from payload_manifest import parse_manifest, payload_offsets


def op_bytes(stream, base, off, length):
    stream.seek(base + off)
    raw = stream.read(length)
    if raw[:6] != b'\xfd7zXZ\x00':
        if length and raw[:1] == b'\x00':
            # ZERO op with data present or raw
            pass
        return raw
    out = b''
    dec = None
    buf = raw
    while buf:
        if dec is None:
            dec = lzma.LZMADecompressor()
        out += dec.decompress(buf)
        if dec.eof:
            dec = None
            buf = getattr(dec, 'unused_data', b'') if False else buf  # placeholder
            break
        buf = b''
    # multi-stream: feed remaining streams
    if dec is None:
        rest = raw
        consumed = None
        # simple multi-stream loop over raw
        out = b''
        d = None
        data = raw
        while data:
            if d is None:
                d = lzma.LZMADecompressor()
                out += d.decompress(data)
            if d.eof:
                data = d.unused_data
                d = None
            else:
                break
    return out


def op_bytes_simple(raw):
    """Multi-stream XZ decompress (fd 37 7a 58 5a magic)."""
    if raw[:6] != b'\xfd7zXZ\x00':
        return raw
    out = b''
    data = raw
    while data:
        d = lzma.LZMADecompressor()
        out += d.decompress(data)
        if d.eof and d.unused_data:
            data = d.unused_data
        else:
            break
    return out


def main():
    src, part = sys.argv[1], sys.argv[2].lower()
    out_path = sys.argv[3] if len(sys.argv) > 3 else f'/tmp/part_{part.replace("/", "_")}.img'

    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            with z.open('payload.bin') as f:
                head = f.read(24)
                version, msize, ssig = payload_offsets(head)
                man = f.read(msize)
                data_base = 24 + msize + ssig
                parts = parse_manifest(man)
                rec = next((r for r in parts if r['name'].lower() == part), None)
                if not rec:
                    sys.exit(f'no partition {part!r}; have: ' +
                             ', '.join(r['name'] for r in parts))
                new = rec['new'] or {}
                img = b''
                for k, o in enumerate(rec['ops']):
                    f.seek(data_base + o['data_offset'])
                    raw = f.read(o['data_length'])
                    chunk = op_bytes_simple(raw)
                    img += chunk
                    print(f'  op{k}: type={o["type"]} len={o["data_length"]} -> {len(chunk)}')
                sha = hashlib.sha256(img).hexdigest()
                print(f'{part}: size={len(img)} (expect {new.get("size")}) '
                      f'sha256={sha} match={sha == new.get("sha256")}')
                open(out_path, 'wb').write(img)
                print('wrote', out_path)
    else:
        blob = open(src, 'rb').read()
        version, msize, ssig = payload_offsets(blob[:24])
        parts = parse_manifest(blob[24:24 + msize])
        rec = next((r for r in parts if r['name'].lower() == part), None)
        if not rec:
            sys.exit(f'no partition {part!r}')
        data_base = 24 + msize + ssig
        img = b''
        for o in rec['ops']:
            img += op_bytes_simple(blob[data_base + o['data_offset']:
                                        data_base + o['data_offset'] + o['data_length']])
        open(out_path, 'wb').write(img)
        print('wrote', out_path, len(img))


if __name__ == '__main__':
    main()
