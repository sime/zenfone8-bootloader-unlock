#!/usr/bin/env python3
"""Parse an Android A/B OTA payload.bin header + DeltaArchiveManifest.

Prints payload version, per-partition op types/offsets/lengths/hashes —
specifically enough metadata to extract one partition from a huge OTA
by HTTP Range / partial-file reads (used for abl/xbl on the ZenFone 10).

Schema notes (empirically re-verified against ASUS ZF8/ZF10 payloads,
2026-11-19; see ZF10_PORTABILITY.md §5.2 for the verification log):

  payload header ('CrAU'): u32 magic, u64 BE version, u64 BE manifest size,
  u32 BE signature size, then the manifest, then the signature, then op data
  (data_base = hdr_end + msize + sigsize).

  DeltaArchiveManifest:
    f13 = repeated PartitionUpdate
  PartitionUpdate:
    f1 = partition_name (string)
    f6 = old_partition_info (PartitionInfo)
    f7 = new_partition_info (PartitionInfo)
    f8 = repeated InstallOperation
  PartitionInfo:
    f1 = size (varint)
    f2 = sha256 of the new image (bytes)
  InstallOperation (ASUS payloads; all lengths varints, not AOSP fixed64):
    f1 = type, f2 = data_offset, f3 = data_length
    f6 = dst extents (nested protobuf), f8 = data sha256
  Spanning/antirotation fields observed at f22/f23 (varint + 0x20-byte blob).
    Partitions carry constant type-8 ops whose data blob is a multi-stream
  XZ image decompressing to the exact PartitionInfo.size with the exact
  PartitionInfo sha256 (byte-verified on ZF8 abl .296 and ZF10 abl .52/.65).
  This matches payload-dumper-go's REPLACE_XZ handling; NOTE stock AOSP's
  update_metadata.proto numbers REPLACE_XZ=10 and ZERO=8 — the ASUS fork
  evidently uses 8 for the XZ-carried replace op. Trust the blob magic
  (fd 37 7a 58 5a) over the enum.

Usage: payload_manifest.py <payload.bin | OTA.zip> [partition-filter]
"""
import sys, os, struct, zipfile


def varint(b, i):
    v = 0; s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7f) << s
        if not x & 0x80:
            return v, i
        s += 7


def fields(b):
    """Yield (field_number, wire_type, value_or_bytes, end_index)."""
    i = 0
    n = len(b)
    while i < n:
        tag, i = varint(b, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = varint(b, i)
            yield fn, wt, v, i
        elif wt == 2:
            l, i = varint(b, i)
            yield fn, wt, b[i:i + l], i + l
            i += l
        elif wt == 5:
            yield fn, wt, b[i:i + 4], i + 4
        elif wt == 1:
            yield fn, wt, b[i:i + 8], i + 8
        else:
            raise ValueError(f'wire {wt} at {i}')


OP_NAMES = {0: 'REPLACE', 1: 'REPLACE_BZ', 2: 'MOVE', 3: 'BSDIFF',
            4: 'SOURCE_COPY', 5: 'SOURCE_BSDIFF', 6: 'IMGDIFF',
            7: 'SOURCE_IMGDIFF', 8: 'REPLACE_XZ*', 9: 'DISCARD',
            10: 'REPLACE_XZ', 11: 'PUFFDIFF', 12: 'SOURCE_PUFFDIFF',
            13: 'BROTLI_BSDIFF', 14: 'ZUCCHINI', 15: 'LZ4DIFF',
            16: 'ZSTDDIFF'}


def parse_op(msg):
    op = {}
    for f3, w3, v3, _ in fields(msg):
        if w3 == 0 and f3 in (1, 2, 3):
            op[{1: 'type', 2: 'data_offset', 3: 'data_length'}[f3]] = v3
        elif w3 == 2 and f3 == 8:
            op['data_sha256'] = v3.hex()
    return op


def parse_partition_update(msg):
    rec = {'name': None, 'old': None, 'new': None, 'ops': []}
    for f2, w2, v2, _ in fields(msg):
        if f2 == 1 and w2 == 2:
            rec['name'] = v2.decode(errors='replace')
        elif f2 in (6, 7) and w2 == 2:
            info = {}
            for f3, w3, v3, _ in fields(v2):
                if w3 == 0 and f3 == 1:
                    info['size'] = v3
                elif w3 == 2 and f3 == 2:
                    info['sha256'] = v3.hex()
            rec['old' if f2 == 6 else 'new'] = info
        elif f2 == 8 and w2 == 2:
            rec['ops'].append(parse_op(v2))
    return rec


def parse_manifest(man):
    parts = []
    for fn, wt, v, _ in fields(man):
        if fn != 13 or wt != 2:
            continue
        rec = parse_partition_update(v)
        if rec['name']:
            parts.append(rec)
    return parts


def payload_offsets(blob):
    """Return (version, msize, sigsize, data_base)."""
    assert blob[:4] == b'CrAU', 'not a payload'
    version = struct.unpack('>Q', blob[4:12])[0]
    msize = struct.unpack('>Q', blob[12:20])[0]
    ssig = struct.unpack('>I', blob[20:24])[0]
    return version, msize, ssig


def extract_op_bytes(blob, data_base, op):
    """Multi-stream XZ decompress of an op blob -> partition bytes."""
    import lzma
    raw = blob[data_base + op['data_offset']:
               data_base + op['data_offset'] + op['data_length']]
    if raw[:6] != b'\xfd7zXZ\x00':
        if op['type'] == 0:
            return b'\x00' * op['data_length']
        return raw
    out = bytearray(); d = lzma.LZMADecompressor(); buf = raw
    while buf:
        out += d.decompress(buf)
        if d.eof:
            rest = getattr(d, 'unused_data', b'')
            d = lzma.LZMADecompressor(); buf = rest
        else:
            buf = b''
    return bytes(out)


def get_payload_bytes(src, limit=None):
    """payload.bin bytes from an OTA zip (stored, so partial files work
    up to `limit`) or a raw payload file."""
    if os.path.isdir(src):
        src = os.path.join(src, 'payload.bin')
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            data_off = None
            with z.open('payload.bin') as f:
                blob = f.read(limit) if limit else f.read()
    else:
        blob = open(src, 'rb').read()
        if limit:
            blob = blob[:limit]
    return blob


def main():
    src = sys.argv[1]
    filt = sys.argv[2].lower() if len(sys.argv) > 2 else None
    blob = get_payload_bytes(src, limit=64 * 1024 * 1024)
    if blob is None:
        sys.exit('no payload.bin')
    version, msize, ssig = payload_offsets(blob)
    print(f'payload version={version} manifest_size={msize} sig_size={ssig}')
    man = blob[24:24 + msize]
    parts = parse_manifest(man)
    print(f'{len(parts)} partitions in manifest')
    for rec in parts:
        n = rec['name']
        if filt and filt not in n.lower():
            continue
        new = rec['new'] or {}
        ops = rec['ops']
        tnames = ','.join(OP_NAMES.get(o['type'], str(o['type'])) for o in ops)
        print(f"  {n:14s} new_size={new.get('size', '?'):>9} "
              f"new_sha256={new.get('sha256', '?')[:16]}… "
              f"ops={len(ops)} [{tnames}]")
        for o in ops[:4]:
            print(f"      type={o['type']} data_off={o.get('data_offset')} "
                  f"data_len={o.get('data_length')}")


if __name__ == '__main__':
    main()
