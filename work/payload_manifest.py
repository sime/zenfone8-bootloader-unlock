#!/usr/bin/env python3
"""Parse an Android A/B OTA payload.bin header + DeltaArchiveManifest.

Prints payload version, post/pre build fingerprints (when present), and the
install-operation type used for each partition (specifically flags `abl`).

Operation types (AOSP update_metadata.proto):
  0 REPLACE, 1 REPLACE_BZ, 2 MOVE, 3 BSDIFF, 4 SOURCE_COPY, 5 SOURCE_BSDIFF,
  6 IMGDIFF, 7 SOURCE_IMGDIFF, 8 ZERO, 9 DISCARD, 10 BROTLI_BSDIFF,
  11 PUFFDIFF, 12 SOURCE_PUFFDIFF, 13 BROTLI_BSDIFF?, 15 ZUCCHINI, ...

Usage: payload_manifest.py <payload.bin | OTA.zip> [partition-filter]
"""
import sys, io, zipfile

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
            yield fn, wt, b[i:i+l], i + l
            i += l
        elif wt == 5:
            yield fn, wt, b[i:i+4], i + 4
        elif wt == 1:
            yield fn, wt, b[i:i+8], i + 8
        else:
            raise ValueError(f'wire {wt} at {i}')

OP_NAMES = {0:'REPLACE',1:'REPLACE_BZ',2:'MOVE',3:'BSDIFF',4:'SOURCE_COPY',
            5:'SOURCE_BSDIFF',6:'IMGDIFF',7:'SOURCE_IMGDIFF',8:'ZERO',
            9:'DISCARD',10:'BROTLI_BSDIFF',11:'PUFFDIFF',12:'SOURCE_PUFFDIFF',
            13:'BROTLI_BSDIFF?',15:'ZUCCHINI'}

def parse_partition_update(msg):
    name = None; ops = []
    for fn, wt, v, _ in fields(msg):
        if fn == 1 and wt == 2:
            name = v.decode(errors='replace')
        elif fn == 5 and wt == 2:  # operations
            t = None
            for f2, w2, v2, _ in fields(v):
                if f2 == 1 and w2 == 0:
                    t = v2
                    break
            ops.append(t)
    return name, ops

def parse_manifest(man):
    """Schema-flexible: ASUS/Ota payloads seen in the field put partition_updates
    at manifest field 13 with ops at PartitionUpdate field 8 (new_info=6,
    old_info=7); older AOSP used field 3 / ops field 5 / newinfo 8/old 21."""
    parts = {}
    for fn, wt, v, _ in fields(man):
        if fn not in (3, 13) or wt != 2:
            continue
        name = None; ops = []
        old = None
        for f2, w2, v2, _ in fields(v):
            if f2 == 1 and w2 == 2:
                name = v2.decode(errors='replace')
            elif f2 in (5, 8) and w2 == 2:
                t = None
                for f3, w3, v3, _ in fields(v2):
                    if f3 == 1 and w3 == 0:
                        t = v3
                        break
                if t is not None and t <= 31:  # InstallOperation.Type range
                    ops.append(t)
            elif f2 == 7 and w2 == 2:
                old = True
        if name is not None:
            parts[name] = (ops, bool(old))
    return parts

def get_payload_bytes(src, limit=None):
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            with z.open('payload.bin') as f:
                return f.read(limit) if limit else f.read()
    return open(src, 'rb').read()

def main():
    src = sys.argv[1]
    filt = sys.argv[2].lower() if len(sys.argv) > 2 else None
    blob = get_payload_bytes(src, limit=64 * 1024 * 1024)
    assert blob[:4] == b'CrAU', 'not a payload'
    import struct
    version = struct.unpack('>Q', blob[4:12])[0]
    msize = struct.unpack('>Q', blob[12:20])[0]
    ssig = struct.unpack('>I', blob[20:24])[0]
    print(f'payload version={version} manifest_size={msize} sig_size={ssig}')
    man = blob[24:24 + msize]
    parts = parse_manifest(man)
    print(f'{len(parts)} partitions in manifest')
    for n, (ops, has_old) in parts.items():
        if filt and filt not in n.lower():
            continue
        tnames = [OP_NAMES.get(t, str(t)) for t in ops]
        src = 'SRC-DELTA' if has_old else 'FULL/NO-SRC'
        print(f'  {n:14s} {src:11s} ops={len(ops):3d} types={",".join(tnames) if ops else "?"}')
    for s in ('pre-build', 'post-build', 'pre-device', 'pre-build-incremental'):
        # fingerprints stored raw-ish; crude scan
        for pat in (s.encode(),):
            i = 0
            hits = []
            while True:
                j = man.find(pat, i)
                if j < 0 or len(hits) > 1:
                    break
                e = man.find(b'\x00', j)
                if e < 0:
                    break
                hits.append(man[j:e].decode(errors='replace')[:200])
                i = j + 1
            for h in hits:
                print(f'  {h}')

if __name__ == '__main__':
    main()
