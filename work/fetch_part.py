#!/usr/bin/env python3
"""Fetch one partition image from an ASUS A/B OTA over HTTP using Range
requests — works even when the local copy is truncated or not downloaded.

Reads the payload manifest from the head of the remote zip (a few hundred
KB), resolves the requested partition's ops, then range-fetches only those
op blobs, XZ-decodes them (ASUS multi-stream REPLACE_XZ), and verifies the
result against the manifest sha256/size.

Usage:
    fetch_part.py <url|local.zip> <partition_name> [out.bin]

Notes / empirical schema (see ZF10_PORTABILITY.md §5.2):
- payload.bin is STORED (method 0) in ASUS zips; the CrAU header + manifest
  sit in the first ~300 KB, so a small head fetch suffices.
- InstallOperation: f1=type, f2=data_offset, f3=data_length (varints),
  f8=data sha256. Constant-image partitions use a single/ few type-8 ops
  whose data is a concatenated XZ stream.
"""
import sys, os, io, hashlib, lzma, urllib.request, urllib.error, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from payload_manifest import parse_manifest, payload_offsets

HEAD = 8 << 20  # 8 MB head fetch is ample for the manifest


def http_range(url, start, end):
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def xz_multi(data):
    """Decode a concatenated multi-stream XZ blob."""
    out = b""
    d = lzma.LZMADecompressor()
    buf = data
    while buf:
        out += d.decompress(buf)
        buf = b""
        if d.eof:
            buf = d.unused_data
            if not buf:
                break
            d = lzma.LZMADecompressor()
        else:
            break
    return out


def read_head(src):
    if src.startswith("http://") or src.startswith("https://"):
        return http_range(src, 0, HEAD - 1)
    with open(src, "rb") as f:
        return f.read(HEAD)


def get_blob(src, start, length):
    if src.startswith("http://") or src.startswith("https://"):
        return http_range(src, start, start + length - 1)
    with open(src, "rb") as f:
        f.seek(start)
        return f.read(length)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    src, part = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else f"{part}.img"

    head = read_head(src)
    crau = head.find(b"CrAU")
    if crau < 0:
        sys.exit(f"no CrAU in first {HEAD:#x} bytes of {src}")
    ver, msize, ssig = payload_offsets(head[crau:crau + 24])
    data_base = crau + 24 + msize + ssig
    man = head[crau + 24: crau + 24 + msize]
    if len(man) < msize:
        man = get_blob(src, crau + 24, msize)
    parts = parse_manifest(man)
    rec = next((r for r in parts if r.get("name") == part), None)
    if rec is None:
        sys.exit(f"partition {part!r} not in manifest")
    new = rec.get("new", {})
    print(f"{part}: payload v{ver}, {len(rec.get('ops', []))} op(s), "
          f"new size={new.get('size')} sha256={new.get('sha256', '')[:20]}…")

    img = b""
    for o in rec.get("ops", []):
        a = data_base + o["data_offset"]
        L = o["data_length"]
        raw = get_blob(src, a, L)
        if o.get("type") == 0:            # ZERO
            img += b"\x00" * L
            continue
        if raw[:6] == b"\xfd7zXZ\x00":
            dec = xz_multi(raw)
        else:
            dec = raw
        img += dec
        print(f"  op type={o['type']} abs={a:#x} comp={L:#x} -> {len(dec):#x}")

    ok_size = new.get("size") in (None, len(img))
    got = hashlib.sha256(img).hexdigest()
    ok_sha = (new.get("sha256") is None) or (got == new["sha256"])
    open(out, "wb").write(img)
    print(f"wrote {out} ({len(img):#x} bytes) size_ok={ok_size} sha256_ok={ok_sha}")
    if not (ok_size and ok_sha):
        sys.exit(2)


if __name__ == "__main__":
    main()
