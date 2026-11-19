#!/usr/bin/env python3
"""Minimal MEGA public-file downloader (API 'g', anonymous).

Usage:
    python3 mega_dl.py <handle> <key_b64url> <out_path> [max_bytes]

<handle> and <key_b64url> come from a https://mega.nz/file/<handle>#<key> link.
Decrypts AES-128-CTR (key=key[:16], iv=key[16:24]+0*8) in a streaming fashion.
"""
import base64
import json
import os
import sys
import time
import urllib.request

from Crypto.Cipher import AES
from Crypto.Util import Counter


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def api(seq: int, payload: dict, fileid: str = "0"):
    url = "https://g.api.mega.co.nz/cs?id=%d&n=%s" % (seq, fileid)
    body = json.dumps([payload]).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    if isinstance(data, dict) and data.get("e") not in (None, 0):
        raise RuntimeError("MEGA API error: %r" % data)
    return data[0]


def main():
    handle = sys.argv[1]
    key = b64url_decode(sys.argv[2])
    out_path = sys.argv[3]
    max_bytes = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    if len(key) != 32:
        raise SystemExit("expected 32-byte key, got %d" % len(key))
    aes_key = key[:16]
    iv = key[16:24] + b"\x00" * 8

    info = api(0, {"a": "g", "g": 1, "p": handle})
    url = info["g"]
    size = info["s"]
    print("remote size: %d bytes" % size)

    part_path = out_path + ".part"
    existing = os.path.getsize(part_path) if os.path.exists(part_path) else 0

    if max_bytes:
        size = min(size, max_bytes)

    # CTR stream position must match the resume offset (every 16 bytes advances counter)
    start = existing - (existing % 16)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big") + start // 16)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    if start:
        req.add_header("Range", "bytes=%d-" % start)
    mode = "ab" if start else "wb"
    if start and start != existing:
        mode = "wb"
        start = 0

    t0 = time.time()
    done = start
    with urllib.request.urlopen(req, timeout=60) as r, open(part_path, mode) as f:
        while done < size:
            chunk = r.read(min(4 * 1024 * 1024, size - done))
            if not chunk:
                break
            f.write(cipher.decrypt(chunk))
            done += len(chunk)
            pct = done * 100.0 / size
            rate = done / max(time.time() - t0, 1e-6) / 1e6
            print("\r%6.2f%%  %d/%d  %.1f MB/s" % (pct, done, size, rate), end="")
    print()
    os.replace(part_path, out_path)
    print("saved -> %s (%d bytes)" % (out_path, os.path.getsize(out_path)))


if __name__ == "__main__":
    main()
