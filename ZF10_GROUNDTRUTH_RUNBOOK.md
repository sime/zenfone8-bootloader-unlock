# ZF10 ground-truth token runbook (asuskey2 from an unlocked donor)

**Status:** scoped, ready to execute when a donor device + GhostLock
access are available. No device is currently attached.

**Parent doc:** `ZF10_PORTABILITY.md` §5.5–§5.8 — the unlock gate is an
RSA-2048 (e = 3) signature over the device's ISN, verified by a strict
encode-then-compare (`SecRSAVerifySig` mode 1, raw hashid). The verdict
("no local unlock; requires ASUS's private key") is already **[F]** and
does **not** depend on this runbook. This runbook only *confirms the token
format* from a real, officially-unlocked device.

**Notation:** **[F]** = byte-verified against the `.52`/`.65` boot chain;
**[I]** = inference, to be settled by the ground truth itself.

---

## 1. What this can and cannot prove

**Can [I → F if it runs]:**

- the exact plaintext the ASUS-issued token commits to (recovered
  directly: `s^3 mod n` must equal `00 01 FF…FF 00 ‖ plaintext`, so the
  plaintext *falls out* of the public-key operation — no private key
  needed);
- whether that plaintext is the ISN (buffer size 0x15), the ISN ASCII, or
  a small device-info struct;
- the token's exact placement inside the `asuskey2` partition (raw at
  offset 0, or a file inside a filesystem — see §4);
- that the reconstruction in `ZF10_PORTABILITY.md` §5.5 is the live path.

**Cannot — by design [F]:**

- **produce a forgery for any other device.** The token is a full
  PKCS#1 v1.5 signature; the EM embeds the donor's own ISN/plaintext, and
  the ABL compares the entire buffer (§5.7). A donor token is worthless
  to any other unit. This runbook exists for format confirmation only;
- recover, derive, or brute-force the AsusUnlock private key (2048-bit;
  e = 3 does not help the *signer* side at all).

## 2. Prerequisites

| # | Item | Notes |
|---|---|---|
| 1 | An **officially unlocked** ZF10 donor (ASUS app / repair channel) | owner's informed consent required; no unlock is performed by us |
| 2 | The donor's **ISN** | §5 below |
| 3 | GhostLock **remote dump** access to the donor | dump-only; nothing is flashed or written to the donor at any point |
| 4 | Explicit user (project-owner) approval before each new device | house rule; also for any step not listed here |

## 3. What to dump (GhostLock, read-only)

| Priority | Target | Why |
|---|---|---|
| 1 | `asuskey2` partition, full image | primary token store; `read_asuskey` (PE VA 0x2c670) reads a 0x100-byte signature from it |
| 2 | `asuskey` and `asuskey3` partitions, if present | sibling stores [I]; if `asuskey2` is empty, the token may live here |
| 3 | `devinfo` (or the ZF10's DevInfo-equivalent state partition) | optional; records the unlock *result*, useful as a consistency check |
| — | anything else | not needed; do not touch |

Hash every dump (`shasum -a 256`) at acquisition time and record sizes.

## 4. Where the token sits — two hypotheses to settle

[F] The token backend (PE VA 0x11010) is not a raw partition reader: it
calls `gBS->LocateHandleBuffer` on `gEfiSimpleFileSystemProtocol`
(964E5B22-…), i.e. it opens a **volume as a filesystem** and reads a
file (namespace GUID `30F09946-3DEA-4B24-BEA4-CA6AB64EBFDE`, rodata
@PE 0x103e40). So:

- **[I] H1:** the `asuskey2` partition holds a small FAT/filesystem and
  the token is a file inside it (check for `FAT`/VBR signatures at dump
  offset 0; then either mount/extract the file or just scan — §6).
- **[I] H2:** the partition holds the raw 0x100 signature at some fixed
  offset (0 first, then structure-dependent).

The verifier's `--explore` mode (§6) settles this without any manual
parsing: it scans the whole dump for the 0x100 window whose `s^3 mod n`
parses as a strict raw-mode EM. With e = 3 the public-key operation is
two modular multiplications per offset, so a full 1-byte-stride scan of
a multi-MB dump is seconds-to-minutes.

## 5. Getting the donor's ISN (non-destructive options, preferred first)

1. **Device label / retail box** — ASUS prints the ISN (serial-type
   identifier, ~15–21 chars) on the device/box. Zero interaction.
2. **The ASUS unlock app's receipt / account page** for the donor — the
   app displayed the ISN when the unlock was requested.
3. **[I, fallback only]** `fastboot oem get-hwid` on the donor — the ABL
   handler (entry 0xa45bc [0xC8]-offsets) drives `is_unlock` with a
   runtime cert index; per the disassembly it is a query that only
   *reads* state and prints, but it re-runs the full RSA verify on a
   production device, so treat as last resort and only with the owner
   watching.

## 6. Offline analysis (once the dumps are in)

Tool: `work/verify_token.py` (self-tested against a synthetic RSA-2048
e = 3 key; embeds the AsusUnlock public key, sha256(n)
`49b95060b9bfb998c9123427d8e496fc55b8602f9bb9fd61debf0d4b647cae38`).

```sh
# 0. sanity (no dumps needed)
python3 work/verify_token.py --selftest

# 1. locate the token blob anywhere in the dump (settles H1 vs H2)
python3 work/verify_token.py --token asuskey2.bin --explore

# 2. verify it and recover the committed plaintext,
#    with the donor's ISN from the label/app receipt:
python3 work/verify_token.py --token asuskey2.bin --offset <from-1> \
    --isn "<donor ISN ASCII>"
#    (or --isn-hex if the ISN is better expressed in hex)
```

The tool mirrors the SecRSADxe check exactly: `EM = 00 01 FF…FF 00 ‖
plaintext` with ≥ 8 forced `0xFF` padding bytes, full-buffer compare
(`ZF10_PORTABILITY.md` §5.7). It prints the recovered plaintext in
hex/ASCII regardless of PASS — that *is* the format answer.

## 7. Outcome matrix

| Result | Meaning | Action |
|---|---|---|
| PASS, plaintext = ISN (±NUL padding) | reconstruction fully confirmed [F] | record in §5.5 as ground-truthed; close this runbook |
| PASS, plaintext = other bytes | the signed unit is a struct, not bare ISN | reverse the struct against fn 0x1a010/0x21ee0 (identity getter); update §5.5 |
| REJECT everywhere in asuskey2 | token elsewhere or wrapped | repeat `--explore` on `asuskey`/`asuskey3`; if still nothing, the file lives on another volume (§4) — dump list revisited |
| PASS only with `--cert` variants | ASUS rotated the key on the donor's firmware | extract the donor ABL's type-0 cert (§5.5 recipe) and compare modulus hashes |
| dump all zeros | token never persisted (RAM-only verify at unlock time, like the ZF8 `asuskey2` flash stash) | note it; the partition is then not the store; §5.5's volume-reader hunt continues on the donor via the namespace GUID |

In every branch the unlock verdict is unchanged: no forgery becomes
possible.

## 8. Safety rules (hard)

- GhostLock **dump-only**. No flashing, no fastboot writes, no partition
  changes on the donor, ever.
- No destructive step without explicit approval from the project owner
  and the donor's owner.
- Donor data (ISN, IMEI-adjacent identifiers, dumps) stays out of the
  repo; commit only hashes and analysis conclusions, not raw dumps.

## 9. Effort / status

- Offline tooling: **done** (`work/verify_token.py`, self-tested).
- Remaining: donor + GhostLock access (external, scheduling), then
  §3→§6 — roughly an hour of analysis once the dump arrives.
