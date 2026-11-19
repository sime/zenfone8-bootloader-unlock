# ZenFone 10 (ASUS_AI2302) — Unlocking it, with the ZF8 findings as reference

**Date:** 2026-11-19 (updated same day: ABL deep-dive, XBL unpack, padding audit)
**Branch:** `zenfone10-portability`
**Goal:** unlock the ZenFone 10 bootloader. The ZenFone 8 findings
(`RESEARCH_HANDOFF.md` §12: `oem gen-random` → `flash asuskey2` →
`oem auth-hash` → `flashing unlock`, MD5 + MIX transforms, keys
`"12345678"`/`"28825252"`) are the *reference method* — the question is
whether it (or anything else derivable locally) unlocks the ZF10
(SM8550 / Snapdragon 8 Gen 2, `ASUS_AI2302`).

Status: **answered — final** (2026-11-19). The ZF8 recipe does **not**
port. The ZF10 gate is an RSA-signed token over the device's ISN,
verified against an embedded AsusUnlock RSA-2048 **e = 3** key — and the
one candidate weakness (low exponent + sloppy padding) is **disproven by
byte-level audit** of the live verifier (§5.7): strict encode-then-compare,
full deterministic 0xFF PKCS#1 v1.5 padding, full-buffer memcmp. **No
local-unlock avenue survives**; unlocking requires a token signed with
ASUS's private key (§5.6).

Notation: **[F]** = fact verified against binaries; **[I]** = inference.
Coordinates: from §5.5 onward, addresses are **PE VAs** of
`linuxloader10.efi` (MZ header at `payload.bin+0xb8`, ImageBase 0, file
offset == VA). Sections before §5.5 and Appendix A use the older
`payload.bin[0xC8:]`-module offsets, which equal **PE VA − 0x10**;
Appendix A flags the re-verified rows.

---

## 1. Prior probability (before touching a ZF10 binary)

Arguments the protocol family carries over:

- **It is old, shared, platform-wide ASUS factory code, not ZF8-specific.**
  The ROG Phone II (2019, SD855) shipped the identical command set, under
  the internal name "Dungle unlock": `fastboot oem gen-random`, `oem auth-hash`,
  `oem auth-hash_2` (shakalaca fastboot dump,
  <https://gist.github.com/shakalaca/bbc439916f389a7275083f90539059de>).
  Additional handlers present there (`oem rsa_test_`, `oem enter-dload`,
  `get-verify_vbmeta_ret`) match the ZF8 ABL dispatcher almost name-for-name
  (RESEARCH_HANDOFF §12.7/§12.8).
- **ZenFone 9 evidence.** Members' `fastboot getvar` dumps on the ZF9
  (ASUS_AI2205, SD 8+ Gen 1) show the GPT partitions `asuskey`, `asuskey2`,
  `asuskey3` — the on-flash counterparts of the ZF8 protocol's flash targets.
- **ROG Phone 6/6D channel posts** (2022–23 devices) discuss
  `fastboot oem auth-hash` as the working unlock step — the protocol survived
  into ASUS's 2022–2023 bootloaders, including a MediaTek device (6D).

Counter-arguments / risks:

- ASUS knew by late 2023 that enthusiasts read their bootloaders. The ZF10
  launched (Aug 2023) into exactly the period when ASUS was fighting the
  unlock community ("wall of shame", ARB additions).
- The ZF8 conclusion is n=1 (one device, one ABL, A12 `31.1010.0410.61`).

**Net assessment before measurement:** high prior the *commands and
strings* are present in ZF10 ABLs; unknown whether the *algorithm* is.

---

## 2. Firmware sources (verified live 2026-11-19)

All `dlcdnets.asus.com` direct links; sizes from HTTP headers.

| Package | Build (Android) | Bytes | Notes |
|---|---|---|---|
| `UL-ASUS_AI2302-ASUS-34.1004.0204.65-1.1.4-2312-user.zip` | A14 `.65` | 4,019,139,403 | incremental (payload v2, 37 partitions) — **abl ships real content** (see §5.1) |
| `UL-ASUS_AI2302-ASUS-33.0220.0220.52-1.1.4-2308-user.zip` | A13 `.52` | 3,944,738,911 | complete locally; launch-generation bootloader |
| `UL-ASUS_AI2302-ASUS-35.0604.0404.65-1.1.4-2502-user.zip` | A15 `.65` | 4,427,590,121 | local copy truncated at ~3.0 GiB (no EOCD); yields `abl`/`xbl`/`tz`/`vbmeta` only — `uefi` ops sit at ~0xd40f251a, past EOF (§5.8) |
| `UL-ASUS_AI2302-ASUS-35.0604.0404.109-1.1.4-2506-user.zip` | A15 `.109` | 4,449,704,889 | Jun 2025 — not fetched |
| `UL-ASUS_I006D-ASUS-33.0210.0210.296-1.1.26-2305-user.zip` | ZF8 control | 3,400,904,610 | ZF8 A13 full — "do 2023 ASUS bootloaders keep the protocol?" |

Gone from CDN (404): launch builds `33.0220.0220.10`/`.17`, A13 `.101`,
A15 `.140` (the latest, Sep 2026 — XDA `Firmware updates` thread 4620127
confirms).

---

## 3. Empirical test plan

1. **Control (ZF8, A12)** — done historically: protocol present, live-unlock
   verified (handoff §12.9).
2. **Control (ZF8, A13 `.296`)** — extract `abl`, scan markers and
   instruction shapes. ✅ done (§5.3).
3. **ZF10 A13 `.52` / A14 `.65` (range-fetch) / A15 `.65`** — extract `abl`,
   scan markers, compare algorithm. ✅ done (§5.4/§5.5).
4. **Full RE of the ZF10 ABL auth path** — ✅ done (§5.5): find what the
   unlock gate actually verifies, byte-prove it.
5. **Live-device validation** — the remaining gate for any on-device claim;
   no ZF10 attached so far, and no candidate survives to validate (§5.6).
6. **XBL unpack + `SecRSAVerifySig` padding audit** — ✅ done (§5.7),
   decisive: padding is strict, so the e = 3 forgery avenue is closed.

---

## 4. Tooling added on this branch

- `work/extract_abl.py` — generic `abl.elf`/`abl.img` → LZMA payload → PE
  app carve + protocol-marker scan (ASCII **and** UTF-16LE). Reproduces
  `work/abl_payload.bin` byte-for-byte from `raw/abl.elf`.
- `work/annotate10.py` — ARM64 disassembly annotation for the ZF10 modules:
  adrp/add resolution to strings, `bl` target naming, restart-capable
  linear scan (capstone silently stops at undecodable words otherwise —
  every scanner must advance +4 and continue).
- `work/payload_manifest.py` — A/B OTA manifest parser (empirically
  re-verified schema, see §5.2) with `extract_op_bytes` for XZ ops;
  works against partial OTA files/HTTP ranges.

Bl/imm decoding note (applies to all scanners here): `BL` iff `(w>>26)&0x3F
== 0x25`, `B` iff `0x05`; `imm26 = w & 0x3FFFFFF` with bit-25 sign. An
earlier `>>5&0x7FFFF` mask produced false "no callers" results; all caller
walks were redone with the fixed decoder.

---

## 5. Findings

### 5.1 ASUS OTAs ship complete bootloaders — corrected

An earlier version of this section claimed (from a partial A14 `.65`
download) that A14 `.65` ships "no new ABL content (degenerate ZERO op)".
**That was a field-tag misparse — retracted.** With the corrected manifest
schema (§5.2), a 404 KB HTTP-range fetch of the A14 `.65` package settled
it:

| ABL | sha256 (manifest `new_partition_info` == extracted image) |
|---|---|
| ZF10 A13 `.52` | `51ee6aca46b91776539bfc7293e913ec4d6fee3f08ad46751310a2c20bdd77da` |
| ZF10 A14 `.65` | `8dee7383a681cf2f648bc53abe8f0d52cbe79dd87d1f58f00fa7178cefcd97b8` |
| ZF10 A15 `.65` | `4db03e1318d06486829258d3638fdf372460f517e9d0685281d603e06d7ac3ab` |
| ZF8 A13 `.296` (control) | `ba899f28d342a2862dfc8ac7a35d937c1e39d686f2799a278b7bf2ac65dd732a` |

Every `abl` update is one type-8 op carrying a multi-stream XZ blob that
decompresses to exactly `PartitionInfo.size` with exactly the
`PartitionInfo` sha256 (**[F]**, byte-verified). The same is true for
`xbl`, `xbl_config`, `xbl_ramdump`, `tz`, `hyp`, `aop`, `vbmeta`
(**[F]** — extracted & hash-verified for the A13 `.52` and range-fetched
A14 `.65` packages).

Method note for huge OTAs: `payload.bin` is STORED (method 0) in ASUS
zips; its local-file header sits in the first KBs, the manifest in the
first ~300 KB, so partial files or HTTP `Range` requests suffice for
any partition whose op data lands early (`abl` data_offset is 0 for
`.52`/A14 `.65`; xbl is ~100 KB from the payload end — still two ranges).

### 5.2 Manifest schema (empirically settled; parser: `work/payload_manifest.py`)

- **[F]** `payload.bin` header: `CrAU`, **big-endian** u64 version, u64 BE
  manifest size, u32 BE signature size; op data starts at
  `24 + msize + sigsize`.
- **[F]** `PartitionUpdate`: `f1`=name, `f6`=old info, `f7`=**new** info,
  `f8`=ops. `PartitionInfo`: `f1`=size (varint), `f2`=sha256.
- **[F]** `InstallOperation` (ASUS fork): `f1`=type, `f2`=data_offset,
  `f3`=data_length — **varints** (not AOSP's fixed64) — `f6`=dst extents,
  `f8`=data sha256. Constant-image partitions use a single `type=8` op
  with an XZ blob (`fd 37 7a 58 5a`); stock AOSP numbering would call 8
  "ZERO" — trust the blob magic, not the enum.

### 5.3 Control: the 2023 ZF8 ABL keeps the factory symmetrical protocol — and *also* has the RSA path

**[F]** The ZF8 A13 `.296` ABL (2023-05, extracted + hash-verified) retains
the complete ZF8 unlock stack: all commands (`gen-random`, `auth-hash`,
`auth-hash_2`, `get-imeiauth`), UTF-16 `asuskey2` ×3, `Random Num = `,
`Authorized Result`, both keys `"12345678"`/`"28825252"` (8-char, keylen
`0x40` slot, same `.data` layout as A12), MIX1/MIX2 instruction shapes
(exact dword hits at `0x466c0`/`0x466c8`-region), MD5 IV/constant tables.
I.e. the scanner suite detects everything it must.

**[F — plot twist]** The ZF8 A12 *and* A13 ABLs also contain the full
"asymmetric" machinery this study found in the ZF10: byte-identical
`AsusUnlock` mini-certificates incl. the same RSA-2048 **e=3** modulus
(sha256 `cda39824c2ef5c22bb14b6fc940c9ca4dca1896cf315b713fb5948ea715a13a8`),
and "AsusUnlock" strings. Both mechanisms have coexisted in ASUS
bootloaders since at least the ZF8. **[I]** So "present in the binary"
proves nothing about which one *gates* the unlock — that must be decided
per-device from the call graph (which is what §5.5 does for the ZF10,
and what the ZF8 emulation already did: on the ZF8 the gate is the
symmetric path).

### 5.4 ZF10 markers vs machine code

**[F]** Both ZF10 ABL generations (A13 `.52`, A15 `.65`; A14 `.65` same
modulo ±0x600 data shifts) carry the *protocol family surface*:
`gen-random`, `get-imeiauth`, UTF-16 `asuskey2` ×3, `Random Num = `,
`Authorized Result : PASS/FAILED`, keys `"12345678"`/`"28825252"`,
keylen slot `0x40`, `receive asuskey2 data`, `asus.authorized`.

**[F]** The ZF8 *algorithm* is absent in ZF10:

- MIX transforms: 0 hits for every ZF8 instruction shape
  (`ubfx`-rol2 `530e3d2b`, rol9 `53073d49`, `rev` `5ac00908` pairs)
  in both generations — while the ZF8-A13 control hits at its expected
  offset. Rotates would need `extr`/`lsl-lsr-orr` codegen; a module-wide
  scan for the ZF8 magic adds (`#6/#7/#3/#9`) finds **zero**.
- MD5: the table-driven implementation (IV `0x103e40` = 67452301…,
  sin-constants T-table `0x103fa8`, round-fn ptr table
  `0x104128`–`0x104140` with verified F/G/H/I semantics) has **no direct
  callers and no pointer references** — dead code kept from the shared
  factory code-base.
- Keys: the `"12345678"`/`"28825252"` dwords are *fields of a runtime
  asuskey2-content struct* (`0x2b2348-0x2b2366`) that the asuskey2 flash
  handler overwrites (`str w0,[x8,#0x354]` at `0xa03b8`; CRC prints at
  `0xa0694-0xa0a0`); one runtime integrity check (`ldp/cmp/str -1`) at
  `0xa0410`. **[I]** They are initial/scratch values, not live secrets.

**[F]** ZF10 fastboot dispatch table (rows 16 bytes: `fn@+0, name@+8`,
base `0x1063a0`): every listed handler name is a *tail-shared pool
pointer* (e.g. `' asus-lock' @0xa3a64`, `'oem asus-unlock' @0xa3fd4`,
`'oem get-hwid' @0xa45cc`, `' hash_' = "oem hash_"`, `' asus-unlock'`,
`' em get-imeiauth'`). True entry = stored `fn − 0x10` (the stored pointer
skips the stack-cookie prologue; handlers begin at `sub sp, …` after the
previous function's trailing `bl __stack_chk_fail`).

### 5.5 The ZF10 unlock gate: an RSA-signed token vs the device's ISN

Established by full disassembly of the A13 `.52` ABL and cross-checked
against a decompiler (Ghidra) model of the same PE. **[F]** throughout;
addresses are **PE VAs** of `linuxloader10.efi` (see Notation).

```
is_unlock(decrypt_type)                  fn 0x2d090   (frame 0x1d0)
  │   (arg stored [sp,0x84])
  ├─ isn_buf  ← read device identity      fn 0x1a010(&buf, 0x15) → 0x21ee0
  │    prints "[ABL] +++ is_unlock(ISN=%a),size=%d"          @0x2d198
  │    (string @0xec85d)
  ├─ sig_buf[0x100] ← read_asuskey        fn 0x2c670(buf, 0x100)   @0x2d1e4
  │    prints "[ABL] +++ read_asuskey(signature_len=%d)"     @0x102210
  │    backend fn 0x11010 reads the token from a filesystem volume:
  │      gBS(+0x138) = LocateHandleBuffer on
  │      gEfiSimpleFileSystemProtocol 964e5b22-6459-11d2-8e39-00a0c969723b
  │      (bytes @0x11fea8); "ExecImgFromVolume()" failure family;
  │      per-call namespace GUID 30f09946-3dea-4b24-bea4-ca6ab64ebfde @0x103e40
  └─ verify(sig, 0x100, plain, len, type) fn 0x471c0 "SecRSATestAppMain (decrypt_type = %d)"
       └─ RsaVerify                        fn 0x46d80
            │   "RsaVerify : signature_len = %d, plain_text_len = %d"
            │   keytype := 3 (constant)    @0x46dd8
            ├─ gBS->LocateProtocol(ASN1X509 408EC123-134E-4B80-9142-B89A0E08F8B3,
            │     record @0x11ff88)        → iface
            ├─ vb_read_oem_certificate(iface, out, decrypt_type)   fn 0x45dd0
            │     0 → 0x121438 len 0x3dd / 1 → 0x121b4c 0x361 / 2 → 0x121815 0x337
            │     (raw cert bytes via ASN1X509 iface +0x30)
            ├─ ASN1X509 iface +0x18 GetRSAFromCert, +0x10 → (N, e)
            └─ VerifySignature             fn 0x46010   @0x470a4
                 ├─ keytype switch: 2 → hashid 3 (len 0x20, SHA-256);
                 │     3 → hashid 1 (len = plain_len, RAW);
                 │     else → EFI_UNSUPPORTED
                 ├─ gBS->LocateProtocol(SecRSA EB7A442A-CEF4-40A7-A8AE-5A2E7F48E172,
                 │     record @0x11ff98)   @0x4635c   → iface
                 ├─ SecRSA iface +0x8 SecRSABigIntReadBin ×2 (import N, e)
                 └─ SecRSA iface +0x10 SecRSAVerifySig(ctx, mode=1, NULL, hash_id,
                        sig, 0x100, plain, plain_len)
```

**Provenance correction (retraction).** The previous revision attributed
the cert store to GUID `eb7a442a…` and SecRSA to `5172ffb5…`, and left the
protocol wiring flagged as possibly "swapped/dead" pending XBL inspection.
Both were one-record addressing slips on the `.data` GUID grid: the records
are `0x11ff78` 51AA59DE…, `0x11ff88` **408EC123** (ASN1X509 — used by
RsaVerify), `0x11ff98` **EB7A442A** (SecRSA — used by VerifySignature),
`0x11ffa8` 5172FFB5… (EnvDxe — *not* SecRSA). Byte-verified by resolving
each `gBS(+0x140)` Locate call (`0x11ff88` in fn 0x46d80; `0x11ff98` at
0x4636c in fn 0x46010). The same wiring exists in the field-proven ZF8
ABLs (§5.7), so the chain is live, not dead.

Callers of `is_unlock` (both **[F]**):

- the device-unlock flow (fn 0xcc0e0, "UNLOCK FAIL : %d") calls
  `is_unlock(0)` at 0xe1358 — **cert type 0 = the AsusUnlock key (e = 3)**;
- the guarded fastboot handler (`cmp w19,#3; b.lo` at 0xa7a3c; call at
  0xa7a68) calls `is_unlock(w19)` with a runtime cert index 0–2 (its
  source is a small getter, `bl 0x25ac`, masked to < 3);
- a second `SecRSATestAppMain` caller exists (mega-fn 0x9e810, call site
  0x9ff08): it builds a 19-byte plaintext from a request struct and passes
  **decrypt_type 1 — the "Internet Widgits" dev cert** — so it is not the
  unlock path.

**The embedded certificates** (**[F]**, format: 8-byte prefix + custom
mini-cert ASN.1: AlgId(sha256WithRSAEncryption) + issuer + validity +
subject + SPKI; parser named "ASN1X509GetRSAFromCert"):

| type | cert | key | notes |
|---|---|---|---|
| 0 ( bootloader/"RD") | C=TW, ST=Taiwan, L=Taipei, **O=Asus, OU=AsusUnlock, CN=AsusUnlock**, email AsusUnlock; validity 2015→2046 | RSA-2048, **e = 3** | n sha256 `cda39824…`, n=0xc6c5841d4af71d… |
| 1 | C=AU "Some-State", O="Internet Widgits Pty Ltd" (OpenSSL template!), O-variant "ASUS" | RSA-2048, e=65537 | dev-template |
| 2 | C=AU "Some-State", O=ASUS | RSA-2048, e=3 | dev-template |

Identical type-0 cert + modulus found at the same VAs in A14 `.65` and
A15 `.65` and in the ZF8 A12/A13 ABLs (**[F]**). The `.data` region next
to the asuskey2 struct additionally embeds two real X.509s (A13 VAs
`0x2b2412`/`0x2b27ea`: issuer C=CN JiangSu SuZhou O=ASUS OU=Phone
**CN=Timo / Timo_Xu@asus.com**, 2023-02-27, e=65537) — **[I]** likely the
IMEI/watermark-token verification certs.

**The fastboot surface of the unlock** (**[F]**, strings + call graph;
addresses in this paragraph are `[0xC8]`-module offsets = PE VA − 0x10):

- `oem asus-unlock` (entry `0xa3fc4`) is the renamed `cmd_oem_auth_hash`:
  it SafeString-stores the user argument into the auth-global page
  (`[0x2cb000+0xed0]`) via wrapper `0x2544` → EDK2 SafeString `0x3ab8`,
  then prints `"[ABL] cmd_oem_auth_hash - Authorized hash : PASS"` —
  unconditionally. A *setter*, not a verifier.
- `oem get-hwid` (entry `0xa45bc`) is the real **token-verify driver**:
  prints device info + `Random Num = ` (`0xa7cd0`), calls `is_unlock(type)`
  for `type < 3` (`cmp w19,#3; b.lo …` at `0xa7a2c`), prints
  `"Verify unlock token fail."` (`0xa4734`→`0xe6bc5`) and on success
  `"Device unlocked successfully."` (`0xa3714`/`0xa48cc`→`0xf6216`).
- `flashing unlock` / `flashing unlock_critical` / `flashing get_unlock_ability`
  strings resolved into the CmdFlashing cluster (`0xab808`) and the
  0x9c4xx flash-subdispatch; `flashing unlock` xrefs at `0x9c49c/0x9c4b8`.
- Three token universes with dedicated verify helpers: **RD**
  (`verify_RD_unlock` `0xaf51c`, "Check RD unlock token Success", "[BL]
  RD unlocked : plain_text= %a", `sn_buf = %a"), **WM = WaterMask**
  (`verify_WM_unlock`, "WaterMaskID", `oem asus-wm-unlock`,
  "Verify watermask unlock token fail."), and **xts** (`oem xts-unlock`,
  "Device is already xts unlocked!").
- Other ZF8-eq names: `oem hash_` (row `0xa5b30`) is a plain
  **state dumper** (prints `===`, `W_L/W_H`), not an auth-hash successor.

**[I]** Reconstruction: the ZF10 unlock flow is an ASUS-issued token for
this device's ISN (flashed via `fastboot flash asuskey2 …` and read back
by `read_asuskey`), then a trigger (`oem get-hwid` / `flashing unlock`) →
`is_unlock(0)` → RSA-verify the token against the *AsusUnlock* **e = 3**
public key, with the device's own ISN as the signed plaintext (raw-mode
PKCS#1 v1.5) → DevInfo is unlocked. Exactly the shape of ASUS's official
(app / repair-centre-issued) unlock — matches the observed 2026 status quo
of no free ZF10 unlock.

### 5.6 Verdict — fact vs inference

- **[F]** The ZF8 symmetric recipe (`gen-random` → local MD5+MIX with
  `"12345678"`/`"28825252"` → `auth-hash`) **cannot** unlock a ZF10: the
  challenge/response compute does not exist in the ZF10 ABL; the key
  strings are struct defaults; the MD5 library is dead code; `oem
  asus-unlock` verifies nothing by itself.
- **[F]** The ZF10 checks an RSA signature (token read via `read_asuskey`
  from a filesystem volume) over the device's ISN, using certificates
  embedded in the ABL; cert type 0 (`AsusUnlock`) is the bootloader-unlock
  root.
- **[I]** A local unlock therefore needs either counterfeit signatures
  (the ASUS private key — not derivable) **or** an implementation weakness
  in the verification.
- **[F — lead closed]** The AsusUnlock key uses **e = 3**, but the padding
  audit of the live verifier (§5.7) disproves the low-exponent avenue:
  `SecRSAVerifySig` is invoked with mode 1 and keytype 3 → hashid 1 (raw),
  and it is a strict encode-then-compare — it builds the complete
  PKCS#1 v1.5 EM (full deterministic `0xFF` fill, minimum padding
  enforced) and memcmps the **entire buffer** against the recovered
  `s^e mod n`. Bleichenbacher-style e = 3 forgeries need a digest-only or
  padding-lenient comparison; there is none here.
- **Net verdict [F/I]:** no local-unlock avenue survives in the A13 `.52`
  bootloader. Unlocking a ZF10 requires a token signed by ASUS's
  AsusUnlock private key (official app / repair channel).
- Live-device validation remains the final gate for any on-device
  conclusion (n=1 lessons) — but there is no candidate left to validate.

### 5.7 XBL DXE core: protocol providers and the `SecRSAVerifySig` padding audit

**[F]** The four GUIDs are served by DXE drivers that live in XBL, not in
the ABL. Both the ZF10 A13 `.52` XBL and — as the control — the ZF8 XBL
were unpacked (`xbl` ELF → outer FV → **gzip**-wrapped GUID-defined
section files; *not* LZMA), and the protocol-installation graph was read
from `InstallMultipleProtocolInterfaces` sites (a `ldr xN,[gBS+0x148];
br xN` tail-thunk pattern — an earlier census missed these). Provider map
(identical for ZF10 `.52` and ZF8):

| GUID | provider | iface slots | role |
|---|---|---|---|
| `408EC123-134E-4B80-9142-B89A0E08F8B3` | ASN1X509Dxe | 7 | cert bytes, `GetRSAFromCert`, RSA params |
| `EB7A442A-CEF4-40A7-A8AE-5A2E7F48E172` | SecRSADxe | 2 crypto | +0x8 `BigIntReadBin`, +0x10 `SecRSAVerifySig` |
| `5172FFB5-4253-7D51-C641-A701F973103C` | EnvDxe | 6 | trivial getters (constants/defaults) |
| `8E5E…` | VerifiedBootDxe | 9 | facade brokering ASN1X509 |
| `55B1D734…` | UCDxe | — | irrelevant to this path |
| `51AA59DE…` | — | — | referenced by the ABL, not installed in scope |

**[F]** The ZF8 census is structurally identical (same providers, same
2-slot SecRSA, same trivial 5172 getters). ZF8 unlock works in the field
with this exact wiring, which rules out any "dead code / swapped provider"
reading of the ZF10 wiring.

**The audit (SecRSADxe, all **[F]**).** The ABL-side call resolves to:

- iface slot +0x8 = fn `0x14e4` → `bl 0x15b0` (`BigIntReadBin`; returns
  `0x50`, or 0 on failure) — imports N and e from the ASN1X509 key;
- iface slot +0x10 = fn `0x1518` → argument shuffle → **`bl 0x1670`** —
  the verify core, i.e. `SecRSAVerifySig` *is* 0x1670 (byte-linked, no
  ambiguity).

`0x1670` performs:

1. `s^e mod n` via fn 0x1e9c into a fresh buffer (0x1738), with an **exact
   length** requirement (0x1740–0x1748).
2. For **mode 1** (the mode the unlock chain passes): build the complete
   expected EM via fn 0x1840 (0x1784) and compare the whole buffer with
   fn 0x2094 (0x17a8); any difference yields error 0x1000.
3. For mode ≠ 1: fn 0x19f8 (hash index 0–7) — not used by the unlock path.

`0x1840` is a strict PKCS#1 v1.5 signature encoder, byte-verified at
0x1940–0x19c0: `EM[0]=00, EM[1]=01, memset(EM+2, 0xFF, k−3−t−m), 00,
[DigestInfo prefix (hash table stride 0xc0, prefix at entry+0x98)], msg`.
It enforces minimum padding (error 0x1004 when `k < t+11` or
`k−11−t < m`). There is no branch that skips or randomises the `0xFF`
fill and no "look only at the digest" comparison. Hash-table indices
(SecRSADxe rodata @file 0x6198): **1 = raw** (digest_len 0, no
DigestInfo), 2 = SHA-1 (OIW OID), 3 = SHA-256, 4 = SHA-224, 5 = SHA-384,
6 = SHA-512.

**Why e = 3 does not help [F].** The classic low-exponent forgery
(Bleichenbacher '06 / Finney) requires the verifier to accept an `s^e mod n`
whose high bits match a loosely-specified encoding while padding and
trailing bytes stay attacker-controlled — feasible because `s^3` can be
made congruent to such an encoding with a short cube-root search. Here the
encoding is fully specified and deterministic (`00 01 FF…FF 00 ||
plaintext`, ~234 forced `0xFF` bytes at the usual ISN lengths) and compared
in full. A forgery would need an integer `s` with `s^3 ≡ EM (mod n)`
*exactly* over a 2048-bit modulus — the cube-root gap is astronomically
larger than any fix-up an attacker can supply.

**Verdict: the AsusUnlock e = 3 key is not exploitable via
`SecRSAVerifySig`. The last local-unlock avenue is closed.**

### 5.8 Next steps

The decisive question is answered (§5.6/§5.7): there is no local weakness
to weaponise. What remains is optional confirmation, not a path to unlock:

1. **Ground-truth token** from an officially unlocked ZF10 (`asuskey2`
   dump, non-destructive via GhostLock remote dumps only) — would confirm
   the reconstruction (raw-mode PKCS#1 v1.5 signature over the ISN-derived
   plaintext) but cannot produce a forgery.
2. **`.52 → .65` wiring diff** — blocked: the A15 `.65` OTA download is
   truncated at ~3.0 GiB while the `uefi` partition ops start at
   ~0xd40f251a, past EOF. Re-download the full 4.4 GB zip to compare
   (expected: no semantic change).
3. **Remaining ZF10 ABL corners** (none plausibly change the verdict): the
   `flashing unlock` → DevInfo write path, the RD/WM/xts token helpers
   (`verify_RD_unlock`, WaterMask), and the two `.data` X.509s (CN=Timo).
4. **Live validation** only if a candidate ever appears; none does.

---

## Appendix A — ZF10 A13 `.52` anchor table

Coordinates: `[0xC8]`-module VAs (`payload.bin[0xC8:]`); **PE VA = +0x10**.
Rows marked ↦ were re-derived this revision and are given in **PE VA**.

| What | Where |
|---|---|
| dispatch rows {fn@+0, name@+8} | `0x1063a0`-`0x106900` (name pointers are tail-shared) |
| handler cluster / CmdFlashing | `0xa3000`-`0xa9000`; `0xab808` |
| `oem asus-unlock` (cmd_oem_auth_hash setter) | entry `0xa3fc4` (row fn `0xa3fd4`) |
| `oem get-hwid` (token-verify driver) | entry `0xa45bc` (row fn `0xa45cc`); token prints `0xa3714`, `0xa4734`, `0xa48cc` |
| `verify_RD_unlock` / RD token strings | `0xaf51c`; success print `0xaf7cc` |
| is_unlock ↦ | PE VA `0x2d090` (frame 0x1d0, arg @`[sp,0x84]`); ISN identity `0x1a010`+`0x21ee0`; token `0x2c670`; verify `0x471c0`→`0x46d80`→`0x46010` |
| read_asuskey (token) ↦ | PE VA `0x2c670`; backend volume reader PE VA `0x11010` (LocateHandleBuffer on gEfiSimpleFileSystemProtocol); namespace GUID `30f09946…` @PE `0x103e40` |
| ImageFromPartition wrapper | `0x21ed0` (label string in-module); partition handle via `0x1a000(&p, 0x15)` |
| verify AppMain / decrypt / verify ↦ | PE VA `0x471c0` → RsaVerify PE `0x46d80` (keytype = 3 @`0x46dd8`) → VerifySignature PE `0x46010` |
| cert selection ↦ | PE VA `0x45dd0` (type→blob map: 0/1/2 → `0x121438`/`0x121b4c`/`0x121815`) |
| SecRSAVerifySig ↦ | ABL slot +0x10 of **EB7A442A** (record @PE `0x11ff98`, Locate @`0x4636c`); provider body PE VA `0x1518`→`0x1670` |
| hash modes ↦ | PE VA `0x46010` switch: keytype 3 → hashid 1 = **raw** (len = plain_len); 2 → hashid 3 = SHA-256 (len 0x20); else EFI_UNSUPPORTED. Table: idx 1 raw / 2 SHA-1 / 3 SHA-256 / 4 SHA-224 / 5 SHA-384 / 6 SHA-512 |
| embedded unlock cert (type 0) ↦ | PE VA `0x121438` len `0x3dd`, RSA-2048 e=3, sha256(n) `cda39824…` (byte-verified via `openssl x509 -inform DER`) |
| asuskey2 struct / key defaults | `0x2b2348`-`0x2b2366` (keylen 0x40 slot at `0x2b234c`, keys `0x2b2354`/`0x2b235d`) |
| asuskey2 flash handler writes | `0x9f238`-`0xa13c4` region; `receive asuskey2 data` `0xefc32`-family |
| .data X.509s (ASUS CN=Timo etc.) | `0x2b2412`, `0x2b27ea` (A13; A14 +0x10) |
| auth globals page | `0x2cb000+0xed0..0xedf` (asus-unlock stores its arg ptr at +0xed0) |
| fastboot flash-subdispatch strings | `flashing unlock` `0xff567`(ctx) — xrefs `0x9c49c/0x9c4b8`; `unlock_critical` `0xe8b4d` |

## Appendix B — ZF8 reference anchors (for diffing)

MIX1 `0x46514`, MIX2 `0x46588`, response calc `0x465f8`, CmdOemGenRNG
`0x4de64`, CmdOemAuthHash `0x4df80`, key table `0x1e669c/0x1e66a5`,
DevInfo `0x1fe328` (+0xc guard, +0x10 authorized, +0x82 random,
+0x3b4/+0x3c4 buffers), `Authorized Result : PASS` `0x4e13c`. All
verified by live emulation (`work/emu.py`, `work/asusauth.py`).

## Appendix C — ZF8 cross-check (control) and XBL carve recipe

**[F]** ZF8 A13 `.296` ABL: `is_unlock` @`0x2f910`; one giant
`SecRSATestAppMain` region `0x3a458`–`0x3d4b8` (it contains per-app
sub-prologues, so a naive "stp x29,x30,[sp,#-N]" walk sees one symbol);
GUID records `0x1dd424` 51AA / `0x1dd434` 408EC / `0x1dd444` EB7A /
`0x1dd454` 5172, each preceded by a 4-byte prefix (real GUID at +4);
5172-Locate failure prints "…rifySignature: LocateProtocol failed".

**[F]** ZF8 XBL carve: ELF64LE, outer FV at PH8 (file `0x8c000`,
`8C8CE578…`); inside are GUID-defined-section files whose 24-byte headers
end in a raw **gzip** stream (not LZMA) → inner FVs. The ZF8 DXE census
matches the ZF10 `.52` provider map exactly (§5.7).

**[F]** ZF10 `.52` XBL: sha256
`3fecd40289f004ceef2e63a593c532dcf1bf953d2d3039eaab10c94df986d614`
(1,212,416 bytes); recipe identical (ELF PH8 → outer FV → GUID-defined
gzip sections → inner FVs).

## Provenance

Primary research: models GLM 5.3 / DeepSeek V4.1 Flash (analysis) — all
**[F]** items were established by direct disassembly/hash verification
and, from §5.5/§5.7, by decompiler output (Ghidra-backed REA:
`analyze_function` pseudocode + native value-flow) recorded in the session
logs on this branch. No claims above rest on forum sources; those appear
only in §1 priors.
