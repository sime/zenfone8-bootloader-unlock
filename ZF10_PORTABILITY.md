# ZenFone 10 (ASUS_AI2302) — Unlocking it, with the ZF8 findings as reference

**Date:** 2026-11-19 (updated same day after the ABL deep-dive)
**Branch:** `zenfone10-portability`
**Goal:** unlock the ZenFone 10 bootloader. The ZenFone 8 findings
(`RESEARCH_HANDOFF.md` §12: `oem gen-random` → `flash asuskey2` →
`oem auth-hash` → `flashing unlock`, MD5 + MIX transforms, keys
`"12345678"`/`"28825252"`) are the *reference method* — the question is
whether it (or anything else derivable locally) unlocks the ZF10
(SM8550 / Snapdragon 8 Gen 2, `ASUS_AI2302`).

Status: **ABL (fastboot app) reverse-engineered** — the answer is below in
§5. The ZF8 recipe does **not** port; the ZF10 verifies an RSA-signed
token. One concrete local-unlock lead survives (§5.6).

Notation: **[F]** = fact verified against binaries (addresses are module
VAs — module = `payload.bin[0xC8:]`, i.e. the `linuxloader10.efi` PE32
app); **[I]** = inference.

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
| `UL-ASUS_AI2302-ASUS-35.0604.0404.65-1.1.4-2502-user.zip` | A15 `.65` | 4,427,590,121 | partial locally (3.1 GB), still yields `abl` + `vbmeta` (op data early in payload) |
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
5. **Live-device validation** — only remaining gate; no ZF10 attached so far.
6. **XBL unpack + `SecRSAVerifySig` padding audit** — new, the decisive step
   for the one surviving local-unlock avenue (§5.6).

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

Established by full disassembly of the A13 `.52` ABL (**[F]** throughout;
all addresses module VAs, `linuxloader10.efi = payload.bin[0xC8:]`):

```
is_unlock(decrypt_type)                 fn 0x2d080   (frame 0x1d0)
  ├─ buf            ← read_lock(ISN…)   fn 0x2c660(buf, 0x100)   @0x2d1d4
  │    ("…lock(ISN=%a),size=%d", UFS/RPMB identity data via protocol
  │     at GUID eb7a442a-cef4-40a7-a8ae-5a2e7f48e172)
  ├─ handle         ← ImageFromPartition fn 0x1a000(&p, AT(0x15)) → 0x21ed0
  │    (asuskey-partition image; fail prints "- read_asuskey fail")
  └─ verify(p, 0x100, image, len, type)  fn 0x471b0 "AppMain (decrypt_type = %d): plain_text…"
       └─ 0x46d70 "Verify : signature_len = %d, plain_text_len = %d"
            ├─ gBS->LocateProtocol(cert-store GUID eb7a442a…)      @0x46e2c
            ├─ select OEM cert by decrypt_type                    fn 0x45dc0
            │     0 → 0x121438 len 0x3dd   ("RD"/bootloader-unlock)
            │     1 → 0x121b4c len 0x361
            │     2 → 0x121815 len 0x337
            │     else → EFI_UNSUPPORTED
            ├─ ASN1X509GetRSAFromCert (protocol +0x18 prep, +0x10 extract)
            ├─ gBS->LocateProtocol(SecRSA GUID 5172ffb5-4253-7d51-c641-a701f973103c)
            ├─ SecRSABigIntReadBin ×2 (key import; "for modulus failed!" @0xf6cf5)
            └─ SecRSAVerifySig(ctx, 1, NULL, hash_id,
                    signature, sig_len,      ← asuskey token image
                    plain_text, plain_len)   ← ISN/lock data buffer
                  hash_id: case3→1 (VB_SHA1, len=sig_len), case2→3
                  (VB_SHA256, len 0x20); mode string @0xfbc49/f06c4
                  result prints "SecRSAVerifySig() : PASS !!/FAIL !!" (0xf26cd/0xf0701)
```

Verification maths runs in a **different bootloader stage** (protocol
producers are not in the abl module: the GUIDs each appear exactly once,
as LocateProtocol rodata; XBL image extracted — §5.7 — but its FVs are
compressed, so the implementation is not yet sighted **[F/I]**).

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

**The fastboot surface of the unlock** (**[F]**, strings + call graph):

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

**[I]** Reconstruction: the ZF10 unlock flow is
`fastboot flash asuskey2 <ASUS-issued token for this device's ISN>` →
`oem get-hwid` (or `flashing unlock`) → `is_unlock(0)` → RSA-verify the
token against the *AsusUnlock* e=3 public key with the device's own
lock/ISN data as the signed plaintext → DevInfo is unlocked. Exactly the
shape of ASUS's official (app/repair-center-issued) unlock — matches the
observed 2026 status quo of no free ZF10 unlock.

### 5.6 Verdict — fact vs inference

- **[F]** The ZF8 symmetric recipe (`gen-random` → local MD5+MIX with
  `"12345678"`/`"28825252"` → `auth-hash`) **cannot** unlock a ZF10:
  the challenge/response compute does not exist in the ZF10 ABL; the key
  strings are struct defaults; the MD5 library is dead code; `oem
  asus-unlock` verifies nothing by itself.
- **[F]** The ZF10 checks an RSA signature (token in the asuskey
  partition) over device-identity data, using certificates embedded in
  the ABL, one of which (`AsusUnlock`) is the bootloader-unlock root.
- **[I]** Therefore a local unlock requires either counterfeit
  signatures (needs the ASUS private key — not derivable) **or** an
  implementation weakness in the verification.
- **[F→I lead]** The AsusUnlock key uses **e = 3**. Low-exponent RSA
  with sloppy PKCS#1 v1.5 parsing is historically broken
  (Bleichenbacher/Finney-style forgeries: a single crafted blob with the
  right high bits can pass verifiers that don't check the full padding).
  Whether this is exploitable on the ZF10 depends 100% on the padding
  rigor of `SecRSAVerifySig`, which lives in XBL. This is the one
  concrete local-unlock avenue — hypothesis until XBL is unpacked.
- Live-device validation remains the final gate for any conclusion
  about *the* device in hand (n=1 lessons).

### 5.7 Next steps

1. **Unpack XBL** (Qualcomm MBN ELF, compressed FV segments; A13 `.52`
   XBL extracted: sha256 `3fecd40289f004ceef2e63a593c532dcf1bf953d2d3039eaab10c94df986d614`,
   1,212,416 bytes; xbl_config `9e8468c4…`; xbl_ramdump `a5a18e36…`).
   Find the protocol producers (GUIDs `eb7a442a…` cert-store,
   `5172ffb5…` SecRSA) and audit `SecRSAVerifySig`'s PKCS#1 v1.5 checks
   against the e=3 key. This decides the only surviving local avenue.
2. Complete the command map: exact `flashing unlock` handler flow
   (0x9c4xx subdispatch → DevInfo write), how `decrypt_type` is selected
   in `oem get-hwid` (`w19` provenance), the two `.data` X.509s' role.
3. Optionally confirm the token format from an officially unlocked ZF10
   (asuskey2 partition dump would give a ground-truth token to test the
   padding hypothesis against — non-destructive via GhostLock remote
   dumps only).
4. Live test once 1–2 give a concrete candidate.

---

## Appendix A — ZF10 A13 `.52` anchor table (module VAs)

| What | Where |
|---|---|
| dispatch rows {fn@+0, name@+8} | `0x1063a0`-`0x106900` (name pointers are tail-shared) |
| handler cluster / CmdFlashing | `0xa3000`-`0xa9000`; `0xab808` |
| `oem asus-unlock` (cmd_oem_auth_hash setter) | entry `0xa3fc4` (row fn `0xa3fd4`) |
| `oem get-hwid` (token-verify driver) | entry `0xa45bc` (row fn `0xa45cc`); token prints `0xa3714`, `0xa4734`, `0xa48cc` |
| `verify_RD_unlock` / RD token strings | `0xaf51c`; success print `0xaf7cc` |
| is_unlock | `0x2d080` (read_lock caller), typography `0xf1649` read_asuskey, `0xe3257` Verify PASS, `0x100074` Verify FAIL |
| read_lock(ISN) helper | `0x2c660` (RPC/UFS protocol `0x11000`, GUID-ish parse) |
| ImageFromPartition wrapper | `0x21ed0` (label string in-module); partition handle via `0x1a000(&p, 0x15)` |
| verify AppMain / decrypt core | `0x471b0` → `0x46d70` → `0x46000` |
| cert selection | `0x45dc0` (type→blob map: 0/1/2 → `0x121438`/`0x121b4c`/`0x121815`) |
| SecRSAVerifySig call | `0x465a4` (protocol slot +0x10 of GUID `5172ffb5…`) |
| hash modes | case3 → id 1 (SHA-1), case2 → id 3 "VB_SHA256" (strings `0xfbc49`, `0xf06c4`) |
| embedded unlock cert (type 0) | `0x121438` len `0x3dd`, RSA-2048 e=3, sha256(n) `cda39824…` |
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

## Provenance

Primary research: models GLM 5.3 (analysis) — all **[F]** items were
established by direct disassembly/hash verification recorded in the
session logs on this branch. No claims above rest on forum sources; those
appear only in §1 priors.
