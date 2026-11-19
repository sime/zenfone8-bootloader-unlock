# ZenFone 10 (ASUS_AI2302) — Can the ZF8 findings unlock it?

**Date:** 2026-11-19
**Branch:** `zenfone10-portability`
**Question:** Do the ZenFone 8 bootloader-unlock findings
(`RESEARCH_HANDOFF.md` §12: the ABL factory challenge–response protocol
`oem gen-random` → `flash asuskey2` → `oem auth-hash` → `flashing unlock`,
keys `"12345678"`/`"28825252"`) apply to the ZenFone 10
(SM8550 / Snapdragon 8 Gen 2, `ASUS_AI2302`)?

Status: **IN PROGRESS** — see §3 for the empirical plan being executed.

---

## 1. Prior probability (before touching a ZF10 binary)

Arguments the protocol family carries over:

- **It is old, shared, platform-wide ASUS factory code, not ZF8-specific.**
  The ROG Phone II (2019, SD855) shipped the identical command set, under the
  internal name "Dungle unlock": `fastboot oem gen-random`, `oem auth-hash`,
  `oem auth-hash_2` (shakalaca fastboot dump,
  <https://gist.github.com/shakalaca/bbc439916f389a7275083f90539059de>).
  Additional handlers present there (`oem rsa_test_`, `oem enter-dload`,
  `get-verify_vbmeta_ret`) match the ZF8 ABL dispatcher almost name-for-name
  (RESEARCH_HANDOFF §12.7/§12.8) — i.e. ASUS has carried the same fastboot
  command implementation forward across SoC generations (SD855 → SD888 → …)
  for at least six years at the time of the ZF8 ABL.
- **ZenFone 9 evidence.** Members' `fastboot getvar` dumps on the ZF9
  (ASUS_AI2205, SD 8+ Gen 1) show the GPT partitions `asuskey`, `asuskey2`,
  `asuskey3` — the on-flash counterparts of the ZF8 protocol's flash targets.
- **ROG Phone 6/6D channel posts** (2022–23 devices) discuss
  `fastboot oem auth-hash` as the working unlock step — the protocol survived
  into ASUS's 2022–2023 bootloaders, including a MediaTek device (6D).
- The ZF8's own protocol is *factory* tooling (ATD/dongle authorization), used
  by ASUS service centers; there was never a reason for ASUS to remove it
  when they killed the *server* unlock, and the ZF8 A12→(A13?) record shows
  the keys stayed `"12345678"`/`"28825252"` (same value as ROG2-era).

Counter-arguments / risks:

- ASUS knew by late 2023 that enthusiasts read their bootloaders. The ZF10
  launched (Aug 2023) into exactly the period when ASUS was fighting the
  unlock community ("wall of shame", ARB additions). If they ever swept the
  factory fastboot commands out, 2023+ ABLs are where it would have happened.
- The ZF8 conclusion is n=1 (one device, one ABL, A12 `31.1010.0410.61`).
  Whether even the ZF8's *own* A13 ABL keeps the protocol was never tested
  (README "Read this first"). The ZF10 test cannot assume it.

**Net assessment before measurement:** high prior the protocol is present in
at least the launch-era (A13 `33.0220.0220.x`) ZF10 ABL; genuinely unknown
whether it survives into current A15-era bootloaders.

---

## 2. Firmware sources (verified live 2026-11-19)

All `dlcdnets.asus.com` direct links; sizes from HTTP headers.

| Package | Build (Android) | Bytes | Notes |
|---|---|---|---|
| `UL-ASUS_AI2302-ASUS-34.1004.0204.65-1.1.4-2312-user.zip` | A14 `.65` | 4,019,139,403 | **incremental — requires prior build A13 `.101`** (per ASUS release note) |
| `UL-ASUS_AI2302-ASUS-33.0220.0220.52-1.1.4-2308-user.zip` | A13 `.52` | 3,944,738,911 | second-ever public "Software Image for WW/EU/RU/IN/TW/US SKUs" |
| `UL-ASUS_AI2302-ASUS-35.0604.0404.65-1.1.4-2502-user.zip` | A15 `.65` | 4,427,590,121 | first A15 major upgrade |
| `UL-ASUS_AI2302-ASUS-35.0604.0404.109-1.1.4-2506-user.zip` | A15 `.109` | 4,449,704,889 | Jun 2025 |
| `UL-ASUS_I006D-ASUS-33.0210.0210.296-1.1.26-2305-user.zip` | ZF8 control | 3,400,904,610 | ZF8 A13 full — control experiment for "do 2023 ASUS bootloaders keep the protocol?" |

Gone from CDN (404): launch builds `33.0220.0220.10`/`.17`, A13 `.101`,
A15 `.140` (the latest, Sep 2026 — XDA `Firmware updates` thread 4620127
confirms it is no longer served).

Method note: every ZF10 `UL-…user.zip` is an A/B OTA package whose
`payload.bin` includes the `abl` partition update
(ZenFone-8-equivalent payloads verified locally to carry `abl`; ZF10 payloads
verified by extraction below). Older payloads are incremental (diff against
the previous build) — `payload-dumper-go` with `-old` chains them once a full
base image is available.

---

## 3. Empirical test plan

1. **Control (ZF8, A12)** — done historically: protocol present, live-unlock
   verified (handoff §12.9).
2. **Control (ZF8, A13 `.296`)** — extract `abl` from the A13 full payload,
   run the marker scan. Answers: did ASUS remove the factory protocol in
   their 2023 bootloaders? (They shipped the ZF8's `.296` in 2023-05, so it
   is evidence about ASUS's *behavior in 2023*, though not about the ZF10.)
3. **Chain-extract the ZF8 A13 bootloaders** `.296→.312→.314→.326→.332`
   from local delta payloads (`-old` chaining) — establishes whether the
   protocol persists across the ZF8's own update history.
4. **ZF10 A13 `.52`** — extract `abl`, scan markers, compare keys and
   handler layout vs the ZF8 ABL.
5. **ZF10 A15 `.65` (and `.109` if needed)** — same test on the
   current-generation bootloader that ZF10 devices actually run today.
6. If markers present: full RE of the ZF10 ABL handlers (confirm the
   challenge/response algorithm is the ZF8 one — MIX1/MIX2 transform, key
   table, CmdFlash `asuskey2` RAM stash, DevInfo authoritization persistence,
   `flashing unlock` gate). The ZF8 tooling (`work/disasm.py`, `work/emu.py`,
   `work/asusauth.py`) is directly reusable once addresses are remapped.
7. Only then: live-device validation on a real ZF10 (needs hardware;
   non-destructive through the `PASS` step per ZF8 §12.9).

Expected verdicts by outcome:
- Markers in `.52` + A15 → the ZF8 method ports; current-firmware ZF10s are
  likely unlockable locally. Live test still mandatory (n=1 lessons).
- Markers in `.52` only → unlock may require being on an old-enough
  bootloader; ARB analysis becomes the central question (ZF10 got explicit
  anti-downgrade notices from A14 `.180`, 2024-08).
- No markers anywhere → the ZF8 findings do **not** port as-is; the ZF10
  ABL is the first ASUS bootloader with the factory protocol removed.

## 4. Tooling added on this branch

- `work/extract_abl.py` — generic `abl.elf`/`abl.img` → LZMA payload → PE
  app carve + protocol marker scan (ASCII **and** UTF-16LE). Validated:
  reproduces `work/abl_payload.bin` byte-for-byte from `raw/abl.elf` and
  flags every ZF8 protocol marker.

## 5. Findings

*(filled in as measurements complete — see git history of this file)*
