# ASUS ZenFone 8 (I006D/EU) — Bootloader Unlock Research Handoff

**Date:** 2026-11-19
**Author:** field notes from a live device session
**Primary model:** GLM 5.3 — research, reverse-engineering, tooling, live run.
**Secondary model:** DeepSeek V4.1 Flash — independent peer review (§14).
**Purpose:** hand off everything learned to another model/engineer so research can continue
without repeating the work. Facts are marked; inferences are marked **[inference]**.
**Caution:** §12 publishes factory unlock keys and the complete working unlock sequence
(hardcoded keys `"12345678"` / `"28825252"`). Treat this document as containing
exposed credentials.

---

## 1. Executive summary

- **Decisive (second session): the bootloader WAS UNLOCKED — fully locally, no server.**
  A factory challenge-response protocol was found in ABL (`oem gen-random` →
  `flash asuskey2` → `oem auth-hash`), reverse-engineered completely, verified in
  emulation and live on the locked device (PASS), and used to unlock
  (`fastboot flashing unlock`): `flash.locked=0`, `verifiedbootstate=orange`,
  `asus.authorized=1`, Android booted normally. See §12, esp. §12.9/§12.10.
- **For the app/server path** the earlier findings stand: the community
  "downgrade + MITM" trick is dead — ASUS's unlock server refuses every request
  with `retCode 405 "NOT ALLOWED"` (app error `10405`), and MITM is also blocked
  client-side: re-signing the unlock APK makes the system DM service reject it
  (`"com.asus.unlock is not ASUS package"` → `11003`) before any network call.
- The paid route (ASUS EU "executive care", ~€185, reported working Dec 2025) still
  exists but was never needed.
- A **full downgrade from A13 `33.0210.0210.332` to A12 `31.1010.0410.61` was performed
  successfully on the live device** using ASUS's signed RAW firmware over fastboot — even
  though the bootloader was **locked**. This proves the RAW-flash path works on a locked BL
  and that the anti-rollback fuse did **not** brick the device; that A12 package is also
  the ABL that §12 was reverse-engineered from.
- Phase 3 (post-unlock): the device has since been upgraded to A13 firmware and
  LineageOS installed — see §13.
- **UPDATE (Nov 19 2026, second session):** a **fully local, server-independent factory
  challenge-response protocol was found in ABL** (`oem gen-random` → `flash asuskey2` →
  `oem auth-hash`). The response algorithm was reverse-engineered completely, verified
  against emulated ABL code, and verified live on the locked device: PASS, with the
  authorization persisted to the devinfo partition. **The bootloader was then UNLOCKED
  with `fastboot flashing unlock` — final state: `flash.locked=0`,
  `verifiedbootstate=orange`, `asus.authorized=1`, Android booted normally.** The
  server is irrelevant to unlocking this device. See §12, esp. §12.9.

---

## 2. Target device (initial state, pre-unlock)

| Property | Value |
|---|---|
| Model | `ASUS_I006D` (ZenFone 8, `lahaina` / Snapdragon 888 / SM8350) |
| Product | `EU_I006D`; system/product name `WW_I006D` |
| Serial | `<SERIAL>` |
| Region | `ro.boot.country_code=EU` |
| Carrier string | `EU-ASUS_I006D-WW` (`ro.vendor.product.carrier`) |
| Original build | `33.0210.0210.332` (Android 13, built 2024-01-24, sec patch 2023-11-01) |
| Original fota | `WW_I006D-WW_user_33.0210.0210.332-user-20240124` |
| Bootloader | `Post-CS3-1-WW-user` |
| Slot | `a` (A/B, `slot-count:2`) |
| Lock state | `unlocked:no`, `secure:yes`, `mask_unlocked:N`, `rt_unlocked:locked`, `rd_unlocked:locked` |
| AVB | `avb_version 1.1`, `verifiedbootstate=green`, `veritymode=enforcing` |
| ATD flags | `ro.boot.asus.authorized=0`, `ro.boot.asus.remount=0`, `vendor.atd.unlocked.ready=0` |
| Anti-rollback | **not readable** — `fastboot getvar anti` → `GetVar Variable Not found` |
| HWID | `7`; `fastboot getvar project` → `ZS590KS` |
| DM client | `com.asus.dm` = `DMClient.apk` v`3.1.0.74_230905` (system app) |
| Unlock app | `com.asus.unlock` v`1.0.0.7_210127`, `minSdk=29`, **`targetSdk=30`** |

State above = **initial state, pre-unlock** (as first observed on A13 `.332`, and on A12
`.61` after the §6 downgrade). Current state: **bootloader UNLOCKED** (§12.10:
`flash.locked=0`, `verifiedbootstate=orange`, `asus.authorized=1`), LineageOS installed
(§13). The mid-project freezes no longer apply on the A13-era builds
(`ota_disable_automatic_update` reads `null`; FOTA/system-update works on the unlocked
bootloader — §13.1).

---

## 3. The unlock flow (reverse-engineered by the community)

From XDA thread "Unlocking the bootloader and rooting" (Dev4Mod, ROG 6) and follow-ups:

- The `AsusUnlock` app binds to the **system** service `com.asus.dm/.c2dm.UnlockService`
  (`AsusUnlockService`). The app is only a UI/client; **`com.asus.dm` performs the unlock.**
- App flow (from logcat): `check Service` → `check Internet` → `check verify` →
  `register DMServer` → server response → `ReturnFail` / `DMRegister`.
- The app POSTs to **`https://dm.asus.com/unlock/register`** with at least:
  `apkVersion`, `swVer`, `keyIndex`, plus device identity (`SNI`/SSN, IMEI...).
- Per Dev4Mod:
  - A client-side **authentication token** is built by RSA-encrypting
    `SSN + IMEI + "#UnlockTool"`.
  - The server returns a **`secrettoken`** which is written to the `/ADF` partition
    (specifically `/ADF/asuskey.bin`) — this is the key that actually unlocks.
  - `swVer` is only a **version gate** (server checks you're on a sufficiently new/old build);
    `keyIndex` is ignored.
- **Critical:** the `secrettoken` came from the **server**, not computed on-device. So the
  "MITM" trick only rewrote `apkVersion` and `swVer` (to pass the gate); the key still had to
  be issued by ASUS. Once the server stopped issuing keys, no client change could help.

### swVer format
```
<android-major>..<fota-version-with-9999999..999999>..<carrier>
```
Worked examples:
- A13 `.314`, non-EU: `13..WW_I006D-WW_user_9999999..999999.0210.0210.314..ASUS-ASUS_I006D-WW`
- A13 `.296`: `13..WW_I006D-WW_user_9999999..999999.0210.0210.296..ASUS-ASUS_I006D-WW`
- A12 `.160`, EU: `12..WW_I006D-WW_user_9999999..999999.1010.0411.160..EU-ASUS_I006D-WW`
- A12 `.61` (this device, EU): `12..WW_I006D-WW_user_9999999..999999.1010.0410.61..EU-ASUS_I006D-WW`

### Community status table (from XDA, Jan 2024)
| Build | Unlock worked? |
|---|---|
| A12 `31.1010.0411.160` (a.k.a. `99.1010.0411.160`) | **yes** |
| A13 `33.0210.0210.314` | **yes** |
| A13 `33.0210.0210.296` | **yes** |
| A13 `33.0210.0210.326` | **no** |
| A13 `33.0210.0210.332` (this device's original) | **no** |

ASUS added **anti-rollback** to patch the method (documented in zenfyrdev "wall of shame").
The unlock program was quietly killed Nov 2023 and ASUS confirmed (Oct 2025) it is **not
coming back**.

---

## 4. Server behavior — hard evidence

### 4.1 Endpoint responses (probed from this machine, 2026-11-18)
- `dm.asus.com` → `103.10.4.184`; TLS cert issued by Sectigo OV, `CN=dm.asus.com`,
  **reissued Dec 2025, valid to Jan 2027** (so the host is still maintained).
- `GET` and `POST` to `/unlock/register`, `/unlock/query`, `/unlock/unlock`,
  `/api/unlock/register` (and any path) all return HTTP 200 with:
  ```json
  {"retCode":407,"message":"success"}
  ```
  i.e. a **catch-all stub** — no per-request logic, no key.

### 4.2 Genuine app on the unlockable A12 build (decisive)
With the genuine ASUS-signed app, direct connection (no proxy), on A12 `31.1010.0410.61`:
```
UNL->UnlockActivity: Unlock process now at register DMServer
ViseLog: body:{"data":{"project_status":"","project":""},"retCode":405,"message":"NOT ALLOWED"}
UNL->ReturnFail: Login1 error !!! retCode : 405 message : NOT ALLOWED
UNL->DMRegister: Login error !!! retCode : 405 message : NOT ALLOWED
```
The app then shows **`10405`** ("Failed to unlock your device, please try again later.[10405]").
This matches multiple ZenTalk reports of `10405`.

**The actual request (captured from ViseLog, 2026-11-18):**
```
POST https://dm.asus.com/login?credData=<RSA(SSN+IMEI+"#UnlockTool") b64url>&imei=<IMEI>&model=ASUS_I006D&carrier=EU-ASUS_I006D-WW
→ HTTP 200  {"data":{"project_status":"","project":""},"retCode":405,"message":"NOT ALLOWED"}
```
Note the **endpoint is `/login`, not `/unlock/register`**. The mitmproxy script in the
community method rewrites `apkVersion`/`swVer` on **`/unlock/register`** (the version gate).
The `405` here is returned one step **earlier**, at the `register DMServer` → `/login` stage, with
empty `project_status`/`project`. So the deny is upstream of the version gate the MITM patched.

**Conclusion (app/server path):** the server denies at `/login` before the version gate; no
build, region, or `swVer` rewrite can unlock *via the app*. *(Caveat: this live test was on
A12 `.61`; the community's known-good A12 was `.160`. A rigorous reproduction should retry
from `.160`/`.296`. But a `/login` denial with empty project is a server-side
eligibility/service signal, not a version mismatch.)* The local ABL protocol (§12) is an
independent path that bypasses the server entirely and is unaffected by this conclusion.

---

## 5. MITM attempt — and why it is now blocked twice over

1. **Server:** no longer returns a `secrettoken` (see §4). This alone kills it.
2. **Client trust:** `com.asus.unlock` is `targetSdk=30`, so Android **ignores user-installed
   CAs** for it. Interception with a user-CA (mitmproxy) fails:
   `Client TLS handshake failed ... does not trust the proxy's certificate`.
3. **Signature check:** to make it trust a user CA we patched the APK with
   `apk-mitm` (adds a network-security-config trusting user CAs, strips pinning) — but
   `apk-mitm` must **re-sign** it (debug key). Then the system DM service rejects it:
   ```
   DMClient: utils> com.asus.unlock is not ASUS package.   (repeated)
   ```
   Result: error **`11003`**, and **no `dm.asus.com` request is ever made**.
   → **Catch-22:** MITM requires re-signing; re-signing breaks ASUS's signature check.
   Only a **system** CA (root) would avoid re-signing — and there is no root.

---

## 6. Downgrade procedure that WORKED (reproducible)

### 6.1 Artefacts
- RAW image: `WW-ZS590KS-31.1010.0410.61-MR0-2204-user-20220422.zip` → **A12 `31.1010.0410.61`**
  - 4,006,660,447 bytes; 78 files; 7,792,859,256 bytes uncompressed; zip integrity verified.
  - Mirror used (Google Drive): `https://drive.google.com/file/d/1D0FhjEEYXYahCkD163kHOtpITYOUqSho/view`
    (downloaded with `gdown`).
  - ASUS still hosts the **A11** RAW: `https://dlcdnets.asus.com/pub/ASUS/ZenFone/ZS590KS/WW__ZS590KS_30.11.51.41_MR0_20210513_release-user.raw.zip` (3.5 GB, 200 OK).
  - The A12 `.160` full (`UL-ASUS_I006D-ASUS-99.1010.0411.160-1.1.9-9999-user.zip`) is MEGA-only
    (`mega.nz/file/z0pQDQzZ#WZ9CAbOGNQqXK3BDcmQs1wJ6eHvozyElXRpGPrSL9EI`); MEGA blocks
    anonymous downloads here (`-16`).
- The RAW package is a **fastboot image set** (not an on-device OTA):
  `abl.elf`, `xbl.elf`, `xbl_config.elf`, `super.img` (6.87 GB), `boot.img`, `vendor_boot.img`,
  `dtbo.img`, `vbmeta*.img`, `gpt_both0..6.bin`, `persist.img`, `ADF.img`, `ASDF_384M.img`,
  `ASUS-xrom.img`, `firmware/*` (incl. **`prog_firehose_ddr.elf`**, `prog_firehose_lite.elf`,
  `NON-HLOS.bin`, `xbl`, `tz`, `hypvm`, `aop`, `devcfg`, `qupv3fw`, `cpucp`, ...),
  plus `update_image.sh`, `update_image_for_mac.sh`, `flashall_AFT.cmd`, and CRC32 manifests.

### 6.2 What the script does (`update_image_for_mac.sh`)
Flashes, in order: `misc` (erase) → `abl_a/b` → **`reboot-bootloader`** → `multiimgoem_a/b`
→ GPT `partition:0..6` → `xbl & xbl_config` → `shrm` → `abl` (again) → `aop` → `tz` → `hyp`
→ `modem` → `bluetooth` → `dsp` → `keymaster` → `rtice` → `storsec` → `spunvm` →
`qweslicstore` → `devcfg` → `qupfw` → `cpucp` → `logfs` → `uefisecapp` → `featenabler` →
`imagefv` → `ADF.img` → `vbmeta` → `vbmeta_system` → `boot` → `vendor_boot` → `dtbo` →
`xrom` → `asdf` → erase `super` + flash `super.img` → CRC32 self-check of every partition →
`oem factory-reset` → reboot.
It self-checks `fastboot getvar project == ZS590KS` and `oem get-hwid`.

### 6.3 How it was actually run (locked BL, macOS)
- The ASUS script uses `sudo` and a bundled **x86_64** `fastboot_for_mac` (runs under Rosetta;
  reports `fastboot 30.0.5`). A no-sudo copy was made:
  `sed 's/sudo //g' update_image_for_mac.sh > flash_nosudo.sh` (fastboot needs no root on macOS).
  A system-fastboot variant (`sed 's#./fastboot_for_mac#fastboot#g'`) exists as fallback.
- Command: `cd raw && bash flash_nosudo.sh 2>&1 | tee flash_run.log`.

### 6.4 Operational gotchas encountered
- **USB dropouts:** the device repeatedly fell off USB after `adb reboot` / `fastboot reboot`;
  only a **full phone power-cycle + cable reseat** restored it. During a wedged fastboot
  channel, `fastboot devices` still listed the phone but `getvar`/`flash` **hung**. A full phone
  power cycle fixed it.
- **Orphaned fastboot processes** from a killed session can hold the USB handle → same hang.
  `pkill -9 -f fastboot` + replug.
- **Abort rule:** the first real write is `abl_a`. An anti-rollback refusal would appear there.
  It did **not** — the flash completed and CRC32 passed for all partitions incl. `super`.
- Result: booted into A12 `31.1010.0410.61`; ARB did **not** block it.

---

## 7. Open research leads (for a new model)

**Status: superseded by §12 — the device is unlocked.** Kept as the historical
server-path research queue; none of it was ever needed. Leads 4–6 (EDL, `/ADF`, ATD)
are moot for unlocking, but lead 4 remains relevant as *rescue* knowledge
(EDL firehose availability — see the relock caution in §13.3).

Ranked by promise. None are known to work yet (as researched pre-§12).

1. **`com.asus.dm` (DMClient) reverse engineering.** Decompile `DMClient.apk`
   (`/system/app/DMClient/DMClient.apk`, v3.1.0.74). Determine: exact `/unlock/register`
   params; how `secrettoken` is validated; whether the client-side RSA of
   `SSN+IMEI+"#UnlockTool"` uses an **em-bedded public key** (if so, the token is reproducible
   offline, but the *key* still comes from the server). Look for a **local** unlock path used by
   factory/ATD that bypasses the server.
2. **Is `405 NOT ALLOWED` per-IMEI or global?** Try with a different SIM/region identity, or
   inspect whether the response depends on any header. (Evidence strongly suggests global.)
2b. **Did the RAW flash change the device identity used in `credData`?** `credData` =
   RSA(SSN+IMEI+"#UnlockTool"). A full RAW flash rewrites `ADF`, `persist`, `asdf`, `xrom`;
   if ASUS's "SSN" lives in one of those, the computed `credData` may no longer match the
   value ASUS has on file → `/login` returns `405` even if the service were alive. Test by
   comparing pre/post-flash `credData`, or by running the same app on a never-flashed ZF8.
3. **Cloned-server feasibility.** Chinese paid unlockers reportedly emulated the ASUS server
   (as `com.asus.dm`'s backend). If the `secrettoken` is deterministic per device from data +
   a key present in DMClient/firmware, a clone is possible. Inspect the APK/firmware for the
   key-derivation and for any symmetric/private material.
4. **EDL / firehose.** SM8350 normally needs a signed firehose. Interesting: the RAW package
   ships **`firmware/prog_firehose_ddr.elf`** and `prog_firehose_lite.elf`. If these are
   ASUS-signed programmers that authenticate on this device, EDL could read/write partitions
   (e.g. `ADF`/`asuskey.bin`, `devinfo`-like state) or dump the unlock state. Verify whether the
   retail SM8350 accepts them (very likely it will **not** — auth required).
5. **`/ADF` partition.** The raw image flashes `ADF.img` (32 MB). Per Dev4Mod the unlock key is
   `/ADF/asuskey.bin`. Study what `ADF.img` contains and whether an unlock can be forced by a
   crafted `asuskey.bin` (it must be signed/verified by the bootloader — likely impossible).
6. **ATD path.** `com.asus.atd.deviceproperty` / `com.asus.atd.smmitest` exist. Factory "ATD"
   unlock (`ro.boot.asus.authorized`) may be reachable via SMIT/diagnostics. Unexplored.
7. **Zenfone 9 method transplant.** The ZF9 had a similar exploit that ASUS patched with ARB.
   Review the ZF9 thread for any primitive that does not depend on the server.
8. **Paid ASUS EU route (legal, works).** `executivecare@asus.com` / EU support; ~€185.
   Confirmed working Dec 2025 (phone picked up, unlocked, returned). ASUS lost a UK case over
   removing the advertised feature; EU warranty argument is strong.

---

## 8. Dead ends (do not repeat)

- MITM with a **user** CA → app is `targetSdk 30`, ignores user CAs.
- Patch APK with `apk-mitm` → re-sign breaks `com.asus.dm` signature check (`11003`, no request).
- `fastboot oem unlock` → not supported by ASUS bootloader.
- `fastboot flashing unlock` **without authorization** → rejected by the gate (this was
  originally recorded as "not supported"). With the §12 authorization
  (rd_unlocked getter = 1) it **works** — it is how the device was unlocked (§12.10).
- `EDLUnlock` (Giovix92) → only pre-2018 MSM89xx (alephsecurity EDL exploit); SM8350 unaffected.
- EDL couldn't be tested for lack of an authenticated firehose handshake.
- MEGA anonymous download of A12 `.160` → `-16` (quota/account).
- On-device OTA-style downgrade with a **full** ROM (`.296`) → updater silently rejects
  (needs a **RAW** package; RAW on this platform = fastboot image set).

---

## 9. Key file/command inventory (this machine)

```
~/Development/zenfone8/
├── AsusUnlock.apk                 genuine ASUS-signed unlock app (4.68 MB)
├── AsusUnlock-patched.apk         apk-mitm re-signed (BLOCKED by signature check)
├── unlock_mitm_addon.py           mitmproxy script (EU swVer for A12 .61)
│                                  (renamed from unlock.py; ≠ work/unlock.py)
├── mitmproxy-ca.crt / .pem        CA pushed to phone (still installed on device)
├── mitm.log                       recorded unlock-app/server traffic
├── device_identity_snapshot.md    pre/post-flash identity snapshot
├── ZF8_DOWNGRADE_RUNBOOK.md       operator runbook
├── mega_dl.py                     minimal MEGA downloader (API 'g', anonym.; -16 here)
├── extract.log                    apk extraction log
├── RESEARCH_HANDOFF.md            this file (§14 records the LLM peer review)
├── scripts/                       extracted ASUS flash scripts (update_image*.sh, …)
├── logs/                          apktool decode/encode/sign logs
├── firmware/a13/                  A13 upgrade set: renamed OTA deltas
│                                  .312/.314/.326/.332 (UL-…-1.1.99-9999-user.zip)
├── raw/                           extracted A12 raw image set (~7.8 GB) — recovery/undo, KEEP
│   ├── fastboot_for_mac           working fastboot v30.0.5 (raw/adb + raw/fastboot are Linux-only)
│   ├── abl.elf                    the ABL §12 was reverse-engineered from
│   ├── flash_nosudo.sh / flash_sysfb.sh    ASUS flash-script variants
│   └── flash_run.log / flash_run2.log      successful flash logs (all CRC32 passed)
└── work/                          §12 reverse-engineering workspace
    ├── abl_linuxloader.efi        extracted ABL PE32+ ARM64 (target)
    ├── abl_payload.bin, cmdflash.bin, asus_bl_cert.der   extraction artefacts
    ├── asusauth.py                response computation + self-tests (logic FROZEN)
    ├── emu.py                     Unicorn emulation harness (ground-truth oracle)
    ├── disasm.py                  capstone VA-range disassembler
    ├── unlock.py                  end-to-end unlock tool (live-verified commands)
    ├── asuskey2_response.bin      64-byte response of the §12.9 live run
    └── DMClient.apk               pulled DM client (§7.1 lead)
```

Useful probes:
```bash
# server stub
curl -sS -X POST https://dm.asus.com/unlock/register \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'apkVersion=2.0&swVer=99.999.999.999&keyIndex=1'
# -> {"retCode":407,"message":"success"}

# device unlock-state
adb shell getprop ro.boot.flash.locked
adb shell getprop ro.boot.vbmeta.device_state
fastboot getvar project          # ZS590KS
fastboot getvar anti            # Variable Not found (ARB hidden)
```

---

## 10. References

- XDA "Unlocking the bootloader and rooting" (technique):
  https://xdaforums.com/t/unlocking-the-bootloader-and-rooting.4649239/
- XDA ZenFone 8 unofficial unlock (status table, closed):
  https://xdaforums.com/t/update-unoff-bl-unlock-24-01-20-asus-closed-this-method.4649465/
- XDA "Is there something new to unlock ZenFone 8?" (Nov 2025, confirmed dead):
  https://xdaforums.com/t/is-there-something-new-to-unlock-zenfone-8.4757278/
- ZenFone 8 firmware/OTA collection:
  https://xdaforums.com/t/zenfone-8-firmware-ota-collection.4620171/
- XDA "Asus says they will unlock my bootloader for money" (~€185, works):
  https://xdaforums.com/t/asus-says-they-will-unlock-my-bootloader-for-money.4685488/
- ZenTalk: server returns 10405:
  https://zentalk.asus.com/t5/zenfone-8/unlocking-zenfone-8-failed-to-unlock-10405/td-p/436909
- ZenTalk: ASUS confirms unlock program ended (Oct 2025):
  https://zentalk.asus.com/t5/zenfone-8/will-asus-ever-re-enable-zenfone-8-bootloader-unlocking-server/td-p/485393
- Wall of shame (ASUS section, ARB + history):
  https://github.com/zenfyrdev/bootloader-unlock-wall-of-shame/blob/main/brands/asus/README.md
- EDLUnlock (pre-2018 only): https://github.com/Giovix92/EDLUnlock

---

## 11. One-line conclusion

**The server is not the wall — the wall was imaginary.** The ABL contains a complete
local factory unlock protocol (§12), fully reverse-engineered, verified in emulation,
verified live, and **used to unlock this device on Nov 19 2026** (§12.9). The
app-based/server path (`com.asus.dm`, unlock app, secrettoken) is obsolete for anyone
with fastboot access to an ABL that still contains the `oem gen-random` family.

---

## 12. FACTORY UNLOCK PROTOCOL IN ABL (found Nov 19 2026 — server-independent)

**This supersedes the pessimism above for the bootloader we are actually running**
(A12 `31.1010.0410.61`; device ABL == `raw/abl.elf`, CRC-verified during the downgrade).

Target of analysis: `raw/abl.elf` → LZMA-decompressed FV → `work/abl_payload.bin` →
EFI APPLICATION "LinuxLoader" → `work/abl_linuxloader.efi` (PE32+ ARM64;
`.text` VA 0x1000–0x1de000 with **rawoff == vaddr**, so file reads by VA are direct;
`.data` 0x1de000–0x200000). **Facts** below are from disassembly (Ghidra via REA +
capstone) and Unicorn emulation of the real code.

### 12.1 The protocol, end to end

| Step | Command | ABL behavior (fact) |
|---|---|---|
| 1 | `fastboot oem gen-random` | CmdOemGenRNG @0x4de78. Clears flag DAT_001fe334, calls `random_num_generator` @0x46c70: **challenge = lowercase-hex MD5(sprintf("%x", uuid+timer))**, 32 chars → buffer 0x1fe3aa. Prints `Random Num = %a` (fmt @0x1c2d0c) between `====` rules to the fastboot response. At the end sets DAT_001fe334 = 1 ("challenge generated") via fragment @0x51c58, then FastbootOk. **Live-verified: completes in ~3 ms.** |
| 2 | *(local)* | Response = **transform(md5hex(challenge ‖ key))** — see 12.2/12.3. 64 ASCII lowercase hex chars. |
| 3 | `fastboot flash asuskey2 <64-byte file>` | CmdFlash @0x473e0 special-cases the partition name (UTF-16 compare vs `asuskey2` @0x1c416a) → 0x47e74 → 0x47eb0: zero 0x41 bytes at receiver buffer **0x1fe70d**, `CopyMem(0x1fe70d, download_buffer@0x1fe370, 0x40)`. Logs `receive asuskey2 data (%d)`. **RAM-only — no partition is written.** |
| 4 | `fastboot oem auth-hash` | CmdOemAuthHash @0x4df94 (key_select=1). Requires DAT_001fe334 ≠ 0 (else prints `fastboot oem gen-random, first` @0x1c2e90 and fails — **order matters**). Recomputes calc hash from the same challenge, prints `Calculate hash =` / `Receiver hash =`, `CompareMem(0x1fe6cc, 0x1fe70d, 0x40)`. **Match** → setter 0x2ddc0(1): is_authorized_1 = 1 (RAM byte 0x1f686a) **+ persists whole DevInfo** (0xb98 bytes @0x1f5de8 via 0x1d0d8), sets unlock-ability DAT_001fe338 = 1, re-reads getter 0x2dd90 — only if nonzero prints `Authorized Result : PASS`. **Mismatch** → is_authorized = 0, `Authorized Result : FAILED`. **Live-verified: PASS, and the flag PERSISTED across a bootloader reboot.** |
| 5 | `fastboot getvar rd_unlocked` | is_authorized_1 (live getter 0x2dd90 reads RAM byte 0x1f686a) — but the **getvar string is registered at fastboot init**, so it shows a **stale** `locked` until reboot. After reboot following step 4 success → `unlocked`. `flashing unlock` reads the LIVE getter, so it does not care about the stale string. |
| 6 | `fastboot flashing unlock` | CmdFlashingUnlock @0x49a60. If secure boot: requires **rd_unlocked OR rt_unlocked**, else `FAIL "permission denied"` (@0x1c1001). If DevInfo+0xd already 1 → `Device already : unlocked!`. Else 0x2d1d8(0,1): **writes DevInfo.is_unlocked (offset 0xd) = 1 and persists**; responds OKAY. (No volume-key prompt observed in this path.) |

Related commands decoded: a third handler @0x4e204 (same key/compare, sets is_authorized_2 →
`rt_unlocked` — live name untested, likely `oem auth-hash_2` or `auth-hash_3`), and
`oem get-imeiauth` @0x4e474 (key_select=2 "28825252"; challenge =
imei1(15)+imei2(15)+"00"; sets is_authorized_3 → `mask_unlocked`). Keys: "12345678"
@0x1e66ac, "28825252" @0x1e66b5, keylen 0x40 @0x1e66a4. **Caution:** the earlier static
name→handler mapping was off by one — the live names above (`gen-random` = 0x4de78,
`auth-hash` = 0x4df94) are confirmed on-device; treat untested names the same way until
probed.

**Gotcha that cost hours:** the string pool at 0x1c4xxx is **UTF-16LE** (GPT-style names);
single-byte reads there truncate to 1 char. Use `xxd` on the file directly.
**Another:** `0x43c54` = Fastboot**Ok** ("OKAY" @0x1bea08) and `0x43b88` = Fastboot**Fail**
("FAIL" @0x1c0601) — the opposite of what one assumes when skimming.

### 12.2 Response computation (cmd_oem_gen_hash @0x4690c — fact)

```
key       = "12345678"                       # key_select=1 (auth-hash, live-verified)
buf       = challenge(32 ASCII) ‖ key(8 ASCII)   # contiguous, strlen=40
md5hex    = md5(buf).hexdigest()              # 32 lowercase ASCII chars (verified real MD5)
response  = transform(md5hex)                # 64 lowercase ASCII chars
```

`transform` (FUN_00046608, key_select arg is **hardcoded 1**): operates on the 32 ASCII
chars in two 16-char blocks; per block two 8-char groups; chunks of 2 chars read as LE
u16 (D,C,B,A = chars[0:2],[2:4],[4:6],[6:8]); group 1 mixed with MIX1, group 2 with MIX2
(in place, called via arg-forwarder @0x51d14 — NOT an empty function, it forwards
x2=B, x3=A); chunks written back **reversed** [A,B,C,D]; finally `sprintf("%02x"×32)` of
all 32 bytes → 64 chars (uppercase from %02X, then lowercased by the caller).

```
MIX1(D,C,B,A):  S1=A+D, S2=B+C, S3=A+D+C, S4=A+B          (all u16, mod 0x10000)
                T1=ROL16(S1,2)+6, T2=ROL16(S3,9)+7
                R2=ROL16(S2,1),  R4=ROL16(S4,4)
                D'=T1^T2, C'=T2^R2, B'=R4^R2, A'=D'^R4
MIX2(D,C,B,A):  S1..S4 as above
                T1=ROL16(S1,6)+3, T2=bswap16(S2)+2, T3=ROL16(S4,3)+3, S3c=S3+9
                D'=T1^S3c, C'=S3c^T2, B'=T3^T2, A'=D'^T3
```
Rolations are emitted as `ubfx`+`bfi` pairs; all semantics confirmed by emulation, not
hand-reading. `compute_response()` in `work/asusauth.py` implements this.

### 12.3 Why this works on a LOCKED device (CmdFlash gate analysis — fact)

- Critical-partition list @0x1c4b98 (11 entries): `abl, aop, xbl_config, xbl, devcfg,
  keymaster, storsec, imagefv, multi_image, shrm, uefi_sec`. **`asuskey2` is not in it.**
- The secure-boot/`disable_checkfw`/image-verify gate @0x47518–0x47540 is reached *only*
  when the flashed partition matched the critical list; everything else falls through to
  the special-name chain. No other lock check exists in the path.
- Special names in the chain (UTF-16 @0x1c4xxx): `avb_custom_key` 0x1c406e,
  `partition` 0x1c408c, `mibib` 0x1c4148, `sha256` 0x1c4154, `sig` 0x1c4162,
  **`asuskey2` 0x1c416a**, `frp` 0x1c417c (→ `FRP_UNLOCK(SSN=%a)` path!), `CRC` 0x1c4184,
  `signature` 0x1c41b6, `userdata` 0x1c41c0.

### 12.4 Verification performed (fact)

Unicorn (QEMU core) emulates the actual ABL code — image mapped identity, the frame-chain
tracker @0x31480 stubbed by hook (returns synthetic global 0x50000800 → scratch
"virtual stack" 0x60000000), stack guard 0xc0c0c0c0 @0x1de0c0, debug prints disabled by
zeroing 0x7bd35 (bit1) and 0x7bd38 (mask).

- `run_md5()` == `hashlib.md5` (the hash is genuine MD5)
- standalone `asusauth.py` vs emulated ABL code: **MIX1/MIX2 300/300, transform 100/100,
  full challenge→response 50/50 for key_select 1 and 2 — ALL VERIFIED**

### 12.5 Tools (this machine)

```
~/Development/zenfone8/work/
├── abl_linuxloader.efi     extracted ABL LinuxLoader (PE32+ ARM64) — primary RE target
├── abl_payload.bin         LZMA-decompressed FV payload
├── cmdflash.bin            .text dump VA 0x47000-0x48400 (CmdFlash region)
├── asus_bl_cert.der        embedded ASUS unlock cert (CN=ZS590KS)
├── disasm.py               capstone VA-range disassembler for the EFI (adrp/bfm annotated)
├── emu.py                  Unicorn emulation harness (md5/mix/transform/gen_hash)
├── asusauth.py             STANDALONE response calculator + self-test vs emulator
├── unlock.py               end-to-end unlock script (see below)
└── DMClient.apk            pulled com.asus.dm (unanalyzed — queued lead, §12.8)
```

`work/unlock.py` flow: adb reboot bootloader → `oem gen-random` (parse `Random Num =`)
→ `compute_response()` → write 64-byte `asuskey2_response.bin` → `flash asuskey2`
(assert both OKAYs) → `oem auth-hash` → PASS → **if `--final-unlock`: `flashing unlock`
in the SAME boot session as the PASS** (the gate reads the live RAM byte — never reboot
between PASS and unlock) → `reboot bootloader` → `getvar rd_unlocked`/`unlocked`
(persistence verification only; getvar strings are registered at fastboot init, so the
persisted value shows only after that reboot). Steps up to PASS are **non-destructive**
(RAM + persisted auth flag only); `flashing unlock` is destructive (unlock may wipe
userdata at next boot). Command names are **live-verified** (§12.9). Paths/serial are
overridable via `--adb` / `--fastboot` / `--serial` (defaults are this machine's).

**Host tools note:** `raw/adb` and `raw/fastboot` are **Linux x86-64 binaries** and will
not run on macOS (`Exec format error`). Use `/opt/local/bin/adb` (macports) and
`raw/fastboot_for_mac` (v30.0.5 — tested working).

### 12.6 Remaining steps

**ALL DONE Nov 19 2026** — including the final unlock:

1. ~~Live protocol run~~ done — §12.9, `rd_unlocked: unlocked`, persisted.
2. ~~`fastboot flashing unlock`~~ **executed and successful — BOOTLOADER UNLOCKED**.
3. ~~post-unlock boot~~ Android booted normally; verified properties:
   `ro.boot.flash.locked=0`, `ro.boot.verifiedbootstate=orange`,
   `ro.boot.asus.authorized=1` (previously `1`/`green`/`0`).

### 12.7 Address quick-reference (all facts from disasm/emulation)

```
Commands / dispatch
  0x44fb8  fastboot command dispatcher
  0x473e0  CmdFlash          (asuskey2 UTF-16 compare @0x4790c; receiver store @0x47eb0)
  0x49a60  flashing unlock
  0x4690c  cmd_oem_gen_hash  (challenge→response computation)
  0x4de78  oem gen-random    (CmdOemGenRNG; RNG @0x46c70)  ← live-verified name (§12.9)
  0x4df94  oem auth-hash     (key_select=1)               ← live-verified name (§12.9)
  0x4e204  third compare handler (key_select=1, sets is_authorized_2 → rt_unlocked);
           live command name UNTESTED (static "auth-hash_2/_3" guesses were off by one)
  0x4e474  oem get-imeiauth  (key_select=2, challenge=imei1+imei2+"00")
  0x4dc70  oem rsa_test_     (undecoded)
  0x46608  transform         (key_select hardcoded 1)
  0x46528  MIX1
  0x46598  MIX2
  0x51d14  arg-forwarder called by transform (forwards x2=B, x3=A — NOT empty)

Flags / buffers (RAM)
  0x1fe3aa  challenge buffer (32 ASCII hex)
  0x1fe6cc  calc hash buffer
  0x1fe70d  receiver buffer (64 ASCII; CompareMem vs calc, len 0x40)
  0x1fe334  "challenge generated" flag (set by gen-random, required by auth-hash)
  0x1fe338  unlock-ability flag
  0x1fe370  download_buffer base

DevInfo / persistence
  0x2ddc0/0x2de38/0x2deb0  is_authorized setters (1/2/3)
  0x2dd90/0x2dda0/0x2ddb0  getters = rd_unlocked / rt_unlocked / mask_unlocked
  0x2d1d8  DevInfo writer (is_unlocked = DevInfo+0xd)
  0x1f686a is_authorized_1 in DevInfo image (0xb98 bytes @0x1f5de8, via FUN_0001d0d8)

Keys / strings
  0x1e66a4 keylen 0x40; 0x1e66ac "12345678" (key_select 1); 0x1e66b5 "28825252" (2)
  0x1c2d0c "Random Num = %a"; 0x1c2e90 "fastboot oem gen-random, first"
  0x1c4b98 critical-partition list (11 names, UTF-16LE)
  0x43c54 FastbootOk ("OKAY" @0x1bea08); 0x43b88 FastbootFail ("FAIL" @0x1c0601)
```

### 12.8 Queued leads (not yet worked — for the next session)

In rough priority order, after the live protocol run:

1. **DMClient.apk** (`work/DMClient.apk`, com.asus.dm v3.1.0.74_230905) — still
   unanalyzed. Decoding its `secrettoken` derivation would tell us what the server
   used to return; **[inference]** only useful as a cross-check or for the `/ADF`
   asuskey.bin format, since the protocol in §12 makes the server unnecessary.
2. **Firehose programmers** (`raw/firmware/`) — a Sahara/Firehose emergency-download
   (EDL) primitive on SM8350 would be an independent route to flash `asuskey2`-class
   data directly to DevInfo. **[inference]** probably blocked without a paid loader.
3. **`oem rsa_test_`** @0x4dc70 — exists in the dispatcher (fact); purpose undecoded.
4. **FRP special-flash path** — flashing partition name `frp` (UTF-16 @0x1c417c) is
   special-cased in CmdFlash to a `FRP_UNLOCK(SSN=%a)` path (fact). Worth decoding:
   it may accept an SSN-based unlock string, another server-free channel.
5. **Other `oem` sub-modes**: `asus-unlock`, `rt_lock`, `mk_lock` appear in the
   dispatcher (fact); semantics undecoded. The third compare handler @0x4e204
   (→ `rt_unlocked`) is a ready-made second authorization if `oem auth-hash`
   misbehaves — same key, same algorithm, different DevInfo flag, and
   `flashing unlock` accepts either.

### 12.9 LIVE VERIFICATION — Nov 19 2026 (all facts, from the device)

**Result: the factory protocol works on the live locked device, end to end,
including persistence.** Run log (host: `raw/fastboot_for_mac` v30.0.5):

```
$ fastboot oem gen-random
(bootloader) ==================================
(bootloader) Random Num = 98a80c74ed2995862a78a6bf86d54eb7
(bootloader) ==================================
OKAY [  0.003s]                      ← handler completes in ~3 ms

response = compute_response(challenge, key_select=1)
         = 4e09ac59fddf2760bba9961cf007e47f2d6ea6ade4495b17872ce8eab35f0900

$ fastboot flash asuskey2 work/asuskey2_response.bin
Sending 'asuskey2' (0 KB)  OKAY [0.012s]
Writing 'asuskey2'        OKAY [0.001s]

$ fastboot oem auth-hash
(bootloader) Calculate hash = 40a5fd26...   ← see note below
(bootloader) Receiver hash = 40a5fd26...
(bootloader) Authorized Result : PASS
OKAY [  0.010s]

$ fastboot getvar rd_unlocked      → locked   (stale init-registered string)
$ fastboot flashing get_unlock_ability → 1    (live RAM ability flag, set by PASS branch)
$ fastboot reboot bootloader
$ fastboot getvar rd_unlocked      → unlocked ← AUTH PERSISTED TO DEVINFO PARTITION
$ fastboot getvar rt_unlocked      → locked
$ fastboot getvar unlocked         → no      (final unlock not yet executed)
```

Key live findings:

- **Command names**: step 1 is `oem gen-random`, step 4 is `oem auth-hash`
  (the old §12.1 names were off by one — the error message
  `fastboot oem gen-random, first` from `oem auth-hash` on a cleared flag is what
  revealed the true mapping).
- **PASS branch internals** (disasm, confirmed by behavior): setter 0x2ddc0(1)
  writes RAM byte 0x1f686a then persists the full DevInfo (0x1d0d8); PASS is only
  printed if a re-read via getter 0x2dd90 returns nonzero. Getter 0x2dd90 reads
  the live RAM byte — that is what `flashing unlock` checks, so the stale
  `rd_unlocked: locked` getvar string is irrelevant to the unlock gate.
- **Persistence confirmed**: after `fastboot reboot bootloader`, the re-read
  DevInfo yields `rd_unlocked: unlocked`. The authorization is now durable
  device state; the final `flashing unlock` will pass its gate after any reboot.
- **Print oddity (open, cosmetic)**: the `Calculate/Receiver hash =` lines print
  `40a5fd26ba91f0e726aae45182eeb500` (with sliding-window repeats at offsets
  0/8/16). This matches none of: our 64-char response, the pre-transform md5
  (`a0151ce3...`), or md5(response). The compare itself is genuine (PASS +
  persisted flag + live getter) — the printed value is some intermediate whose
  rendering is not worth chasing.
- **USB-wedge lesson (iatrogenic)**: `Command exceeded timeout of X ms` messages
  earlier in the session were **host-side shell timeouts killing fastboot**, not
  fastboot or ABL giving up. Killing the client while the device is mid-response
  tears down the USB pipe and wedges ABL's fastboot task permanently (enumeration
  still works; no command responds). Recovery: bootloader-menu → *restart
  bootloader*. All protocol commands actually complete in **milliseconds** —
  always give fastboot generous host-side timeouts and never kill it mid-wait.
- `fastboot devices` with no device present **blocks** (`< waiting for any device >`)
  — don't use it in tight poll loops; a single `getvar` with a long timeout waits
  for the device itself and then queries.

### 12.10 FINAL RESULT — BOOTLOADER UNLOCKED (Nov 19 2026)

After the persistence check confirmed the gate was durably open, the user approved
the destructive final step. `fastboot flashing unlock` was executed
(OKAY; `getvar unlocked` → `yes`), and the device then booted Android normally.
Post-unlock properties (adb, read-only):

```
ro.boot.flash.locked       = 0      (was 1)
ro.boot.verifiedbootstate  = orange (was green — AVB correctly reports unlocked)
ro.boot.asus.authorized    = 1      (was 0 — the persisted is_authorized_1 flag
                                     propagated into the kernel boot args)
```

**Summary of the complete unlock procedure that worked on this device** (A12
`31.1010.0410.61`, serial <SERIAL>, from a locked + verified state):

```
1. fastboot oem gen-random                  # prints "Random Num = <32 hex>"
2. python3 -c "...compute_response(...)"    # work/asusauth.py, key_select=1 → 64 chars
3. fastboot flash asuskey2 <response-file>  # 64-byte ASCII file, RAM-only stash
4. fastboot oem auth-hash                   # → "Authorized Result : PASS"
5. fastboot flashing unlock                 # → OKAY (gate: rd_unlocked getter = 1)
6. fastboot reboot                         # device boots Android, unlocked
```

Steps 1–4 are non-destructive and repeatable (each gen-random generates a fresh
challenge). Step 5 is the only destructive step (ASUS unlock behavior: possible
userdata wipe/decryption loss on next boot — did not occur here; the device
booted the existing OS). `work/unlock.py` automates the whole sequence
(`--final-unlock` gates step 5).

---

## 13. Phase 3 — LineageOS install (A13 firmware upgrade first)

Goal: LineageOS 24.0 on `sake` (ASUS ZenFone 8). Wiki
<https://wiki.lineageos.org/devices/sake/install/> requires **stock Android 13
firmware (latest = 33.0210.0210.332)**, booting stock A13 once and verifying
SMS/calls/VoLTE (IMS provisioning), and removing all Google accounts before install.

### 13.1 Facts (Nov 19 2026)

- Device was on A12 `31.1010.0410.61`, **unlocked** (§12.10), SKU fingerprint
  `asus/EU_I006D/...` (EU is served by the shared WW/EU package stream — no
  separate EU firmware exists; official packages are labeled "for WW/EU/RU/JP").
- **System Update works on the unlocked bootloader**: the FOTA server offered
  `.61 → 31.1010.0411.89` and the user ran it (evidence the updater ignores
  ORANGE verified-boot state). `ota_disable_automatic_update` global setting
  reads `null` — the earlier freeze did not persist.
- Firmware availability (XDA collection thread 4620171 + ASUS official):
  latest A13 = **.332**, available only as DUMP/MEGA or OTA deltas — **no FULL
  zip**. FULL exists only for **.296** (official ASUS page, 3.17 GB,
  `UL-ASUS_I006D-ASUS-33.0210.0210.296-1.1.26-2305-user.zip`, downloaded to
  `~/Downloads`). Verified a true full A/B package (payload.bin 3.4 GB,
  `ota-type=AB`, **no pre-build precondition**, post-build
  `WW_I006D 33.0210.0210.296` SDK 33).
- All four A13 deltas verified live on ASUS CDN (fota2.asus.com, HTTP 200) and
  downloaded to `firmware/a13/`, renamed per the local-update convention:
  `.296→.312` (231 MB), `.312→.314` (73 MB), `.314→.326` (158 MB),
  `.326→.332` (74 MB), each `UL-ASUS_I006D-ASUS-<target>-1.1.99-9999-user.zip`.

### 13.2 Plan / state (executed — see §13.3 for outcome)

1. `adb push` FULL .296 to `/sdcard/` → reboot → tap "System update file detected"
   notification → installs stock A13 .296 (from any A12 base; the `.89` interlude
   irrelevant). Full ROMs keep their **original filename** at the storage root —
   only OTA deltas are renamed to `…-1.1.99-9999-user.zip` (XDA HOWTO).
2. Local-update the four deltas in order (.312 → .314 → .326 → .332),
   one reboot + tap each. Expected end state: A13 `33.0210.0210.332`
   (the version the device originally shipped on).
3. Verify unlock survives — reasoning: the A13 OTA/full image sets contain **no
   `devinfo` image**, and unlock state lives in DevInfo, so updates cannot touch
   it (inference — §6's no-ARB observation predates the unlock and is not evidence
   here). Empirical check: `fastboot getvar unlocked` → `yes` after the A13
   upgrade and **before** LineageOS `Format data`.
4. Boot stock A13, test SMS/calls/VoLTE, **remove all Google accounts**.
5. LineageOS: download `vendor_boot.img`, `boot.img`, ROM zip (+ optional
   GApps arm64) from <https://download.lineageos.org/devices/sake>;
   `fastboot flash vendor_boot`, reboot bootloader, `fastboot flash boot`,
   boot to recovery, **Format data** (mandatory), sideload ROM, sideload GApps
   **before first boot**.

Open risks/assumptions: (a) WW-package-on-EU-device acceptance — expected fine
(shared stream), failure mode is a harmless refused notification; (b) unlocked-BL
local update — the successful FOTA `.61→.89` offer/install shows update paths
ignore the unlock; (c) **ARB forward direction is an assumption** — the only ARB
datapoint is the A13→A12 *downgrade* booting; walking `.296→.332` forward should
be safe but was not previously proven in that direction.

### 13.3 Outcome & cautions (Nov 19 2026)

**User reports LineageOS 24.0 installed and running.** The firmware walk
(.296 full → delta chain) and the stock-A13 SMS/calls/VoLTE test were performed
by the user off-host and are **not host-verified**. That LineageOS boots at all
is itself evidence the unlock survived the A13 upgrade — a re-locked bootloader
would reject the LineageOS boot images (see caution 1).

To verify when USB debugging is re-enabled on LineageOS:
- `ro.bootloader` / baseband should read A13 `33.x` (`.332` if the full chain ran);
- test calls/SMS/VoLTE on LineageOS (IMS provisioning was to be carried from stock);
- `fastboot getvar unlocked` → `yes` (optional, bootloader mode).

Cautions going forward:
1. **Do NOT relock the bootloader while LineageOS is installed.** A locked
   bootloader enforces ASUS-signed boot images; LineageOS images are not
   ASUS-signed, so the device would fail to boot — and the only rescue would be
   EDL with a signed firehose (§7.4 — not public). Relock only after a
   deliberate full stock re-flash.
2. `Format data` in recovery was mandatory before the first LOS boot.
3. Archive `firmware/a13/` and the `.296` full zip — ASUS has pulled most
   packages from official channels, and the fota2 delta URLs were verified live
   only as of Nov 19 2026.

---

## 14. Peer review (Nov 19 2026)

An independent second LLM (DeepSeek V4.1 Flash) reviewed §1–§13 and `work/*`.
Findings accepted in full and applied:

- `work/unlock.py`: 2.1 persistence-check substring bug (`"unlocked" in "rd_unlocked:…"`
  always true) → regex `rd_unlocked:\s*(\w+)` compare; 2.2 poll loop violated the
  §12.9 never-kill rule → single blocking `getvar project`; 2.3 `flashing unlock` now
  runs in the SAME session as the auth PASS (reboot is verification only); 2.4 OKAY and
  `unlocked: yes` assertions added; 2.5 wrong error string fixed; 2.6 paths/serial
  overridable via CLI.
- Document: §1/§2/§11 reconciled with the unlock result; §4.2 conclusion scoped to the
  app/server path; §7 marked superseded (EDL kept as rescue knowledge); §8
  `flashing unlock` entry corrected; §9 inventory regenerated from disk; §12.5 flow
  description updated; §12.7 address table corrected to the live-verified names;
  §13.2 step 3 reasoning fixed (no-devinfo-image, not "downgrade preserved unlock");
  §13.3 cautions added (relock, format data, firmware archival); credential-exposure
  caution added to the header.
- Top-level mitmproxy script renamed `unlock.py` → `unlock_mitm_addon.py` to
  disambiguate from `work/unlock.py`.
- `asusauth.py` / `emu.py` logic unchanged; regression gate re-run after the changes:
  `ALL VERIFIED`, emulated MD5 matches, 64-byte response file intact.
