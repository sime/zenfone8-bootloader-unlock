# ZenFone 8 (I006D/EU) — Downgrade to Android 12 + unlock attempt

**Reality check:** ASUS's unlock backend (`dm.asus.com/unlock/register`) now returns a
static `{"retCode":407,"message":"success"}` for every path — it no longer issues unlock
keys. This downgrade **will not unlock the bootloader**. It is kept only for older-firmware
use. ASUS confirmed (Oct 2025) the unlock program is not returning.

## Artifacts (already downloaded)
- Zip: `A12_raw_31.1010.0410.61.zip` (4.01 GB, `WW-ZS590KS-31.1010.0410.61-MR0-2204-user-20220422`)
- Extracted: `raw/` (78 files, ~7.79 GB)

## ⚠️ Risks
- **Anti-rollback:** device is on `33.0210.0210.332`. The raw image is from 2022. If the
  ARB fuse was raised by `.326+`, flashing the old `abl` can make the phone unbootable.
  There is **no EDL recovery** (SM8350, not a pre-2018 MSM exploitable target).
- **Full wipe** (data + possibly IMEI — back it up).
- The script flashes the **bootloader and GPT**, not just the system.

## Pre-flight
```bash
cd /Users/smales/Development/zenfone8/raw
file fastboot_for_mac            # if x86_64 → need Rosetta 2 or use the system fastboot
chmod +x fastboot_for_mac update_image_for_mac.sh
adb devices                      # confirm the phone is visible first
```

## Flash procedure
1. Back up anything you care about. Charge to 100%. Use a **data** USB cable in a **direct**
   port (no hub) — a reseat has been needed after every reboot on this machine.
2. `adb reboot bootloader` (or: power off, then hold **Vol+ and Power**).
3. Confirm fastboot sees it: `fastboot devices`.
4. Run the ASUS flasher (prompts for your macOS password via `sudo`):
   ```bash
   cd /Users/smales/Development/zenfone8/raw
   sh update_image_for_mac.sh
   ```
5. **Watch the very first lines.** It flashes `abl_a`/`abl_b` first. If you see
   `FAILED (remote: ...)` / `Flashing is not allowed in Lock State` / any anti-rollback
   message, power off and STOP — that's the expected locked/ARB answer.
6. If it runs through, it ends with `oem factory-reset` and reboots into Android 12 `.61`.

## If the flash refuses (locked bootloader)
ASUS's raw flash may require an unlocked bootloader on this firmware. If so, there is no
path — it confirms the dead end. Do **not** keep retrying.

## After a successful downgrade (optional)
- Reach a known-unlockable build: OTA to `33.0210.0210.296`, or stay on A12 `.160`.
- Attempt the (expected-to-fail) unlock:
  ```bash
  cd /Users/smales/Development/zenfone8
  ~/Library/Python/3.14/bin/mitmproxy -s unlock_mitm_addon.py -p 8080
  ```
  Then set the phone's Wi-Fi proxy to `<mac-ip>:8080`, install `AsusUnlock_1.0.0.7_210127_fulldpi.apk`,
  and run it. Expect `retCode 407` / "unlock failed".

## The only working path today
ASUS EU "executive care" paid unlock (~€185). Contact `executivecare@asus.com`; cite the
advertised feature + EU warranty (ASUS already lost a UK case on this).
