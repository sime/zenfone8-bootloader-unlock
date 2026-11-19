#!/usr/bin/env python3
"""
ASUS ZenFone 8 (I006D) bootloader unlock via the factory challenge-response
protocol in ABL (Android 12, abl matches raw/abl.elf).

Protocol (reverse-engineered + LIVE-VERIFIED, see RESEARCH_HANDOFF.md §12/§12.9):
  1. fastboot oem gen-random   -> prints "Random Num = <32 hex>"  (challenge)
  2. response = transform(md5(challenge + "12345678").hexdigest()) (64 chars)
  3. fastboot flash asuskey2 <64-byte response>                   (RAM stash)
  4. fastboot oem auth-hash   -> compares; PASS sets+persists is_authorized_1
  5. fastboot flashing unlock -> DevInfo.is_unlocked=1 (DESTRUCTIVE: may wipe
     userdata). MUST run in the SAME boot session as the PASS above: the
     unlock gate reads the live RAM byte set by step 4, so never reboot
     between 4 and 5 (if the devinfo persist failed, the gate is open only
     until reboot).
  6. fastboot reboot bootloader + getvar rd_unlocked/unlocked -> persistence
     verification only.

Steps 1-4 (+6 as verification) are non-destructive (RAM + devinfo auth flag
only). Step 5 is only run with --final-unlock.

USB discipline (§12.9): never kill a waiting fastboot client — a host-side
timeout that kills fastboot mid-response wedges ABL's fastboot task until a
manual "restart bootloader". All protocol commands complete in milliseconds
on a healthy link; this script uses single blocking calls with generous
timeouts instead of tight poll loops. (A timeout expiry while NO device is
present is safe: fastboot is then only polling, with no pending transfer
to the target.)

Scope: verified against the A12 (31.1010.0410.61) ABL only. Whether the A13
ABL still contains the oem gen-random family is untested (§13 of the handoff).

adb/fastboot default to whatever is on your PATH (override with
--adb / --fastboot). --serial selects which adb device to reboot into the
bootloader (default: the single connected device).
"""
import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ADB = "adb"            # whatever is on PATH; override with --adb
FASTBOOT = "fastboot"  # whatever is on PATH; override with --fastboot
SERIAL = None          # adb device serial; override with --serial (default:
                       # reboots the single connected adb device)

sys.path.insert(0, HERE)
from asusauth import compute_response  # noqa: E402


def run(cmd, timeout=30, check=False):
    print(f"  $ {' '.join(os.path.basename(c) if i == 0 else c for i, c in enumerate(cmd))}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("    TIMEOUT")
        return None
    out = (p.stdout or "") + (p.stderr or "")
    if out.strip():
        for line in out.strip().splitlines():
            print(f"    | {line}")
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {cmd}")
    return out


def wait_for_fastboot(timeout=180):
    # ONE blocking call — fastboot itself waits for the device
    # ('< waiting for any device >'). No poll loop, no killed clients.
    out = run([FASTBOOT, "getvar", "project"], timeout=timeout)
    return bool(out and "ZS590KS" in out)


def fastboot(*args, timeout=30, check=False):
    return run([FASTBOOT] + list(args), timeout=timeout, check=check)


def getvar(name, timeout=120):
    """Read one fastboot variable; parse 'name: value' (NOT substring match —
    'unlocked' is a substring of 'rd_unlocked', which masked the old check)."""
    out = fastboot("getvar", name, timeout=timeout)
    m = re.search(rf"{re.escape(name)}:\s*(\w+)", out or "")
    return m.group(1) if m else "unknown"


def main():
    global ADB, FASTBOOT, SERIAL
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-reboot", action="store_true",
                    help="device is already in fastboot/bootloader mode")
    ap.add_argument("--dry-run", action="store_true",
                    help="compute the response but do not flash/verify")
    ap.add_argument("--final-unlock", action="store_true",
                    help="run 'fastboot flashing unlock' after successful auth "
                         "(DESTRUCTIVE: unlocking may wipe userdata)")
    ap.add_argument("--adb", default=ADB, help=f"adb binary (default: {ADB})")
    ap.add_argument("--fastboot", default=FASTBOOT,
                    help=f"fastboot binary (default: {FASTBOOT})")
    ap.add_argument("--serial", default=SERIAL,
                    help="adb device serial to reboot (default: the single "
                         "connected device)")
    args = ap.parse_args()
    ADB, FASTBOOT, SERIAL = args.adb, args.fastboot, args.serial

    # 0. device state
    serial = args.serial
    if not args.skip_reboot:
        out = run([ADB, "devices"], timeout=10)
        devs = [l.split()[0] for l in (out or "").splitlines()
                if l.endswith("\tdevice")]
        if not devs:
            raise SystemExit("no adb device visible (USB debugging on?); use "
                             "--skip-reboot if it is already in bootloader mode")
        if serial and serial not in devs:
            raise SystemExit(f"serial {serial!r} not among adb devices: {devs}")
        print("\n[*] rebooting to bootloader...")
        run([ADB] + (["-s", serial] if serial else []) +
            ["reboot", "bootloader"], timeout=30)
    if not wait_for_fastboot():
        raise SystemExit("device did not enter fastboot mode")

    # 1. generate challenge
    print("\n[*] step 1: fastboot oem gen-random")
    out = fastboot("oem", "gen-random", timeout=180)
    if out is None:
        raise SystemExit("no response from oem gen-random")
    m = re.search(r"Random\s*Num\s*=\s*([0-9a-fA-F]{32})", out)
    if not m:
        raise SystemExit(f"could not parse challenge from:\n{out}")
    challenge = m.group(1).lower()
    print(f"\n[*] challenge: {challenge}")

    # 2. compute response
    response = compute_response(challenge, key_select=1)
    print(f"[*] response: {response}")
    resp_file = os.path.join(HERE, "asuskey2_response.bin")
    with open(resp_file, "w") as f:
        f.write(response)
    assert len(response) == 64
    print(f"[*] wrote {resp_file} (64 bytes)")
    if args.dry_run:
        print("[*] dry run: stopping here")
        return

    # 3. deliver response via flash asuskey2 (expect BOTH OKAYs: download+write)
    print("\n[*] step 2: fastboot flash asuskey2")
    out = fastboot("flash", "asuskey2", resp_file, timeout=120)
    if out is None or out.count("OKAY") < 2:
        raise SystemExit(f"flash asuskey2 did not complete both stages:\n{out}")

    # 4. compare + authorize
    print("\n[*] step 3: fastboot oem auth-hash")
    out = fastboot("oem", "auth-hash", timeout=180)
    if out is None:
        raise SystemExit("no response from oem auth-hash")
    if "Authorized Result : PASS" not in out:
        print("[!] auth-hash did not report PASS — response mismatch?")
        print(out)
        raise SystemExit(1)

    # 5. final unlock (optional) — SAME boot session as the PASS above
    if args.final_unlock:
        print("\n[*] step 4: fastboot flashing unlock  (DESTRUCTIVE)")
        out = fastboot("flashing", "unlock", timeout=300)
        if out is None or "OKAY" not in out:
            raise SystemExit(f"flashing unlock did not report OKAY:\n{out}")
        state = getvar("unlocked")
        print(f"\n=== unlocked: {state} ===")
        if state != "yes":
            raise SystemExit("flashing unlock reported OKAY but getvar "
                             f"unlocked == {state!r} (expected 'yes')")
    else:
        print("\n[*] authorization stage complete (gate open in THIS boot "
              "session). Re-run with --final-unlock to actually unlock "
              "(may wipe userdata).")

    # 6. persistence verification (reboot reloads DevInfo from the partition)
    print("\n[*] verification: reboot bootloader, getvar rd_unlocked")
    fastboot("reboot", "bootloader", timeout=120)
    time.sleep(10)
    rd_state = getvar("rd_unlocked", timeout=180)
    print(f"=== rd_unlocked (persisted): {rd_state} ===")
    if rd_state != "unlocked":
        print("[!] auth flag did NOT persist to devinfo — any unlock attempt "
              "after a reboot needs steps 1-4 re-run first")
    if args.final_unlock:
        state = getvar("unlocked")
        print(f"=== unlocked (after reboot): {state} ===")
        if state != "yes":
            print("[!] WARNING: getvar unlocked != yes after reboot")


if __name__ == "__main__":
    main()
