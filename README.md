# ZenFone 8 (I006D / ZS590KS) — Local Bootloader Unlock

Unlock the ASUS ZenFone 8 bootloader **entirely on your own machine, with no
ASUS server involved**, using a factory challenge–response protocol found
inside the phone's own bootloader (ABL).

Background: every documented "software" ZenFone 8 unlock method was the official
Unlock app talking to an ASUS server. That server now refuses every request
(`retCode 405 "NOT ALLOWED"`), and the app tricks around it (MITM, patched APK,
downgrade games) are dead — evidence in [`RESEARCH_HANDOFF.md`](RESEARCH_HANDOFF.md)
§4–§5. This repo is the result of reverse-engineering the A12 bootloader image
itself, which turned out to contain a complete **local** factory authorization
protocol:

```
fastboot oem gen-random   →  the bootloader gives you a 32-hex challenge
compute the response      →  64 ASCII chars, derived from the challenge
fastboot flash asuskey2 <response>
fastboot oem auth-hash    →  "Authorized Result : PASS"
fastboot flashing unlock  →  unlocked (may wipe user data)
```

This was reverse-engineered statically, verified in emulation, and then run
live: **it unlocked a real, previously-unlockable ZenFone 8 on 2026-11-19**
(then upgraded to A13 firmware and LineageOS — §13 of the handoff).

---

## ⚠️ Read this first

Be clear-eyed about what you are getting into:

- **You can brick your phone.** A full firmware downgrade plus a bootloader
  authorization sequence on your only device. If you brick it, there is
  **no publicly available rescue**: this SoC's EDL mode needs a signed
  "firehose" loader that has never been released publicly, and a
  hard-bricked ZenFone 8 may be unrecoverable outside (possibly declined)
  paid ASUS service. Assume that if this goes wrong for you, that's it.
- **This has been tested on exactly one phone.** One ZenFone 8 (I006D), one
  firmware combination, one Mac, one USB cable. Everything in this repo is
  an n=1 result. The protocol is *believed* general, but belief is not data.
- **Verified against the Android 12 ABL only** (`31.1010.0410.61`). Whether
  later (A13) bootloaders still contain the protocol — and whether they use
  the same keys — is **untested**. If `oem gen-random` doesn't answer on
  your firmware, you must downgrade to the tested A12 build first.
- **Unlocking may wipe user data.** Everything on internal storage may be
  lost. Back up first.
- **Never re-lock the bootloader while running anything not signed by ASUS**
  (e.g. LineageOS). A locked bootloader rejects non-ASUS boot images and the
  device will not boot — and see "no public rescue" above.
- **Never interrupt a fastboot command mid-response.** Unplugging the cable
  or killing the client while the bootloader is answering can wedge its
  fastboot task until a manual "restart bootloader". The tool here uses
  single blocking commands with generous timeouts — let it run.
- The unlock is **your responsibility**. MIT license, no warranty whatsoever.

Before anything: confirm your phone is actually this model —
`fastboot getvar project` must answer `ZS590KS`. Not a ZenFone 8 Flip, not any
other ASUS device. Don't try.

---

## Part 1 — I just want to unlock my phone

You don't need to read a single line of analysis. You need: a Mac/Linux
machine, Python 3 (no third-party packages), `adb` + `fastboot` on PATH, a
good USB cable, and patience.

### 1. Get onto the tested firmware (only if you need to)

The tested configuration is **Android 12, firmware `31.1010.0410.61`** — this
is the ABL the protocol was reverse-engineered from, keys verified against.

Quick check on your current firmware, in bootloader mode:

```
fastboot oem gen-random
```

- If it prints `Random Num = <32 hex>` — the protocol is present in *your*
  bootloader. (Note: on anything newer than A12 `.61` this is untested by the
  author — keys could differ. If `auth-hash` doesn't PASS, nothing is changed
  and you can fall back to the downgrade.)
- If it prints `UNKNOWN COMMAND` — downgrade to A12 `.61` first. The full
  locked-bootloader downgrade procedure that **worked** (ASUS's own signed
  RAW image set flashed over fastboot, despite a locked bootloader) is
  written up step-by-step in [`ZF8_DOWNGRADE_RUNBOOK.md`](ZF8_DOWNGRADE_RUNBOOK.md)
  (theory in the handoff §6). **The full-RAW flash is the single most
  dangerous step in this whole project — read the warnings above.**

### 2. Authorize (non-destructive)

With the phone in bootloader mode (boot with Volume-Up held, or let the
script reboot it via adb):

```
python3 work/unlock.py                 # reboots the device via adb first
python3 work/unlock.py --skip-reboot   # if it's already in bootloader mode
```

Expected output, in order:

- `Authorized Result : PASS` — your response matched the bootloader's own
  computation (RAM-only, plus one persisted authorization flag)
- `=== rd_unlocked (persisted): unlocked ===` — authorization survived a
  reboot into the bootloader

Nothing is unlocked yet; your data is intact; you can stop here and the
phone remains exactly as it was (the extra authorization flag is inert).

### 3. Unlock (destructive)

When you're ready — backups done, truly ready:

```
python3 work/unlock.py --final-unlock
```

(Typo-guarded: the flag is `--final-unlock`.) It re-runs the whole block
with a fresh challenge, and *in the same boot session as the PASS* runs:

```
fastboot flashing unlock
```

Expected: `OKAY`, then `unlocked: yes` (and `rd_unlocked: unlocked` after
the verification reboot). The tool enforces the same-session rule itself —
do not reboot the phone yourself between the PASS and this step.

### 4. Afterward

- `fastboot flashing unlock` converts the device state; a data wipe may
  happen on next boot.
- If you then head to LineageOS (worked here): don't re-lock the bootloader
  while it's on the device; the A13 firmware walk that preserved the unlock
  is in the handoff §13.
- **Don't re-lock.** (Yes, it's on this list twice. That's deliberate.)

### If something doesn't match the expected output

Stop. `FAIL` from `auth-hash`, missing `PASS`, missing `OKAY`s — none of these
change the device; just power off and walk away. Wedged fastboot → hold the
power button and try again. Anything stranger than that, read
[`RESEARCH_HANDOFF.md`](RESEARCH_HANDOFF.md) §12.9 (operational gotchas) before
retrying.

---

## Part 2 — Verify the approach and implementation (with an LLM, or yourself)

The full evidence chain lives in
[`RESEARCH_HANDOFF.md`](RESEARCH_HANDOFF.md) — facts vs
inferences are marked throughout — and every claim below is checkable.

### Part 2a — Machine-checkable gates (no LLM needed, run these first)

```
# tools compile
python3 -m py_compile work/unlock.py work/asusauth.py work/emu.py

# the response calculator cross-checks itself against an EMULATION OF THE
# ACTUAL ABL CODE (unicorn): MIX1/MIX2 300/300, transform 100/100,
# challenge→response 50/50 per key — expect the final line: ALL VERIFIED
python3 -B work/asusauth.py

# the emulation oracle standalone (same self-checks from the emulated side)
python3 -B work/emu.py
```

`asusauth.py` needs only stdlib to *use*; the self-tests above require
`pip install unicorn capstone` because they load and run the real ABL code.

### Part 2b — The known-answer vector

From the live, on-device run of the unlock (handoff §12.9), 2026-11-19:

| Item | Value |
|---|---|
| `fastboot oem gen-random` printed | `(bootloader) Random Num = 98a80c74ed2995862a78a6bf86d54eb7` |
| challenge | `98a80c74ed2995862a78a6bf86d54eb7` |
| key_select | `1` (`oem auth-hash` / key `"12345678"`) |
| **expected response** | `4e09ac59fddf2760bba9961cf007e47f2d6ea6ade4495b17872ce8eab35f0900` |

That response is also saved verbatim (64 ASCII bytes) as
`work/asuskey2_response.bin` — the exact bytes the bootloader answered
`Authorized Result : PASS` to on the real device.

One-liner check:

```
python3 -c "import sys; sys.path.insert(0,'work'); from asusauth import compute_response; \
print(compute_response('98a80c74ed2995862a78a6bf86d54eb7', key_select=1) == \
open('work/asuskey2_response.bin').read())"
# must print True
```

### Part 2c — LLM-assisted independent audit

Hand the following to your model (all in this repo):

1. [`RESEARCH_HANDOFF.md`](RESEARCH_HANDOFF.md) — the primary source (protocol
   in §12, live session in §12.9/§12.10, addendum §13, peer review §14)
2. `work/asusauth.py` — the standalone response calculation
3. `work/emu.py` — the unicorn emulation harness, i.e. the ground-truth oracle
4. `work/unlock.py` — the end-to-end tool
5. `work/abl_linuxloader.efi` — the actual bootloader binary

A note on prior review: **this work was already independently reviewed by a
second LLM** before publication (Nov 2026). That review found real bugs —
including a persistence check that could never fail and a session-ordering
flaw in the tool — and **every finding was applied and is recorded in handoff
§14**. The review transcript itself is not published; §14 summarizes the
findings and fixes. Your review can use it as a benchmark: if you find
issues §14 doesn't already list, or disagree with one of its fixes, that's
a signal worth reporting in an issue.

A protocol that resists look-ahead bias — ask the model to commit before it
sees the answers:

1. **Before it sees `asusauth.py` or the known answer:** give it handoff §12.2
   (the algorithm description: MD5 nested, keys, MIX1/MIX2 byte-mangling) and
   ask it to independently implement the calculation and predict the response
   for challenge `98a80c…eb7`. Compare against the vector above. If its output
   differs by even one character, the discrepancy is finding #1.
2. **Then** give it `asusauth.py` + `emu.py` and ask: does the code faithfully
   implement §12.2? Does the emulation harness (`emu.py` map/stub assumptions,
   §12.4) actually execute ABL code, or could it be comparing two copies of the
   same bug? (It loads the real binary; check the mapping table in §12.4
   against the code.)
3. **If it has tool access**: ask it to disassemble `work/abl_linuxloader.efi`
   itself (e.g. with capstone via `work/disasm.py`) and verify the §12.7
   address table — dispatcher `0x44fb8`, `gen_hash 0x4690c`, `transform 0x46608`,
   `MIX1 0x46528`, `MIX2 0x46598`, the `asuskey2` receiver store `0x47eb0`, the
   challenge buffer `0x1fe3aa`, and the hardcoded keys `"12345678"`/`"28825252"`
   in the binary.
4. **Ask it to audit `work/unlock.py` against the §12.9 operational rules**:
   single blocking fastboot calls only (no poll loops that could kill a
   client mid-response), `flashing unlock` only in the same boot session as
   the PASS, both `OKAY`s (download + write) asserted, `getvar` parsing that
   can't be fooled by the `unlocked`/`rd_unlocked` substring trap.
5. **Red-team questions worth asking**: what would a FAIL from `auth-hash`
   actually leave behind (answer should be: nothing)? What could make the
   PASS a false positive? What assumptions does the A12-only scope rest on,
   and what exactly would change on an A13 ABL?

What an LLM **cannot** verify: the live-device claims (§12.9/§12.10, §13).
Those are the author's hands-on session; the record is as honest as it can be
made on paper (unverified items are labeled), but n=1 means n=1. If you run
Part 1, *you* are the replication study — file an issue either way.

---

## Repository layout

```
├── RESEARCH_HANDOFF.md            the full research record (facts vs [inference])
├── ZF8_DOWNGRADE_RUNBOOK.md       operator runbook for the A12 RAW downgrade
├── LICENSE                        MIT + third-party firmware exception
├── unlock_mitm_addon.py           mitmproxy script — historical (server path is dead)
├── mega_dl.py                     minimal MEGA downloader (historical)
├── scripts/                       ASUS's own flash scripts (license exception)
└── work/
    ├── abl_linuxloader.efi        the ABL binary — the target (license exception)
    ├── asus_bl_cert.der           embedded ASUS unlock cert (license exception)
    ├── asusauth.py                response calculator + self-tests vs emulator
    ├── emu.py                     unicorn harness that runs the actual ABL code
    ├── disasm.py                  capstone VA-range disassembler for the EFI
    ├── unlock.py                  end-to-end unlock tool (Part 1)
    └── asuskey2_response.bin      64-byte live-run response (Part 2b vector)
```

Not in the repo (deliberately): the ~7 GB A12 RAW image set (`raw/`), A13 OTA
deltas (`firmware/`), the ASUS unlock APKs, logs, the device identity
snapshot (redaction: IMEI/serial `<IMEI>`/`<SERIAL>`), and the transcript of
the prior LLM peer review (its substance is in handoff §14).

## Firmware sources

Nothing copyrighted from ASUS is redistributed here. Get firmware from:

- **XDA firmware collection thread** (RAW packages, OTAs, per-region):
  <https://xdaforums.com/t/zenfone-8-firmware-ota-collection.4620171/>
- **Official:** (helpdesk page, ZenFone 8) — most older packages have been
  pulled, but the A13 `.296` full package was still downloadable there as of
  Nov 2026 — <https://www.asus.com/supportonly/zenfone%208%20(zs590ks)/helpdesk_bios>

## License

MIT for everything original here — the research record, docs, and tools.
ASUS-extracted artifacts (`work/abl_linuxloader.efi`, `work/asus_bl_cert.der`,
`scripts/*.sh`) are covered by the **Third-Party Firmware Files exception** in
[`LICENSE`](LICENSE): they remain ASUS property, are included for verification
only, and no firmware packages are redistributed. Details at the bottom of the
LICENSE file.

## Credits

- The XDA ZenFone 8 community — the firmware OTA collection, and the
  documentation of the historical (now-dead) unlock-app path that motivated
  this deep dive.
- The LineageOS project (`sake` device maintainers) for making the point of
  the exercise worth reaching.
- This repo's research was independently reviewed by a second LLM (findings
  summarized in handoff §14); all of its findings were applied.
