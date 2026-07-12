# Seeed SenseCAP T1000-E — Flashing Guide

This document records all the errata and procedures for flashing the T1000-E.
Read it fully before touching any flash tool or script.

---

## Flash layout (authoritative)

```
0x0000–0x0FFF   Nordic MBR           (4 KB, ROM, protected)
0x1000–0xCFFF   MCUboot boot_partition (48 KB)  ← APP_START_ADDR
0xD000–0x65FFF  slot0_partition       (356 KB, active LICHEN app)
0x66000–0xBEFFF slot1_partition       (356 KB, SMP OTA staging)
0xBF000–0xC2FFF storage_partition     (16 KB)
0xF4000+        Adafruit UF2 bootloader
```

**APP_START_ADDR = 0x1000.**  The Adafruit UF2 bootloader on this device was
compiled without SoftDevice — there is no SoftDevice occupying 0x1000–0x26000.
The bootloader jumps directly to 0x1000 (Nordic MBR page + 1).  MCUboot lives
there, and MCUboot then boots the LICHEN app from slot0 at 0xD000.

---

## Common mistakes that cause silent failure

### 1. Wrong base address (0x26000 or 0x27000)

Standard Adafruit nRF52840 bootloaders compiled *with* SoftDevice S140 use
APP_START = 0x26000 (SoftDevice occupies 0x1000–0x26000).  This T1000-E build
has **no SoftDevice**, so APP_START = 0x1000.

Building with `CONFIG_FLASH_LOAD_OFFSET=0x26000` or generating a UF2 at base
`0x26000` produces a binary that is **never executed**.  The bootloader checks
the vector table at 0x1000, finds the old (MCUboot) or garbage, and either
boots that or loops silently.  USB never appears.  There is no error message.

### 2. UF2 drag-and-drop for initial flash

UF2 drag-drop looks like it works (volume mounts, UF2 is copied, volume
unmounts), but the flash write may be silently rejected.  After the first
serial DFU, the bootloader writes `image_size = 16 KB` to `0xFF000`.  Any
subsequent UF2 block targeting an address above `0x1000 + 16 KB = 0x5000` is
silently discarded.

**Use serial DFU (`flash-t1000e.sh`) for the initial flash.  Use SMP OTA for
all subsequent app updates.**

### 3. Diagnosing "USB never appears"

If you flash firmware and USB does not enumerate within 5 seconds:

1. **Check APP_START** — is the firmware linked at 0xD000 (slot0)?  Run:
   ```
   grep FLASH_LOAD_OFFSET build_t1000e_puck/zephyr/.config
   # Must be: CONFIG_FLASH_LOAD_OFFSET=0xd000
   ```
2. **Check MCUboot header** — is the slot0 binary signed?
   ```
   python3 -c "
   import struct
   with open('build_t1000e_puck/zephyr/zephyr.slot0.signed.bin','rb') as f:
       m = struct.unpack('<I', f.read(4))[0]
   print('OK' if m == 0x96F3B83D else f'BAD magic: 0x{m:08X}')
   "
   ```
3. **Check MCUboot is installed** — has `flash-t1000e.sh` ever run successfully?
   Without MCUboot at 0x1000, the Adafruit bootloader jumps to whatever is
   there (could be garbage, old Meshtastic, etc.).
4. **Serial port naming** — always use `/dev/serial/by-id/` paths, never
   `/dev/ttyACM*`.  The kernel can renumber ttyACM devices across reboots.

---

## Procedures

### Initial flash (bare-metal / no LICHEN firmware)

Requires `adafruit-nrfutil` and `imgtool` (both available in this repo's
venv).

```bash
# Double-tap the reset button → T1000-E DFU volume mounts
# Wait for it to appear (lsblk will show label T1000-E)

./flash-t1000e.sh
# Detects DFU serial port automatically via /dev/serial/by-id/
# Combines MCUboot + signed slot0, then flashes via serial DFU
```

Expected after boot (~3 s):
- `ttyACM0` — LICHEN Native protocol  (VID=0x2FE3 PID=0x0100, "LICHEN Node")
- `ttyACM1` — SMP OTA transport       (for mcumgr / smp-flash.py)

### App update (LICHEN firmware already running)

No reset or USB cable swap required:

```bash
./build-t1000e.sh          # rebuilds puck app and signs slot0
python3 smp-flash.py \
    "$(ls /dev/serial/by-id/*LICHEN*if01 2>/dev/null | head -1)" \
    build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
```

The 1200-bps CDC touch (DFU trigger) is also supported: if LICHEN is running,
`flash-t1000e.sh` touches `ttyACM0` at 1200 baud which triggers a reboot into
the Adafruit DFU bootloader, then flashes automatically.

### Recovery (USB completely dead, double-tap not responding)

If the device is stuck in a fault handler (no USB, no DFU mount):

1. Hold the reset button for >5 s (or remove and reinsert battery if USB power
   is the only source) to force a cold reset.
2. Immediately double-tap the reset button within ~0.5 s of power-up.
3. T1000-E DFU volume mounts → run `./flash-t1000e.sh`.

---

## Build system notes

```bash
./build-t1000e.sh           # build puck app only (MCUboot skipped if present)
./build-t1000e.sh --all     # rebuild MCUboot + puck app
./build-t1000e.sh --clean   # rm -rf build dirs, then build everything
```

Artifacts:
- `build_mcuboot_t1000e/zephyr/zephyr.bin`          MCUboot, linked at 0x1000
- `build_t1000e_puck/zephyr/zephyr.bin`             LICHEN puck app (unsigned)
- `build_t1000e_puck/zephyr/zephyr.slot0.signed.bin` Signed slot0 for MCUboot

The puck app uses `CONFIG_BOOTLOADER_MCUBOOT=y` which causes Zephyr to
pre-allocate a 512-byte MCUboot header region at the start of zephyr.bin.
The `build-t1000e.sh` script strips this placeholder and calls `imgtool sign
--pad-header` to insert the real MCUboot image header before the signed binary
is suitable for programming.

---

## Historical errata

| Date       | Mistake                                     | Symptom                        |
|------------|---------------------------------------------|--------------------------------|
| 2026-06    | Built with FLASH_LOAD_OFFSET=0x26000        | USB never appeared             |
| 2026-06    | Flashed UF2 at base 0x26000 via drag-drop   | DFU accepted, firmware silent  |
| 2026-06    | Diagnosed "USBD NEXT broken"                | False — firmware never ran     |
| 2026-06    | `t1000e_boot_blink()` PRE_KERNEL_1 delay    | 18–30 s USB enumeration delay  |

The "USBD NEXT broken" diagnosis from June 2026 was incorrect.  USB was never
tested because the firmware at 0x26000 was never executed — the bootloader was
jumping to 0x1000 (MCUboot or garbage).  USBD NEXT remains the correct USB
stack for the puck build with `CONFIG_BOOTLOADER_MCUBOOT=y`.

The `t1000e_boot_blink()` function (removed in commit on this branch) ran 6
busy-loops of 64 000 000 iterations each at PRE_KERNEL_1, totalling 18–30 s
before USB initialised.  This was removed; USB comes up in ~3 s.
