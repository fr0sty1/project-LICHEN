#!/usr/bin/env bash
# Initial flash of MCUboot + LICHEN puck firmware to the Seeed T1000-E.
#
# Flash layout (APP_START_ADDR=0x1000, Adafruit UF2 bootloader v0.9.1):
#
#   0x0000–0x0FFF   Nordic MBR (4 KB, protected)
#   0x1000–0xCFFF   MCUboot boot_partition (48 KB) ← APP_START
#   0xD000–0x65FFF  slot0_partition — active LICHEN app (356 KB)
#   0x66000–0xBEFFF slot1_partition — SMP OTA staging (356 KB)
#   0xBF000–0xC2FFF storage_partition (16 KB)
#   0xF4000+        Adafruit UF2 bootloader itself
#
# IMPORTANT: UF2 drag-and-drop at any base address other than 0x1000 does
# NOT work for initial flash.  After the first serial DFU, the bootloader
# stores image_size at 0xFF000 and silently rejects UF2 blocks outside
# that region.  Use this script (serial DFU) for the initial flash.
#
# After first flash, use SMP OTA for app updates — no USB cable or reset:
#   python3 smp-flash.py /dev/serial/by-id/<ttyACM1-equivalent> \
#       build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
#
# Usage:
#   ./flash-t1000e.sh              # build puck app if needed, then flash
#   ./flash-t1000e.sh --rebuild    # force-rebuild MCUboot + puck, then flash
#
# Device state required:
#   - LICHEN firmware running: 1200-bps touch on ttyACM0 triggers bootloader
#     automatically; no manual reset needed.
#   - No firmware / bare-metal recovery: double-tap reset button first,
#     wait for T1000-E volume to mount, then run this script.

set -euo pipefail
cd "$(dirname "$0")"

APP_BUILD="build_t1000e_puck"
MCUBOOT_BUILD="build_mcuboot_t1000e"
COMBINED_BIN="/tmp/t1000e_combined.bin"
COMBINED_DFU="/tmp/t1000e_combined_dfu.zip"
BY_ID="/dev/serial/by-id"

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8

# -----------------------------------------------------------------------
# 1. Build
# -----------------------------------------------------------------------
BUILD_ARGS=()
if [[ "${1:-}" == "--rebuild" ]]; then
    BUILD_ARGS=(--all)
fi
./build-t1000e.sh "${BUILD_ARGS[@]}"

# -----------------------------------------------------------------------
# 2. Combine MCUboot + signed slot0 into a single DFU binary
# -----------------------------------------------------------------------
echo "==> Building combined DFU binary..."
python3 - <<'PYEOF'
import struct

MCUBOOT_ADDR = 0x1000   # boot_partition base = APP_START_ADDR
SLOT0_ADDR   = 0xD000   # slot0_partition base

mcuboot = open("build_mcuboot_t1000e/zephyr/zephyr.bin", "rb").read()
slot0   = open("build_t1000e_puck/zephyr/zephyr.slot0.signed.bin", "rb").read()

reset = struct.unpack_from("<I", mcuboot, 4)[0]
assert MCUBOOT_ADDR <= reset < SLOT0_ADDR, \
    f"MCUboot Reset=0x{reset:08X} not in boot_partition — stale build?"

magic = struct.unpack_from("<I", slot0, 0)[0]
assert magic == 0x96F3B83D, \
    f"slot0 missing MCUboot header (magic=0x{magic:08X}) — run build-t1000e.sh"

pad = b"\xff" * (SLOT0_ADDR - MCUBOOT_ADDR - len(mcuboot))
combined = mcuboot + pad + slot0

with open("/tmp/t1000e_combined.bin", "wb") as f:
    f.write(combined)
print(f"  mcuboot@0x{MCUBOOT_ADDR:05X} ({len(mcuboot)} B)  "
      f"slot0@0x{SLOT0_ADDR:05X} ({len(slot0)} B)  "
      f"total={len(combined)} B")
PYEOF

# -----------------------------------------------------------------------
# 3. Package
# -----------------------------------------------------------------------
echo "==> Packaging DFU..."
adafruit-nrfutil dfu genpkg \
    --dev-type 0x0052 \
    --application "$COMBINED_BIN" \
    --application-version 2 \
    "$COMBINED_DFU"

# -----------------------------------------------------------------------
# 4. Find port and flash
#
# Priority:
#   a) $T1000E_PORT if set — used as-is (must be /dev/serial/by-id/...)
#   b) LICHEN app port (lichen-node pattern) — 1200-bps touch triggers DFU
#   c) DFU bootloader port (Seeed pattern) — already in DFU, flash directly
# -----------------------------------------------------------------------
echo ""

find_port() {
    local pattern="$1"
    ls "$BY_ID/"*"${pattern}"* 2>/dev/null | head -1
}

if [[ -n "${T1000E_PORT:-}" ]]; then
    PORT="$T1000E_PORT"
    echo "==> Using T1000E_PORT=$PORT"
elif PORT=$(find_port "LICHEN"); [ -n "$PORT" ]; then
    echo "==> Found LICHEN app on $PORT — 1200-bps touch will trigger DFU"
elif PORT=$(find_port "T1000-E"); [ -n "$PORT" ]; then
    echo "==> Found T1000-E DFU bootloader on $PORT — flashing directly"
else
    echo "ERROR: No T1000-E serial port found in $BY_ID/"
    echo ""
    echo "  If LICHEN firmware is running: it should appear automatically."
    echo "  For bare-metal recovery: double-tap reset, wait for volume to"
    echo "  mount, then re-run this script."
    exit 1
fi

echo "==> Flashing via serial DFU on $PORT..."
adafruit-nrfutil --verbose dfu serial \
    --package "$COMBINED_DFU" \
    -p "$PORT" \
    -b 115200 \
    --singlebank \
    --touch 1200

echo ""
echo "Done. Expected USB devices after boot (~3 s):"
echo "  ttyACM0  — LICHEN Native protocol (LICHEN Node, VID=0x2FE3)"
echo "  ttyACM1  — SMP OTA transport     (mcumgr / smp-flash.py)"
echo ""
echo "To flash app updates via SMP (no reset, no cable swap):"
echo "  python3 smp-flash.py \$(ls $BY_ID/*LICHEN*if01 2>/dev/null | head -1) \\"
echo "      $APP_BUILD/zephyr/zephyr.slot0.signed.bin"
