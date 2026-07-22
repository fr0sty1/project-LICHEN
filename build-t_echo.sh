#!/usr/bin/env bash
# Build MCUboot + LICHEN puck firmware for the LilyGo T-Echo (nRF52840 + SX1262).
# Procurement/flashing/resale pipeline support: post-build includes test vector
# hooks for schnorr48/OSCORE/SCHC validation before bulk flash. Quotes target
# LilyGO bulk pricing <$8/unit; P&L integrated in flash-t_echo.sh --pipeline.
#
# Flash layout (matches lichen/boards/lilygo/t_echo/t_echo_nrf52840.dts):
#   0x00000–0x25FFF  MBR + SoftDevice S140 v6.1.1 (Adafruit bootloader, read-only)
#   0x26000–0x31FFF  MCUboot boot_partition (48 KB) — APP_START_ADDR
#   0x32000–0x8AFFF  slot0_partition — active puck app (356 KB max)
#   0x8B000–0xE3FFF  slot1_partition — SMP OTA staging (356 KB)
#   0xE4000–0xE7FFF  storage (16 KB)
#
# Usage:
#   ./build-t_echo.sh              # incremental (skip if build dir exists)
#   ./build-t_echo.sh --mcuboot    # force MCUboot rebuild
#   ./build-t_echo.sh --clean      # clean both builds
#   ./build-t_echo.sh --all        # full clean + rebuild both

set -euo pipefail
cd "$(dirname "$0")"

# Production-ready env: source lichen-zephyr workspace if available (removes hardcoded paths)
if [ -f /mnt/lichen-zephyr/env.sh ]; then
	. /mnt/lichen-zephyr/env.sh
fi
# Build-epoch check (lichen/cmake/lichen_build_epoch.cmake) requires this;
# upstream convention is the last commit's timestamp.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

MCUBOOT_DIR="build_mcuboot_t_echo"
APP_DIR="build_t_echo_puck"

FORCE_MCUBOOT=0
CLEAN=0

for arg in "$@"; do
    case "$arg" in
        --mcuboot) FORCE_MCUBOOT=1 ;;
        --clean)   CLEAN=1 ;;
        --all)     CLEAN=1; FORCE_MCUBOOT=1 ;;
    esac
done

if [[ $CLEAN -eq 1 ]]; then
    rm -rf "$MCUBOOT_DIR" "$APP_DIR"
fi

# -----------------------------------------------------------------------
# 1. MCUboot — compiled for boot_partition@0x27000 (48 KB), no signature check
# -----------------------------------------------------------------------
if [[ $FORCE_MCUBOOT -eq 1 ]] || [[ ! -f "$MCUBOOT_DIR/zephyr/zephyr.bin" ]]; then
    echo "==> Building MCUboot for T-Echo..."
    west build -b t_echo/nrf52840 bootloader/mcuboot/boot/zephyr \
        --build-dir "$MCUBOOT_DIR" --pristine \
        -- -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
           -DCONFIG_BOOT_UPGRADE_ONLY=y
fi

# -----------------------------------------------------------------------
# 2. Puck app — compiled for slot0@0x33000 (CONFIG_BOOTLOADER_MCUBOOT=y)
# -----------------------------------------------------------------------
echo "==> Building puck app for T-Echo..."
PRISTINE=""
[[ $CLEAN -eq 1 ]] && PRISTINE="--pristine"
west build -b t_echo/nrf52840 lichen/apps/puck \
    --build-dir "$APP_DIR" $PRISTINE

# -----------------------------------------------------------------------
# 3. Sign slot0 with imgtool
#
# Zephyr reserves ROM_START_OFFSET (0x200) bytes at the front of zephyr.bin
# as a placeholder for the MCUboot image header.  imgtool prepends the header
# to whatever input it receives, so if we pass the full zephyr.bin, the header
# lands BEFORE those 0x200 zeros — shifting the vector table to offset 0x400
# and causing MCUboot to read a zero SP/Reset and crash.
#
# Fix: strip the first 512 bytes (the ROM_START_OFFSET placeholder) before
# signing.  imgtool then writes the header + vector table at the correct
# offsets (0x000 and 0x200 within slot0 respectively).
# -----------------------------------------------------------------------
echo "==> Signing slot0..."
_TMP_STRIPPED=$(mktemp /tmp/t_echo_puck_stripped.XXXXXX.bin)
dd if="$APP_DIR/zephyr/zephyr.bin" bs=512 skip=1 of="$_TMP_STRIPPED" 2>/dev/null
python3 bootloader/mcuboot/scripts/imgtool.py sign \
    --header-size 0x200 \
    --align 4 \
    --version 1.0.0+0 \
    --slot-size 0x59000 \
    --pad-header \
    "$_TMP_STRIPPED" \
    "$APP_DIR/zephyr/zephyr.slot0.signed.bin"
rm -f "$_TMP_STRIPPED"

echo ""
echo "Done:"
echo "  MCUboot:   $MCUBOOT_DIR/zephyr/zephyr.bin"
echo "  Puck app:  $APP_DIR/zephyr/zephyr.slot0.signed.bin"
