#!/usr/bin/env bash
# Build MCUboot and LICHEN puck firmware for the Seeed T1000-E.
#
# Outputs:
#   build_mcuboot_t1000e/zephyr/zephyr.bin          MCUboot binary
#   build_t1000e_puck/zephyr/zephyr.bin             Puck app (unsigned)
#   build_t1000e_puck/zephyr/zephyr.slot0.signed.bin Puck app (MCUboot-signed)
#
# Usage:
#   ./build-t1000e.sh              # Build puck app only (MCUboot skipped if already built)
#   ./build-t1000e.sh --mcuboot    # Force MCUboot rebuild
#   ./build-t1000e.sh --clean      # Clean both build dirs first
#   ./build-t1000e.sh --all        # Rebuild everything

set -euo pipefail
cd "$(dirname "$0")"

APP_BUILD="build_t1000e_puck"
MCUBOOT_BUILD="build_mcuboot_t1000e"
IMGTOOL="bootloader/mcuboot/scripts/imgtool.py"
HEADER_SIZE="0x200"
SLOT_SIZE="0x59000"   # slot0_partition size (356 KB)

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8
# Build-epoch check (lichen/cmake/lichen_build_epoch.cmake) requires this;
# upstream convention is the last commit's timestamp.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

BUILD_MCUBOOT=false
BUILD_APP=true

for arg in "$@"; do
    case "$arg" in
        --mcuboot) BUILD_MCUBOOT=true ;;
        --all)     BUILD_MCUBOOT=true ;;
        --clean)
            rm -rf "$APP_BUILD" "$MCUBOOT_BUILD"
            BUILD_MCUBOOT=true
            ;;
    esac
done

# Always rebuild MCUboot if the binary is missing
if [[ ! -f "$MCUBOOT_BUILD/zephyr/zephyr.bin" ]]; then
    BUILD_MCUBOOT=true
fi

if $BUILD_MCUBOOT; then
    echo "==> Building MCUboot for t1000_e/nrf52840..."
    west build -d "$MCUBOOT_BUILD" -b "t1000_e/nrf52840" \
        bootloader/mcuboot/boot/zephyr -- \
        -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
        -DCONFIG_BOOT_SWAP_USING_MOVE=y \
        -DCONFIG_BOOT_MAX_IMG_SECTORS=256 \
        -DCONFIG_USB_DEVICE_STACK=n \
        -DCONFIG_USB_CDC_ACM=n \
        -DCONFIG_UART_CONSOLE=n \
        -DCONFIG_CONSOLE=n \
        -DCONFIG_LOG=n \
        -DCONFIG_BOOT_WATCHDOG_FEED=n
fi

echo "==> Building LICHEN puck app for t1000_e/nrf52840..."
west build -d "$APP_BUILD" -b "t1000_e/nrf52840" lichen/apps/puck

echo "==> Signing puck app..."
TMP=$(mktemp /tmp/lichen_content_XXXXXX.bin)
# zephyr.bin has a 512-byte pre-allocated MCUboot header region; strip it so
# imgtool --pad-header inserts a real header rather than double-padding.
dd if="$APP_BUILD/zephyr/zephyr.bin" bs=512 skip=1 of="$TMP" 2>/dev/null
python3 "$IMGTOOL" sign \
    --header-size "$HEADER_SIZE" \
    --align 4 \
    --version 0.1.0+0 \
    --slot-size "$SLOT_SIZE" \
    --pad-header \
    "$TMP" \
    "$APP_BUILD/zephyr/zephyr.slot0.signed.bin"
rm -f "$TMP"

echo ""
echo "Build complete:"
echo "  MCUboot:      $MCUBOOT_BUILD/zephyr/zephyr.bin"
echo "  Puck app:     $APP_BUILD/zephyr/zephyr.bin"
echo "  Signed slot0: $APP_BUILD/zephyr/zephyr.slot0.signed.bin"
echo ""
echo "To flash initially (device in UF2 bootloader mode — double-tap reset):"
echo "  ./flash-t1000e.sh"
echo ""
echo "To update OTA after first flash:"
echo "  python3 smp-flash.py rfc2217://localhost:4005 $APP_BUILD/zephyr/zephyr.slot0.signed.bin"
