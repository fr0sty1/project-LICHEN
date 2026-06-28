#!/usr/bin/env bash
# Flash MCUboot + LICHEN puck firmware to T1000-E via UF2 drag-and-drop.
#
# First-time setup only. After this, use smp-flash.py for OTA updates:
#   python3 smp-flash.py rfc2217://localhost:4005 build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
#
# Usage:
#   ./flash-t1000e-uf2.sh [--build]   # --build forces MCUboot rebuild

set -euo pipefail
cd "$(dirname "$0")"

APP_BUILD="build_t1000e_puck"
MCUBOOT_BUILD="build_mcuboot_t1000e"
IMGTOOL="bootloader/mcuboot/scripts/imgtool.py"
UF2CONV="zephyr/scripts/build/uf2conv.py"
COMBINED_UF2="lichen_t1000e.uf2"
FAMILY="0xada52840"
HEADER_SIZE="0x200"
SLOT_SIZE="0x5A000"   # slot0_partition size from t1000_e DTS (360 KB)
SLOT0_ADDR="0x32000"  # slot0_partition offset; MCUboot at 0x26000 (APP_START_ADDR)

# Adjust PYTHONPATH for cbor2 if needed
export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"

# -----------------------------------------------------------------------
# 1. Build MCUboot (once; skip if already built unless --build passed)
# -----------------------------------------------------------------------
if [[ "${1:-}" == "--build" || ! -f "$MCUBOOT_BUILD/zephyr/zephyr.hex" ]]; then
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
        -DCONFIG_LOG=n
fi

# -----------------------------------------------------------------------
# 2. Sign LICHEN puck firmware (add MCUboot header — no key for NONE type)
# -----------------------------------------------------------------------
if [[ ! -f "$APP_BUILD/zephyr/zephyr.hex" ]]; then
    echo "ERROR: $APP_BUILD not built — run: west build -d $APP_BUILD" >&2
    exit 1
fi

echo "==> Adding MCUboot header to firmware..."
# zephyr.bin starts with CONFIG_BOOT_HEADER_SIZE zeros (pre-allocated header space),
# followed by the ARM vector table. Strip those zeros so imgtool --pad-header adds
# a real MCUboot header in their place (without --pad-header imgtool would double-pad).
TMP_CONTENT=$(mktemp /tmp/lichen_content_XXXXXX.bin)
dd if="$APP_BUILD/zephyr/zephyr.bin" bs=512 skip=1 of="$TMP_CONTENT" 2>/dev/null
python3 "$IMGTOOL" sign \
    --header-size "$HEADER_SIZE" \
    --align 4 \
    --version 0.1.0+0 \
    --slot-size "$SLOT_SIZE" \
    --pad-header \
    "$TMP_CONTENT" \
    "$APP_BUILD/zephyr/zephyr.slot0.signed.bin"
rm -f "$TMP_CONTENT"

# -----------------------------------------------------------------------
# 3. Combine MCUboot + signed firmware into a single UF2
#    MCUboot hex:  0x026000–0x031FFF (boot_partition, APP_START_ADDR)
#    Firmware hex: 0x032000–         (slot0_partition)
#    Concatenate by stripping the EOF record (:00000001FF) from MCUboot hex.
# -----------------------------------------------------------------------
echo "==> Building combined UF2..."
TMP_HEX=$(mktemp /tmp/lichen_combined_XXXXXX.hex)
TMP_SLOT0_HEX=$(mktemp /tmp/lichen_slot0_XXXXXX.hex)
# Convert signed slot0 BIN back to intel hex at the correct base address
arm-none-eabi-objcopy -I binary -O ihex \
    --change-addresses "$SLOT0_ADDR" \
    "$APP_BUILD/zephyr/zephyr.slot0.signed.bin" \
    "$TMP_SLOT0_HEX"
grep -v '^:00000001FF' "$MCUBOOT_BUILD/zephyr/zephyr.hex" > "$TMP_HEX"
cat "$TMP_SLOT0_HEX" >> "$TMP_HEX"
python3 "$UF2CONV" "$TMP_HEX" -f "$FAMILY" -o "$COMBINED_UF2"
rm "$TMP_HEX" "$TMP_SLOT0_HEX"
echo "    Created: $COMBINED_UF2"

# -----------------------------------------------------------------------
# 4. Wait for T1000-E UF2 drive to mount, then copy
# -----------------------------------------------------------------------
echo ""
echo "Put T1000-E into bootloader mode (double-tap reset or hold button while plugging in)."
echo "Waiting for UF2 drive to mount..."

MOUNT=""
for i in $(seq 1 60); do
    # Look for the Adafruit/Seeed UF2 bootloader volume
    for candidate in \
        /run/media/"$USER"/T1000* \
        /run/media/"$USER"/SEEED* \
        /run/media/"$USER"/NRF52* \
        /media/"$USER"/T1000* \
        /media/"$USER"/SEEED* \
        /media/"$USER"/NRF52* \
        /media/T1000* /media/SEEED* /media/NRF52*; do
        if [[ -d "$candidate" && -f "$candidate/INFO_UF2.TXT" ]]; then
            MOUNT="$candidate"
            break 2
        fi
    done
    sleep 1
done

if [[ -z "$MOUNT" ]]; then
    echo "ERROR: T1000-E drive not found after 60s." >&2
    echo "Copy manually: cp $COMBINED_UF2 <mount-point>/" >&2
    exit 1
fi

echo "==> Found drive: $MOUNT"
cat "$MOUNT/INFO_UF2.TXT" 2>/dev/null | head -4 || true
echo ""
echo "==> Flashing $COMBINED_UF2 → $MOUNT/"
cp "$COMBINED_UF2" "$MOUNT/"
echo "    Done. T1000-E will reboot into LICHEN firmware."
