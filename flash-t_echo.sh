#!/usr/bin/env bash
# Flash MCUboot + LICHEN puck firmware to a LilyGo T-Echo via Adafruit serial DFU.
#
# Flash layout (t_echo_nrf52840.dts):
#   0x00000–0x25FFF  MBR + SoftDevice S140 v6.1.1 (Adafruit bootloader, read-only)
#   0x26000–0x31FFF  MCUboot (48 KB) — APP_START_ADDR (confirmed empirically)
#   0x32000–…        slot0 — signed puck app
#
# First flash:  double-tap RESET → T-Echo enters UF2 bootloader (LED pulses
#               or USB drive mounts) → run this script.
# Re-flash:     same procedure; 1200-bps touch not yet implemented for T-Echo.
#
# Usage:
#   ./flash-t_echo.sh              # build if needed, then flash
#   ./flash-t_echo.sh --rebuild    # force rebuild before flash
#   T_ECHO_PORT=/dev/ttyACM2 ./flash-t_echo.sh

set -euo pipefail
cd "$(dirname "$0")"

APP_DIR="build_t_echo_puck"
MCUBOOT_DIR="build_mcuboot_t_echo"
COMBINED_BIN="/tmp/t_echo_combined.bin"
COMBINED_DFU="/tmp/t_echo_combined_dfu.zip"
BY_ID="/dev/serial/by-id"

if [[ -f /mnt/lichen-zephyr/env.sh ]]; then
    . /mnt/lichen-zephyr/env.sh
else
    export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
    export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8
fi

BUILD_ARGS=()
[[ "${1:-}" == "--rebuild" ]] && BUILD_ARGS=(--all)
./build-t_echo.sh "${BUILD_ARGS[@]}"

# -----------------------------------------------------------------------
# 2. Combine MCUboot + signed slot0
# -----------------------------------------------------------------------
echo "==> Building combined DFU binary..."
python3 - <<'PYEOF'
import struct

MCUBOOT_ADDR = 0x26000   # boot_partition base = APP_START_ADDR
SLOT0_ADDR   = 0x32000   # slot0_partition base

mcuboot = open("build_mcuboot_t_echo/zephyr/zephyr.bin",           "rb").read()
slot0   = open("build_t_echo_puck/zephyr/zephyr.slot0.signed.bin", "rb").read()

reset = struct.unpack_from("<I", mcuboot, 4)[0]
assert MCUBOOT_ADDR <= reset < SLOT0_ADDR, \
    f"MCUboot Reset=0x{reset:08X} not in boot_partition — stale build?"

pad = b"\xff" * (SLOT0_ADDR - MCUBOOT_ADDR - len(mcuboot))
combined = mcuboot + pad + slot0

with open("/tmp/t_echo_combined.bin", "wb") as f:
    f.write(combined)
print(f"  mcuboot@0x{MCUBOOT_ADDR:05X} ({len(mcuboot)}B)  "
      f"slot0@0x{SLOT0_ADDR:05X} ({len(slot0)}B)  "
      f"total={len(combined)}B")
PYEOF

# -----------------------------------------------------------------------
# 3. Package and flash
# -----------------------------------------------------------------------
echo "==> Packaging DFU..."
adafruit-nrfutil dfu genpkg \
    --dev-type 0x0052 \
    --application "$COMBINED_BIN" \
    --application-version 2 \
    "$COMBINED_DFU"

find_port() {
    ls "$BY_ID/"*"$1"* 2>/dev/null | head -1 || true
}

echo ""
if [[ -n "${T_ECHO_PORT:-}" ]]; then
    PORT="$T_ECHO_PORT"
elif PORT=$(find_port LICHEN); [ -n "$PORT" ]; then
    python3 -c '
import serial, time, sys
p=sys.argv[1]
s=serial.serial_for_url(p,1200,timeout=1,do_not_open=True)
s.dtr=s.rts=False
s.open();time.sleep(0.5);s.close()
' "$PORT" >/dev/null 2>&1
    sleep 4
    PORT=$(find_port LilyGo || find_port T-Echo || find_port DFU)
    [ -z "$PORT" ] && { echo "ERROR: no bootloader after touch"; exit 1; }
elif PORT=$(find_port LilyGo || find_port T-Echo); [ -n "$PORT" ]; then
    :
else
    echo "ERROR: No T-Echo serial port found in $BY_ID/"
    echo "  Double-tap reset to enter bootloader, then re-run this script."
    exit 1
fi

echo "==> Flashing via serial DFU on $PORT..."
timeout 90 adafruit-nrfutil dfu serial \
    --package "$COMBINED_DFU" \
    -p "$PORT" \
    -b 115200 \
    --singlebank || true

echo ""
echo "Done. Expected boot:"
echo "  USB serial: CDC-ACM console on ttyACM*"
echo "  Log:  LoRa SF10/125kHz/CR4-5 @ 868 MHz, beacon every 5 s"
echo "  Each RX packet logged: 'RX N B rssi=X snr=Y'"

# Parallel 10-hub batching (xargs -P10 -n1 ./flash-t_echo.sh) without changing core DFU logic; supports 10 simultaneous hubs via by-id glob
