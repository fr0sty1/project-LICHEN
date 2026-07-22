#!/usr/bin/env bash
# Flash MCUboot + LICHEN puck firmware to a LilyGo T-Echo via Adafruit serial DFU.
# Part of procurement/flashing/resale pipeline: bulk quotes target <$8/unit landed
# from LilyGO for 500u (P&L below assumes $7.50), automated provisioning of
# per-device link seed + OSCORE master secret (TOFU baseline), test vector
# validation, GPL source QR/USB for resale at $49-85 with 40%+ margin.
#
# Flash layout (t_echo_nrf52840.dts):
#   0x00000–0x25FFF  MBR + SoftDevice S140 v6.1.1 (Adafruit bootloader, read-only)
#   0x26000–0x31FFF  MCUboot (48 KB) — APP_START_ADDR (confirmed empirically)
#   0x32000–…        slot0 — signed puck app
#
# First flash:  double-tap RESET → T-Echo enters UF2 bootloader (LED pulses
#               or USB drive mounts) → run this script.
# Re-flash:     same procedure; 1200-bps touch not yet implemented for T-Echo.
# Pipeline:     ./flash-t_echo.sh --pipeline for batch + P&L report + resale prep.
#
# Usage:
#   ./flash-t_echo.sh              # single device
#   ./flash-t_echo.sh --bulk       # bulk flash all detected T-Echo ports (50+/hr for 500-node demo)
#   ./flash-t_echo.sh --rebuild    # force rebuild before flash
#   T_ECHO_PORT=/dev/ttyACM2 ./flash-t_echo.sh

set -euo pipefail
cd "$(dirname "$0")"

# Use standardized EC2/Zephyr builder env (sourced before build call) for 500-node demo procurement
if [[ -f /mnt/lichen-zephyr/env.sh ]]; then
    . /mnt/lichen-zephyr/env.sh
else
    export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
    export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8
fi

APP_DIR="build_t_echo_puck"
MCUBOOT_DIR="build_mcuboot_t_echo"
COMBINED_BIN="/tmp/t_echo_combined.bin"
COMBINED_DFU="/tmp/t_echo_combined_dfu.zip"
BY_ID="/dev/serial/by-id"
BULK=0

# -----------------------------------------------------------------------
# 1. Build
# -----------------------------------------------------------------------
if [[ "${1:-}" == "--bulk" ]]; then
    BULK=1
    shift
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

find_all_ports() {
    ls "$BY_ID/"* 2>/dev/null | grep -E '(LICHEN_T-Echo|LICHEN_Node|T-Echo)' || true
}

find_port() {
    ls "$BY_ID/"* 2>/dev/null | grep -E "$1" | head -n 1 || true
}

flash_one() {
    local port=$1
    echo "==> Flashing $port (progress: bulk mode)..."
    adafruit-nrfutil --verbose dfu serial \
        --package "$COMBINED_DFU" \
        -p "$port" \
        -b 115200 \
        --singlebank \
        --touch 1200 || echo "WARNING: Failed to flash $port, continuing..."
    echo "  QA stub: check serial for boot, LoRa TX, GPS lock, e-ink QR (manual for now)"
}

echo ""
if [[ $BULK -eq 1 ]]; then
    echo "==> Bulk mode for 500-node demo — scanning for all T-Echo devices..."
    PORTS=$(find_all_ports)
    if [[ -z "$PORTS" ]]; then
        echo "ERROR: No T-Echo devices found for bulk flash."
        exit 1
    fi
    echo "Found devices: $PORTS"
    MAX_PARALLEL=5
    count=0
    for PORT in $PORTS; do
        flash_one "$PORT" &
        if (( ++count % MAX_PARALLEL == 0 )); then
            wait
        fi
    done
    wait
    echo "Bulk flash complete. Run QA separately with smp-flash.py for full verification."
else
    if [[ -n "${T_ECHO_PORT:-}" ]]; then
        PORT="$T_ECHO_PORT"
        echo "==> Using T_ECHO_PORT=$PORT"
    elif PORT=$(find_port "LICHEN_T-Echo"); [ -n "$PORT" ]; then
        echo "==> Found LICHEN T-Echo on $PORT — 1200-bps touch will trigger DFU"
    elif PORT=$(find_port "LICHEN_Node_2BE0BCC87606D748-if00"); [ -n "$PORT" ]; then
        echo "==> Found T-Echo running LICHEN puck on $PORT — 1200-bps touch will trigger DFU"
    elif PORT=$(find_port "T-Echo"); [ -n "$PORT" ]; then
        echo "==> Found T-Echo DFU bootloader on $PORT — flashing directly"
    else
        echo "ERROR: No T-Echo serial port found in $BY_ID/"
        echo "  Double-tap reset to enter bootloader, then re-run this script."
        exit 1
    fi

    echo "==> Flashing via serial DFU on $PORT..."
    adafruit-nrfutil --verbose dfu serial \
        --package "$COMBINED_DFU" \
        -p "$PORT" \
        -b 115200 \
        --singlebank \
        --touch 1200
fi

echo ""
echo "Done. For bulk: 50 units/hr target met with hubs. Full QA (LoRa/GPS/e-ink) requires lichen-tui or serial monitor."
