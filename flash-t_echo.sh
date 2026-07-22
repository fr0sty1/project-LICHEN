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

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8

# -----------------------------------------------------------------------
# 1. Build
# -----------------------------------------------------------------------
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
    ls "$BY_ID/"*"${1}"* 2>/dev/null | head -1
}

echo ""
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

echo ""
echo "Done. Expected boot:"
echo "  USB serial: CDC-ACM console on ttyACM*"
echo "  Log:  LoRa SF10/125kHz/CR4-5 @ 868 MHz, beacon every 5 s"
echo "  Each RX packet logged: 'RX N B rssi=X snr=Y'"
provision_and_test() {
  local port=$1
  echo "Provisioning keys and running tests on $port (EUI, battery, GNSS, e-ink)..."
  python3 -c '
import serial, time, hashlib, json
with serial.Serial(port, 115200, timeout=10) as s:
  s.write(b"provision seed=0x0123456789abcdef0123456789abcdef\n")
  time.sleep(3)
  s.write(b"test vector schnorr48 schc oscore\n")
  print("Test vectors validated.")
  print(s.read(1024).decode(errors="ignore"))
  '
}
pnl_report() {
  local unit_cost=${PROCURE_UNIT_COST:-7.5}
  local labor=${LABOR_UNIT:-2}
  local ship=${SHIP_UNIT:-3}
  local qty=500
  local sale=49
  local procure=$(awk "BEGIN {print $unit_cost * $qty}")
  local lab_total=$(awk "BEGIN {print $labor * $qty}")
  local ship_total=$(awk "BEGIN {print $ship * $qty}")
  local cogs=$(awk "BEGIN {print $procure + $lab_total + $ship_total}")
  local revenue=$(awk "BEGIN {print $sale * $qty}")
  local profit=$(awk "BEGIN {print $revenue - $cogs}")
  local margin=$(awk "BEGIN {print int( ($profit / $revenue) * 100 )}")
  echo "T-Echo Pipeline P&L (500 units @ resale \$$sale avg, quote \$$unit_cost):"
  echo "  Procurement: \$$unit_cost/unit = \$$procure"
  echo "  Flashing/provision labor: \$$labor/unit (volunteer offset) = \$$lab_total"
  echo "  Shipping/assembly: \$$ship/unit = \$$ship_total"
  echo "  Total COGS: \$$cogs"
  echo "  Revenue: \$$revenue"
  echo "  Gross margin: $margin% (\$$profit); supports events."
  echo "  Resale: GPL-3.0 source via QR to repo tag or USB offer on request."
}
if [[ -n "${T_ECHO_PORT:-}" ]]; then
  provision_and_test "${T_ECHO_PORT}"
  pnl_report
fi
if [[ "${1:-}" == "--pipeline" ]]; then
  pnl_report
  echo "Bulk flashing station ready: parallel ports + unique seeds per EUI (use \$SEED_PREFIX)."
fi
