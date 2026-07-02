#!/usr/bin/env bash
# No-physical-touch recovery + reflash for the nRF52840 LICHEN boards.
#
# Ladder (first rung that applies wins):
#   1. Bootloader port already present        -> serial DFU directly
#   2. App running                            -> 1200-bps touch into DFU, then flash
#   3. No port at all (USB-wedged device)     -> uhubctl power-cycle its hub port
#                                                ("software replug"), then rung 1/2
#
#   4. T-Echo only: serial DFU failed/wedged  -> UF2 copy of the combined
#      image to the auto-mounted TECHOBOOT volume (un-wedges the bootloader)
#
# T1000-E has no UF2 rung: its bootloader rejects UF2 blocks outside the app
# region — use the 1200-touch or uhubctl rungs. Last resort is manual DFU.
#
# SMP OTA over the running app (smp-flash.py) is NOT in this ladder yet:
# uploads are killed by the nRF52840 USB/SPIM contention wedge -> 4 s WDT
# reset (see bd). Use it experimentally; this script is the reliable path.
#
# Usage:
#   ./recover.sh t1000e            # build, then recover+flash the T1000-E
#   ./recover.sh t_echo            # build, then recover+flash the T-Echo
#   ./recover.sh t_echo --no-build # skip rebuild, reuse existing DFU package

set -euo pipefail
cd "$(dirname "$0")"

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
BY_ID="/dev/serial/by-id"

BOARD="${1:-}"
NO_BUILD=0
[[ "${2:-}" == "--no-build" ]] && NO_BUILD=1

case "$BOARD" in
    t1000e)
        SERIAL="891FA3226B7B0D14"
        HUB_PORT=6                     # Terminus hub 1-1, physical port 6
        BL_GLOB="Seeed_Studio_T1000-E_${SERIAL}"
        BUILD=./build-t1000e.sh
        MCUBOOT_BIN=build_mcuboot_t1000e/zephyr/zephyr.bin
        SLOT0_BIN=build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
        MCUBOOT_ADDR=0x1000; SLOT0_ADDR=0xD000
        COMBINED=/tmp/t1000e_combined.bin
        DFU_ZIP=/tmp/t1000e_combined_dfu.zip
        ;;
    t_echo)
        SERIAL="2BE0BCC87606D748"
        HUB_PORT=7
        BL_GLOB="LilyGo_T-Echo_v1_${SERIAL}"
        BUILD=./build-t_echo.sh
        MCUBOOT_BIN=build_mcuboot_t_echo/zephyr/zephyr.bin
        SLOT0_BIN=build_t_echo_puck/zephyr/zephyr.slot0.signed.bin
        MCUBOOT_ADDR=0x26000; SLOT0_ADDR=0x32000
        COMBINED=/tmp/t_echo_combined.bin
        DFU_ZIP=/tmp/t_echo_combined_dfu.zip
        ;;
    *)
        echo "usage: $0 {t1000e|t_echo} [--no-build]" >&2
        exit 2
        ;;
esac

APP_GLOB="LICHEN_Node_${SERIAL}-if00"

app_port()  { ls "$BY_ID/"*"$APP_GLOB"* 2>/dev/null | head -1 || true; }
boot_port() { ls "$BY_ID/"*"$BL_GLOB"*  2>/dev/null | head -1 || true; }

wait_for() {  # wait_for <fn> <seconds>
    local fn=$1 secs=$2 p=""
    for _ in $(seq 1 "$secs"); do
        p=$($fn)
        [[ -n "$p" ]] && { echo "$p"; return 0; }
        sleep 1
    done
    return 1
}

# -----------------------------------------------------------------------
# Build + package
# -----------------------------------------------------------------------
if [[ $NO_BUILD -eq 0 ]]; then
    echo "==> Building..."
    $BUILD >/dev/null
fi

echo "==> Packaging combined MCUboot+app DFU image..."
MCUBOOT_BIN="$MCUBOOT_BIN" SLOT0_BIN="$SLOT0_BIN" \
MCUBOOT_ADDR="$MCUBOOT_ADDR" SLOT0_ADDR="$SLOT0_ADDR" COMBINED="$COMBINED" \
python3 - <<'PYEOF'
import os, struct
mcuboot_addr = int(os.environ["MCUBOOT_ADDR"], 16)
slot0_addr   = int(os.environ["SLOT0_ADDR"], 16)
mcuboot = open(os.environ["MCUBOOT_BIN"], "rb").read()
slot0   = open(os.environ["SLOT0_BIN"], "rb").read()
reset = struct.unpack_from("<I", mcuboot, 4)[0]
assert mcuboot_addr <= reset < slot0_addr, \
    f"MCUboot Reset=0x{reset:08X} outside boot partition — stale build?"
pad = b"\xff" * (slot0_addr - mcuboot_addr - len(mcuboot))
open(os.environ["COMBINED"], "wb").write(mcuboot + pad + slot0)
PYEOF
adafruit-nrfutil dfu genpkg --dev-type 0x0052 \
    --application "$COMBINED" --application-version 2 "$DFU_ZIP" >/dev/null

# -----------------------------------------------------------------------
# Recovery ladder
# -----------------------------------------------------------------------
touch_1200() {
    echo "==> 1200-bps touch on $1..."
    python3 - "$1" <<'PYEOF'
import sys, time, serial
s = serial.serial_for_url(sys.argv[1], baudrate=1200, timeout=1, do_not_open=True)
s.dtr = False; s.rts = False
s.open(); time.sleep(0.5); s.close()
PYEOF
}

# The Terminus hub only supports GANGED power switching (-f required):
# cycling any port cycles ALL of them — the other boards just re-enumerate.
# Limitation: this is a host/bus-level replug. A battery-powered board whose
# USB stack died device-side (T1000-E -110 wedge, bd 1jqj) keeps its MCU
# powered through the cycle and stays wedged — that needs a physical replug.
hub_cycle() {
    echo "==> No serial port for $BOARD — power-cycling hub 1-1 (ganged; all ports)..."
    if ! uhubctl -l 1-1 -a cycle -d 3 -f; then
        echo "ERROR: uhubctl failed. Install the hub udev rule (99-lichen-hub.rules)" >&2
        echo "       or run: sudo uhubctl -l 1-1 -a cycle -d 3 -f" >&2
        exit 1
    fi
    sleep 5
}

uf2_fallback() {  # T-Echo only: the wedged bootloader still serves USB MSC
    [[ "$BOARD" == "t_echo" ]] || return 1
    echo "==> Serial DFU failed — trying UF2 fallback via TECHOBOOT..."
    local dev="" vol="" i
    for i in $(seq 1 15); do
        dev=$(lsblk -rno NAME,LABEL 2>/dev/null | awk '$2=="TECHOBOOT"{print "/dev/"$1; exit}')
        [[ -n "$dev" ]] && break
        sleep 1
    done
    [[ -n "$dev" ]] || { echo "TECHOBOOT volume never appeared" >&2; return 1; }
    vol=$(lsblk -rno MOUNTPOINT "$dev" | head -1)
    if [[ -z "$vol" ]]; then
        udisksctl mount -b "$dev" >/dev/null 2>&1 || true
        sleep 1
        vol=$(lsblk -rno MOUNTPOINT "$dev" | head -1)
    fi
    [[ -n "$vol" ]] || { echo "TECHOBOOT would not mount" >&2; return 1; }
    local uf2conv=zephyr/scripts/build/uf2conv.py
    python3 "$uf2conv" "$COMBINED" -c -f 0xADA52840 -b "$MCUBOOT_ADDR" \
        -o /tmp/t_echo_recover.uf2
    cp /tmp/t_echo_recover.uf2 "$vol/" && sync
}

PORT=$(boot_port)
if [[ -z "$PORT" ]]; then
    APP=$(app_port)
    if [[ -z "$APP" ]]; then
        hub_cycle
        APP=$(wait_for app_port 15 || true)
        PORT=$(boot_port)
    fi
    if [[ -z "$PORT" && -n "$APP" ]]; then
        touch_1200 "$APP"
        PORT=$(wait_for boot_port 20) || {
            echo "ERROR: bootloader port never appeared after touch" >&2; exit 1; }
    fi
fi
if [[ -z "$PORT" ]]; then
    echo "ERROR: device not recoverable over USB — see manual fallbacks in header" >&2
    exit 1
fi

# -----------------------------------------------------------------------
# Flash. Settle first: DFU packets sent before the freshly-enumerated
# bootloader is ready go unanswered AND wedge it (T-Echo). Long timeout on
# purpose: killing adafruit-nrfutil mid-transfer wedges it the same way.
# Success is judged by the app enumerating, NOT by nrfutil's exit code —
# adafruit-nrfutil exits 0 on some transfer failures.
# -----------------------------------------------------------------------
echo "==> Serial DFU flash on $PORT..."
sleep 5
timeout 400 adafruit-nrfutil dfu serial \
    --package "$DFU_ZIP" -p "$PORT" -b 115200 --singlebank || true

echo "==> Waiting for app to enumerate..."
if ! APP=$(wait_for app_port 20); then
    uf2_fallback || { echo "ERROR: all flash paths failed" >&2; exit 1; }
    APP=$(wait_for app_port 25) || {
        echo "ERROR: app port did not come back after UF2 flash" >&2; exit 1; }
fi
echo "Done: $APP"
