#!/usr/bin/env bash
# Start RFC2217 serial servers for connected flash/debug targets.
# Servers auto-restart when a device reconnects (handles USB hub power cycling).
# Ctrl-C kills all servers cleanly.
#
# Port assignments:
#   4000 — T3 V1.6.1    usb-1a86_USB_Single_Serial (CH340)
#   4001 — T-Deck       usb-Espressif_USB_JTAG ... -if01  (serial iface, not JTAG -if00)
#   4002 — Heltec V3    usb-Silicon_Labs_CP2102
#   4003 — T-Echo       usb-TTGO_TTGO_eink
#   4004 — T1000-E      usb-Seeed_Studio_T1000-E-BOOT  (UF2 bootloader)
#           OR          usb-LICHEN_Node_*-if00          (LICHEN firmware — LICHEN Native)
#   4005 — T1000-E SMP  usb-LICHEN_Node_*-if02          (LICHEN firmware — mcumgr OTA)
#
# T1000-E ports 4004/4005 switch between the UF2 bootloader and LICHEN firmware.
# Use smp-flash.py rfc2217://localhost:4005 <firmware.signed.bin> for OTA updates.

set -euo pipefail

SCRIPT="$(dirname "$0")/modules/hal/espressif/tools/esptool_py/esp_rfc2217_server.py"

if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: rfc2217 server not found at $SCRIPT" >&2
    exit 1
fi

BY_ID="/dev/serial/by-id"

declare -A PORTS=(
    [4000]="$BY_ID/usb-1a86_USB_Single_Serial_583A002544-if00"
    [4001]="$BY_ID/usb-Espressif_USB_JTAG_serial_debug_unit_3C:84:27:CA:A7:E8-if01"
    [4002]="$BY_ID/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0"
    [4003]="$BY_ID/usb-TTGO_TTGO_eink_2BE0BCC87606D748-if00"
    # T1000-E: watch_server picks up whichever state is present.
    # T1000-E appears under different names depending on firmware state:
    #   UF2 bootloader:      usb-Seeed_Studio_T1000-E-BOOT_...-if00
    #   MCUboot/recovery:    usb-Seeed_Studio_T1000-E_...-if00
    #   LICHEN firmware:     usb-LICHEN_Node_...-if00  (LICHEN Native, console)
    [4004]="$BY_ID/usb-Seeed_Studio_T1000-E_891FA3226B7B0D14-if00"
    [4005]="$BY_ID/usb-LICHEN_Node_891FA3226B7B0D14-if02"
)

declare -A LABELS=(
    [4000]="T3 V1.6.1    "
    [4001]="T-Deck       "
    [4002]="Heltec V3    "
    [4003]="T-Echo       "
    [4004]="T1000-E boot "
    [4005]="T1000-E SMP  "
)

port_free() {
    ! ss -tlnp 2>/dev/null | grep -q ":${1} "
}

watch_server() {
    local port="$1"
    local dev="${PORTS[$port]}"
    local label="${LABELS[$port]}"
    local pid=""

    # Kill the python3 child whenever this subshell exits for any reason.
    _cleanup() { [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; }
    trap _cleanup EXIT

    while true; do
        until [[ -e "$dev" ]]; do sleep 1; done
        until port_free "$port"; do sleep 1; done

        python3 "$SCRIPT" -p "$port" "$dev" &
        pid=$!
        echo "[$(date '+%H:%M:%S')] START $label :$port  pid=$pid"

        wait "$pid" 2>/dev/null || true
        pid=""
        echo "[$(date '+%H:%M:%S')] DOWN  $label :$port — will restart when device reconnects"
    done
}

# Collect watcher PIDs *before* any forking so the parent always owns them.
WATCHER_PIDS=()
for port in "${!PORTS[@]}"; do
    watch_server "$port" &
    WATCHER_PIDS+=($!)
done

stop_all() {
    echo ""
    echo "Stopping all servers..."
    kill "${WATCHER_PIDS[@]}" 2>/dev/null || true
    wait "${WATCHER_PIDS[@]}" 2>/dev/null || true
    exit 0
}
trap stop_all SIGINT SIGTERM

echo "Watching for devices on ports 4000-4005..."
echo "Press Ctrl-C to stop all."
echo ""

wait
