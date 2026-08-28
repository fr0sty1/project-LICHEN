# LICHEN — Zephyr West Workspace

T2 topology: this `zephyr/` directory is the west manifest repository.
Zephyr v3.7.0 (LTS) and all modules are fetched as dependencies.

## Prerequisites

- [west](https://docs.zephyrproject.org/latest/develop/west/install.html) (`pip install west`)
- [Zephyr SDK](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html) (≥ 0.16)
- `arm-zephyr-eabi` toolchain — for nRF52840 (rak4631) and STM32WL (nucleo_wl55jc) targets
- `xtensa-espressif_esp32s3_zephyr-elf` toolchain — for ESP32-S3 targets (heltec_wifi_lora32_v3/esp32s3/procpu)

## Initialise workspace

Run these commands from the workspace root:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install west "setuptools<81"
west init -l lichen/
west update
west zephyr-export
pip install -r zephyr/scripts/requirements.txt
```

Zephyr 3.7 Twister imports `pkg_resources`, which is provided by older
`setuptools` releases. Keep `.venv/bin` first on `PATH` when running
`west twister`; CMake also uses `python3` from `PATH` for Zephyr helper
scripts. If `west` was installed with `pipx` instead of the venv above, install
the same dependencies into west's isolated environment:

```sh
pipx runpip west install -r "$PWD/zephyr/scripts/requirements.txt" "setuptools<81"
```

## Build

All `west build` commands are run from the workspace root (the directory
containing `zephyr/`, `lichen/`, etc. after `west init`).

### Puck (field device)

```sh
# RAK4631 — nRF52840 + SX1262
west build -b rak4631/nrf52840 lichen/apps/puck

# Heltec LoRa32 v3 — ESP32-S3 + SX1262
west build -b heltec_wifi_lora32_v3/esp32s3/procpu lichen/apps/puck
# Note: T-Beam Supreme is BLOCKED (no canonical board definition); see
# project-LICHEN-w8rd and tbeam_supreme.* fragments for details.
```

### Gateway (border router / dev target)

```sh
# Nucleo-WL55JC — STM32WL55 with built-in sub-GHz radio
west build -b nucleo_wl55jc lichen/apps/gateway

# native_sim — simulation target, uses TCP LoRa stub
west build -b native_sim lichen/apps/gateway
```

## Flash

```sh
west flash
```

For native_sim, just run the produced ELF directly:
```sh
./build/zephyr/zephyr.exe
```

The standalone C frame tests run locally with CMake on macOS. Zephyr
`native_sim` tests require a Linux host in the current Zephyr setup; run those
on the project EC2 builder when local native_sim is unavailable.

## Memory Budget

STM32WL55 (nucleo_wl55jc) — 256 KB flash, 64 KB RAM:

| Component | Flash | RAM |
|-----------|-------|-----|
| Zephyr kernel + IPv6 + CoAP + STM32WL LoRa (2026-06-24 baseline) | 78 KB (30%) | 30 KB (47%) |
| **Budget for LICHEN protocol** | **~140 KB** | **~20 KB** |

Build command:
```sh
ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb GNUARMEMB_TOOLCHAIN_PATH=/opt/homebrew \
  west build -b nucleo_wl55jc lichen/apps/gateway
```

The link + L2 component budget is machine checked conservatively by summing
their STM32WL static archives before linker garbage collection.  The
2026-08-27 measurement with Zephyr SDK 0.16.8/GCC 12.2 was 34,188 bytes flash
and 13,287 bytes RAM against the protocol-layer limits above.  The RAM figure
includes the 8,256-byte guarded LoRa RX stack and the 1,248-byte four-frame TX
queue/pool.  The frame-pool code itself is 480 bytes of flash and owns no
separate global storage.

Use the target toolchain's `size` executable so host architecture does not
affect the result:

```sh
export ZEPHYR_SIZE="$ZEPHYR_SDK_INSTALL_DIR/arm-zephyr-eabi/bin/arm-zephyr-eabi-size"
python3 scripts/check_zephyr_memory.py \
  --artifact build/modules/lichen/subsys/lichen/link/liblichen_link.a \
  --artifact build/modules/lichen/subsys/lichen/l2/liblichen_l2.a \
  --flash-limit $((140 * 1024)) --ram-limit $((20 * 1024))
```

Archive filenames are generator-dependent; pass the actual two paths from the
build tree.  For a release image, pass `build/zephyr/zephyr.elf` alone with the
board limits `--flash-limit $((220 * 1024)) --ram-limit $((50 * 1024))`.
The checker emits one JSON record and exits nonzero on a missing artifact,
unparseable tool output, or exceeded budget.  Full-image figures must come
from the pinned Zephyr v3.7 release build; the 4.1 local workspace is only a
component smoke check and does not replace that release gate.

## Directory layout

```
zephyr/              ← this repo (west manifest)
  west.yml
  apps/
    puck/            ← field-device application
    gateway/         ← border-router / SLIP-bridge application
```
