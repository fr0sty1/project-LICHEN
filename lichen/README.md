# LICHEN — Zephyr West Workspace

T2 topology: `lichen/` is the west manifest repository. The Zephyr RTOS
checks out alongside it at `zephyr/`. Zephyr v3.7.0 (LTS).

## Prerequisites

- [west](https://docs.zephyrproject.org/latest/develop/west/install.html) (`pip install west`)
- [Zephyr SDK](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html) (≥ 0.16)
- `arm-zephyr-eabi` toolchain — for nRF52840 (rak4631) and STM32WL (nucleo_wl55jc) targets
- `xtensa-espressif_esp32s3_zephyr-elf` toolchain — for ESP32-S3 targets (heltec_lora32_v3, tbeam_supreme)

## Initialise workspace

Run from **inside** `project-LICHEN/` (delete `.west/` first if retrying):

```sh
cd project-LICHEN
rm -rf .west          # if retrying after a failed west update
west init -l lichen/
west update           # clones Zephyr into zephyr/ alongside lichen/
west zephyr-export
pip install -r zephyr/scripts/requirements.txt
```

`.west/` is created inside `project-LICHEN/`, making it the workspace root.
All subsequent `west` commands must be run from there.

## Build

All `west build` commands are run from `project-LICHEN/` (the workspace root).

### Puck (field device)

```sh
# RAK4631 — nRF52840 + SX1262
west build -b rak4631_nrf52840 lichen/apps/puck

# Heltec LoRa32 v3 — ESP32-S3 + SX1262
west build -b heltec_lora32_v3 lichen/apps/puck

# T-Beam Supreme — ESP32-S3 + SX1262
west build -b tbeam_supreme lichen/apps/puck
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

For native_sim, run the ELF directly:
```sh
./build/zephyr/zephyr.exe
```

## Directory layout

After `west update`:

```
project-LICHEN/
  .west/               ← workspace config
  lichen/              ← this repo (west manifest)
    west.yml
    apps/
      puck/            ← field-device application
      gateway/         ← border-router / SLIP-bridge application
  zephyr/              ← Zephyr RTOS (fetched by west update)
```
