# LICHEN — Zephyr West Workspace

T2 topology: this `zephyr/` directory is the west manifest repository.
Zephyr v3.7.0 (LTS) and all modules are fetched as dependencies.

## Prerequisites

- [west](https://docs.zephyrproject.org/latest/develop/west/install.html) (`pip install west`)
- [Zephyr SDK](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html) (≥ 0.16)
- `arm-zephyr-eabi` toolchain — for nRF52840 (rak4631) and STM32WL (nucleo_wl55jc) targets
- `xtensa-espressif_esp32s3_zephyr-elf` toolchain — for ESP32-S3 targets (heltec_lora32_v3, tbeam_supreme)

## Initialise workspace

Run these commands from the directory **above** `project-LICHEN/`:

```sh
west init -l project-LICHEN/zephyr/
west update
west zephyr-export
pip install -r zephyr/scripts/requirements.txt
```

## Build

All `west build` commands are run from the workspace root (the directory
containing `zephyr/`, `lichen/`, etc. after `west init`).

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

For native_sim, just run the produced ELF directly:
```sh
./build/zephyr/zephyr.exe
```

## Directory layout

```
zephyr/              ← this repo (west manifest)
  west.yml
  apps/
    puck/            ← field-device application
    gateway/         ← border-router / SLIP-bridge application
```
