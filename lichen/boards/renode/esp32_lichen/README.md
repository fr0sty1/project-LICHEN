# ESP32 LICHEN Platform for Renode

Renode platform definition for classic ESP32-based LICHEN devices with external SX1276 radio.

## Supported Boards

- LilyGO TTGO LoRa32 (ESP32 + SX1276)
- Other ESP32 + SX127x combinations

## Usage

```bash
# Start lichen-sim first
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/esp32_lichen/support/esp32_lichen.resc \
    -e "\$elf=@build/ttgo_lora32/zephyr/zephyr.elf; start"
```

## Architecture

The platform provides sufficient ESP32 environment for LICHEN ELF execution:

- **CPU** — Xtensa LX6 at 240 MHz (single-core mode for simulation; cpuType="esp32")
- **Lowmem** — 8KB dummy at 0x0 (bootloader vectors/headers)
- **ROM** — ~448KB at 0x40000000
- **SRAM** — ~180KB DRAM at 0x3FFB0000 + IRAM at 0x40080000
- **Flash mapping** — 64MB at 0x3F800000 (XIP/cache window)
- **UART0** — Console at 0x3FF40000
- **SPI3** — SX1276 radio at 0x3FF65000 (STM32SPI proxy + lichen-sim bridge)

GPIO, RTC_CNTL, EFUSE (MAC/strap), timers, SYSTEM, WDT etc. stubbed via sysbus tags. Memory map and tags adjusted from ESP32 TRM + Zephyr dtsi (esp32_common.dtsi) to eliminate unmapped accesses for ttgo_lora32_esp32_procpu ELFs.

## Limitations

Simulation-focused, not cycle-accurate:

- Single-core only (no CPU1, no dual-core sync)
- No WiFi/BLE (stubbed in DTS)
- GPIO symbolic (no real pin wiring for LED/button/OLED)
- Peripherals sufficient for LICHEN (L2 link, CoAP, RPL, SX1276 TX/RX) but not full ESP32 set
- SX1276 uses shared C# peripheral from peripherals/SX127x.cs

## Files

- `support/esp32_lichen.repl` — platform definition (memory, CPU, UART, SPI proxy, tags)
- `support/esp32_lichen.resc` — Renode load script
- Used by `../ttgo_lora32/support/ttgo_lora32.repl` (do not touch other files per bead)

Modeled exactly after `esp32s3_lichen` with ESP32-specific adjustments.
