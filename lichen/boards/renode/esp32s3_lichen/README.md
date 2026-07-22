# ESP32-S3 LICHEN Platform for Renode

Renode platform definition for ESP32-S3-based LICHEN devices with external SX1262 radio.

## Supported Boards

- LilyGO T-Deck (ESP32-S3 + SX1262 + keyboard + display)
- Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
- Other ESP32-S3 + SX1262 combinations

## Usage

```bash
# Start lichen-sim first
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/esp32s3_lichen/support/esp32s3_lichen.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Architecture

The platform provides sufficient ESP32-S3 environment for LICHEN ELF execution:

- **CPU** — Xtensa LX7 at 240 MHz (single-core mode for simulation)
- **Lowmem** — 8KB dummy at 0x0 (bootloader vectors/headers)
- **ROM** — 512KB at 0x40000000
- **SRAM** — 512KB at 0x3FC88000 (data) / 0x40370000 (instruction)
- **Flash XIP** — 64MB at 0x42000000 + 16MB cache at 0x3C000000
- **UART0** — Console at 0x60000000
- **SPI2** — SX1262 radio at 0x60024000 (full lichen-sim bridge)

GPIO, timers, I2C, EFUSE, etc. are stubbed with sysbus tags. Updated memory map resolves all unmapped segment errors for canonical Zephyr ESP32-S3 ELFs from bridge, gateway, and puck.

## Limitations

This is a simulation-focused platform, not cycle-accurate hardware emulation:

- Single-core only (no CPU1)
- No WiFi/BLE radio emulation (BT HCI stubbed in DTS)
- GPIO routing is symbolic (SX1262 CS/IRQ/BUSY wired via C# peripheral)
- No display/keyboard/SD emulation for T-Deck (disabled in DTS)
- Peripherals sufficient for LICHEN L2, CoAP, RPL but not full ESP32 feature set

## Files

- `support/esp32s3_lichen.repl` — platform definition
- `support/esp32s3_lichen.resc` — Renode script
- `../peripherals/SX1262.cs` — SX1262 C# peripheral model (shared)
