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

The platform provides a minimal ESP32-S3 environment:

- **CPU** — Xtensa LX7 at 240 MHz (single-core mode for simulation)
- **SRAM** — 512KB at 0x3FC88000 (data) / 0x40370000 (instruction)
- **ROM** — 384KB at 0x40000000
- **Flash cache** — 16MB at 0x3C000000 (XIP region)
- **UART0** — Console at 0x60000000
- **SPI2** — SX1262 radio at 0x60024000

GPIO, I2C, and other peripherals are stubbed with memory tags.

## Limitations

This is a simulation-focused platform, not cycle-accurate hardware emulation:

- Single-core only (no CPU1)
- No WiFi/BLE radio emulation
- GPIO routing is symbolic (the SX1262 bridges directly to lichen-sim)
- No display/keyboard emulation (T-Deck peripherals)

## Files

- `support/esp32s3_lichen.repl` — platform definition
- `support/esp32s3_lichen.resc` — Renode script
- `../peripherals/SX1262.cs` — SX1262 C# peripheral model (shared)
