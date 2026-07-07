# Heltec WiFi LoRa32 V3 for Renode

Renode board definition for the Heltec WiFi LoRa32 V3 (ESP32-S3 + SX1262).

## Usage

```bash
# Start lichen-sim
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/heltec_wifi_lora32_v3/support/heltec_wifi_lora32_v3.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1262 radio | Working | Via lichen-sim TCP bridge |
| LED (white) | Stubbed | GPIO35, not wired (GPIO is memory tag) |
| Button | Not implemented | GPIO0 |
| OLED display | Not implemented | I2C, SSD1306 |

## GPIO Mapping

From Heltec V3 schematic and Zephyr heltec_wireless_stick_lite_v3:

- LED (white): GPIO35
- Button (PRG): GPIO0
- Vext control: GPIO36 (powers OLED/sensors)
- ADC control: GPIO37
- SX1262 RESET: GPIO12
- SX1262 BUSY: GPIO13
- SX1262 DIO1: GPIO14
- SX1262 CS: SPI2 (via Renode)

## Hardware Reference

- MCU: ESP32-S3 (dual-core Xtensa LX7 @ 240 MHz)
- Radio: Semtech SX1262
- Flash: 8MB
- PSRAM: 8MB
- Display: 0.96" OLED SSD1306 (128x64)
