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

## Validation (project-LICHEN-27vk)

Basic Renode simulation validated:
- CPU starts (Xtensa LX7 @ 240 MIPS)
- UART0 console works (showAnalyzer shows Zephyr boot, "LICHEN" messages)
- SX1262 connects to lichen-sim (SimPort 5555, "Connected to lichen-sim")
- Basic TX works (lichen-sim receives frames when using puck/gateway with LORA_L2)

Run with:
```bash
lichen-sim --node-port 5555
renode lichen/boards/renode/heltec_wifi_lora32_v3/support/heltec_wifi_lora32_v3.resc \
  -e "\$elf=build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1262 radio | Working | Via lichen-sim TCP bridge; basic TX/RX validated |
| LED (white) | Stubbed | GPIO35, not wired (GPIO is memory tag) |
| Button (PRG) | Not implemented | GPIO0 |
| OLED display | Not implemented | I2C SSD1306 (no Renode model) |

## ESP32-S3 Renode Limitations

- Single-core only (no CPU1 support in model)
- No cycle-accurate timing (LoRa timing approximations via lichen-sim)
- GPIO fully stubbed (memory tags; no interrupt or LED toggle emulation)
- No I2C/display/keyboard support (OLED, buttons ignored)
- ELF loading requires careful memory map; some Zephyr sections map to tagged regions
- No WiFi/BLE radio (focus is LoRa + UART console only)
- Best used with `lichen-sim` for L2 validation; full CoAP/gateway needs physical hardware for complete proof

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
