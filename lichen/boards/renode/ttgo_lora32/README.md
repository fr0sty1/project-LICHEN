# TTGO LoRa32 for Renode

Renode board definition for the TTGO LoRa32 (ESP32 + SX1276).

## Usage

```bash
# Start lichen-sim
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/ttgo_lora32/support/ttgo_lora32.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1276 radio | Working | Via lichen-sim TCP bridge on SPI3 |
| LED | Stubbed | GPIO2 |
| Button | Not implemented | GPIO0 |
| OLED (some variants) | Not implemented | I2C |

## GPIO Mapping

Per upstream DTS for ttgo_lora32_esp32_procpu and TTGO schematic:

- SX1276 on SPI3 (SCK=GPIO18, MISO=GPIO19, MOSI=GPIO23, CS=GPIO5)
- RESET = GPIO14, DIO0 = GPIO2 (IRQ), etc.
- Base esp32_lichen stubs GPIO.

## Hardware Reference

- MCU: ESP32 (dual-core Xtensa LX6 @ 240 MHz)
- Radio: Semtech SX1276
- Flash: 4-16MB
- LoRa: 868/915MHz

Mimics heltec_wifi_lora32_v3 style exactly. ELF loads to CoAP marker with lichen-sim.
