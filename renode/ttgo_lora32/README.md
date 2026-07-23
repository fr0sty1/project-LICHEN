# TTGO LoRa32 Renode Support

Renode platform files for TTGO LoRa32 (ESP32 + SX1276) board.

## Files
- `ttgo_lora32.repl`: Platform definition including esp32_lichen base + SX1276 on SPI3 (per upstream DTS).
- `ttgo_lora32.resc`: Script to load ELF, start CPU, attach analyzer.
- This README.

## Usage
```
renode -e 's @ttgo_lora32.resc'
```

The puck ELF should boot to PRE_KERNEL_1 blink, APPLICATION beeps, and CoAP marker in logs. Interop with lichen-sim verified for TX/RX.

Mimics heltec_wifi_lora32_v3 style. Requires updated SX127x peripheral model and esp32_lichen base (g80o.1/g80o.2).

See renode-workflow.md for full workflow and ELF path adjustments.
