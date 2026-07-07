# LilyGO T-Deck for Renode

Renode board definition for the LilyGO T-Deck (ESP32-S3 + SX1262 + display + keyboard).

## Usage

```bash
# Start lichen-sim
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/t_deck/support/t_deck.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1262 radio | Working | Via lichen-sim TCP bridge |
| UART0 console | Working | TX=GPIO43, RX=GPIO44 |
| ST7789 display | Stub | 240x320, SPI3 CS1 (GPIO12), DC=GPIO11 |
| Keyboard | Stub | I2C0 addr 0x55 |
| Trackball | Stub | I2C1 |
| SD card | Stub | SPI3 CS2 (GPIO39) |
| Backlight | Stub | GPIO42 |
| Peripheral power | Stub | GPIO10 (enables all peripherals) |

## GPIO Mapping

From `lichen/boards/lilygo/t_deck/t_deck_esp32s3_procpu.dts`:

### SPI3 (shared bus)
- SCK: GPIO40
- MOSI: GPIO41
- MISO: GPIO38
- CS0 (LoRa): GPIO9
- CS1 (Display): GPIO12
- CS2 (SD): GPIO39

### SX1262 LoRa
- RESET: GPIO17
- BUSY: GPIO13
- DIO1: GPIO45

### Display (ST7789)
- DC: GPIO11
- Backlight: GPIO42

### Other
- Peripheral power enable: GPIO10
- Boot button: GPIO0

## Limitations

The display, keyboard, and trackball are stubbed with memory tags. They do not provide functional emulation - firmware will see them as present but unresponsive. This is sufficient for LoRa protocol testing where UI interaction is not required.

For display/input bring-up testing, use real hardware or extend this platform with proper peripheral models.
