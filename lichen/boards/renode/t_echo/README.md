# LilyGO T-Echo for Renode

Renode board definition for the LilyGO T-Echo (nRF52840 + SX1262).

## Usage

```bash
# Start lichen-sim
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/t_echo/support/t_echo.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1262 radio | Working | Via lichen-sim TCP bridge |
| LEDs (3x) | Working | P0.13/14/15, active-low |
| Button | Working | P1.10 |
| E-ink display | Not implemented | Add if needed |
| GPS (L76K) | Not implemented | See `samz` task |

## GPIO Mapping

From `lichen/boards/lilygo/t_echo/t_echo_nrf52840.dts`:

- LED0 (green): P0.13
- LED1 (red): P0.14
- LED2 (blue): P0.15
- Button: P1.10
- SX1262 CS: P0.24 (via SPI2 in Renode)
- SX1262 RESET: P0.25
- SX1262 BUSY: P0.17
- SX1262 DIO1: P0.20
