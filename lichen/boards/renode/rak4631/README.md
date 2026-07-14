# RAKWireless RAK4631 for Renode

Renode board definition for the RAK4631 WisBlock (nRF52840 + SX1262).

## Usage

```bash
# Start lichen-sim
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/rak4631/support/rak4631.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Peripherals

| Peripheral | Status | Notes |
|-----------|--------|-------|
| SX1262 radio | Working | Via lichen-sim TCP bridge |
| LEDs (2x) | Working | P1.3 (green), P1.4 (blue), active-low |
| QSPI flash | Not implemented | Add if needed |

## GPIO Mapping

From `zephyr/boards/rak/rak4631/rak4631_nrf52840.dts`:

- LED0 (green): P1.3
- LED1 (blue): P1.4
- SX1262 CS: P1.10
- SX1262 RESET: P1.6
- SX1262 BUSY: P1.14
- SX1262 DIO1: P1.15
- SX1262 TX_EN: P1.7
- SX1262 RX_EN: P1.5

## Key Differences from T-Echo

RAK4631 uses different SPI and GPIO configuration compared to T-Echo:

| Feature | T-Echo | RAK4631 |
|---------|--------|---------|
| SPI1 type | `nordic,nrf-spim` (easyDMA) | `nordic,nrf-spi` (legacy) |
| GPIO port | GPIO0 | GPIO1 |
| CS pin | P0.24 | P1.10 |
| RESET pin | P0.25 | P1.6 |
| BUSY pin | P0.17 | P1.14 |
| DIO1 pin | P0.20 | P1.15 |

Because of these differences, RAK4631 has its own standalone platform file
(`rak4631.repl`) rather than extending `nrf52840_lichen.repl`.
