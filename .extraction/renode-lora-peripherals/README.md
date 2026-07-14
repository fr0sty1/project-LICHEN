# Renode LoRa Peripherals

Renode peripheral models for Semtech LoRa transceivers. Enables LoRa firmware testing in Renode without hardware.

## Supported Peripherals

| Peripheral | Chip | Status |
|------------|------|--------|
| SX1262 | Semtech SX1262 | Functional |
| LR1110 | Semtech LR1110 | Planned |

## Quick Start

### 1. Copy the peripheral to your Renode installation

```bash
cp peripherals/sx126x/SX1262.cs /path/to/renode/
```

Or load it dynamically in your `.resc` script:

```
include @path/to/SX1262.cs
```

### 2. Wire the peripheral in your `.repl`

```
// Attach to SPI bus
sx1262: Wireless.SX1262 @ spi1
    loopback: true      // Single-node testing, no external sim

// Wire GPIO pins (adapt to your board)
gpio0:
    6 -> sx1262@0       // RESET
    10 -> sx1262@1      // CS (for SPI framing)

sx1262:
    IRQ -> gpio0@15     // DIO1/IRQ
    Busy -> gpio0@14    // BUSY
```

See `examples/sx1262_example.repl` for a complete nRF52840 example.

### 3. Run your firmware

```bash
renode -e 'include @your_platform.resc; start'
```

## Operating Modes

### Loopback Mode (Single-Node Testing)

In loopback mode, transmitted data is copied to the receive buffer. Useful for:
- Driver bring-up and opcode verification
- Testing TX/RX interrupt handling
- CI pipelines without external dependencies

```
sx1262: Wireless.SX1262 @ spi1
    loopback: true
```

Or switch at runtime:
```
spi1.sx1262 Loopback true
```

### Bridge Mode (Multi-Node Simulation)

Bridge mode connects to an external RF simulator via TCP. Each Renode instance connects to its own port on the simulator, which models RF propagation between nodes.

```
sx1262: Wireless.SX1262 @ spi1
    simHost: "127.0.0.1"
    simPort: 5555
    loopback: false
```

Override port at runtime:
```
spi1.sx1262 SimPort 5556
```

## SPI Opcode Coverage

The peripheral intercepts these SX1262 SPI opcodes:

| Opcode | Command | Behavior |
|--------|---------|----------|
| 0x0E | WriteBuffer | Stores data in TX buffer |
| 0x1E | ReadBuffer | Reads from RX buffer |
| 0x83 | SetTx | Triggers transmission |
| 0x82 | SetRx | Enters receive mode |
| 0xC0 | GetStatus | Returns simulated status |
| 0x12 | GetIrqStatus | Returns IRQ flags |
| 0x02 | ClearIrqStatus | Clears IRQ flags |
| 0x13 | GetRxBufferStatus | Returns RX length |
| 0x14 | GetPacketStatus | Returns RSSI/SNR |
| 0x80 | SetStandby | Exits RX mode |
| 0x8A | SetModulationParams | Acknowledged, ignored |
| 0x8B | SetPacketParams | Acknowledged, ignored |
| 0x08 | SetDioIrqParams | Acknowledged, ignored |

Configuration commands (frequency, power, modulation) are acknowledged but their values are not used - the simulation does not model RF physics at that level.

## GPIO Interface

### Inputs (OnGPIO)

| Input | Function |
|-------|----------|
| 0 | RESET (active low) |
| 1 | CS (for SPI transaction framing) |

### Outputs

| Output | Function |
|--------|----------|
| IRQ | Interrupt request (DIO1) |
| Busy | Busy status line |

## Bridge Protocol

For multi-node simulation, the peripheral communicates with an external RF simulator using a simple binary protocol over TCP.

All messages are length-prefixed (4-byte little-endian length, then payload).

### Messages

| Type | Code | Direction | Payload |
|------|------|-----------|---------|
| TX | 0x10 | -> Sim | len:2 + data |
| TX_DONE | 0x11 | <- Sim | airtime_us:4 |
| RX_ENTER | 0x24 | -> Sim | timeout_us:4 |
| RX_EXIT | 0x26 | -> Sim | (none) |
| RX_PACKET | 0x27 | <- Sim | len:2 + data + rssi:2 + snr:2 |
| RX_TIMEOUT | 0x28 | <- Sim | (none) |

See `docs/bridge_protocol.md` for full specification.

## License

Apache-2.0
