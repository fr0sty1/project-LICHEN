# nRF52840 LICHEN Platform for Renode

Renode platform definition for nRF52840-based LICHEN devices with external SX1262 radio.

## Supported Boards

- LilyGO T-Echo (`../t_echo/`)
- RAK4631 (`../rak4631/`)

## Single Node Usage

```bash
# Start lichen-sim first
lichen-sim --node-port 5555 --api-port 5556

# Run in Renode
renode lichen/boards/renode/t_echo/support/t_echo.resc \
    -e "\$elf=@build/zephyr/zephyr.elf; start"
```

## Multi-Node Simulation

```bash
# 2x T-Echo nodes (default)
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py

# 3x T-Echo nodes
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py 3

# Mixed topology: T-Echo + RAK4631
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py t_echo rak4631
```

## Pytest Integration

```bash
# Run mesh tests (requires firmware built)
pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py -v

# With different board/node count
pytest ... --board=rak4631 --nodes=3
```

## Architecture

The platform extends Renode's stock `nrf52840.repl` with:

- **SPI2** at 0x40023000 — hosts SX1262 radio (SPI1/TWI1 conflict avoided)
- **SX1262** — magic SPI peripheral that bridges TX/RX to lichen-sim via TCP

GPIO wiring (RESET, BUSY, DIO1) is simulated; actual pin routing doesn't matter
since the SX1262 peripheral bridges directly to the simulation.

## Files

- `support/nrf52840_lichen.repl` — base platform definition
- `support/nrf52840_lichen.resc` — base Renode script
- `run_multi_node.py` — multi-node simulation launcher
- `test_mesh.py` — pytest-based mesh tests
- `../peripherals/SX1262.cs` — SX1262 C# peripheral model (shared)
