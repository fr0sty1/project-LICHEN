# nRF52840 LICHEN Platform for Renode

Renode platform definition for nRF52840-based LICHEN devices with external SX1262 radio.

## Supported Boards

- LilyGO T-Echo (`../t_echo/`) — validated (boot, SPI, L2 init, LoRa TX).
- RAK4631 (`../rak4631/`) — **not yet functional in Renode.** The shared
  platform wiring is T-Echo-specific (gpio0, easyDMA SPIM); the real RAK4631
  wires the SX1262 on gpio1 and uses the legacy `nordic,nrf-spi` controller.
  Tracked by bead `project-LICHEN-r7h4.9`.

## Installing Renode

Renode 1.16.1 was used for validation. On x86_64 Linux use the portable
release; on arm64 (e.g. AWS Graviton) use the arm64 dotnet-portable build:

```bash
# arm64
curl -L -o renode.tar.gz \
  https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-arm64-portable-dotnet.tar.gz
mkdir -p ~/renode && tar -xzf renode.tar.gz -C ~/renode --strip-components=1
# If libicu is not installed, run with invariant globalization:
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
~/renode/renode --version
```

## Building Firmware for Renode

The T-Echo/RAK4631 console defaults to Segger RTT, which Renode cannot capture
headlessly. Build with the Renode console overlay/conf so the console is routed
to UARTE0:

```bash
# From the repo root; SOURCE_DATE_EPOCH is required by the build-epoch check.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
west build -b t_echo/nrf52840 lichen/apps/puck -d build/t_echo_renode -p always -- \
  -DBOARD_ROOT="$PWD/lichen" \
  -DZEPHYR_EXTRA_MODULES="$PWD/lichen" \
  -DEXTRA_DTC_OVERLAY_FILE="$PWD/lichen/boards/renode/nrf52840_lichen/support/renode_console.overlay" \
  -DEXTRA_CONF_FILE="$PWD/lichen/boards/renode/nrf52840_lichen/support/renode_console.conf"
```

`test_mesh.py` and `run_multi_node.py` look for `build/<board>_renode/zephyr/zephyr.elf`
first, then `build/<board>/...`, then `build/zephyr/...`.

## Single Node Usage

```bash
renode lichen/boards/renode/t_echo/support/t_echo.resc \
    -e "\$elf=@build/t_echo_renode/zephyr/zephyr.elf; start"
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
# Run mesh tests (requires firmware built as above)
cd python && uv run pytest ../lichen/boards/renode/nrf52840_lichen/test_mesh.py -v
```

## Architecture

The platform extends Renode's stock `nrf52840.repl`:

- **SPI1** at 0x40004000 — hosts the SX1262. Renode's stock platform models this
  address as `twi1` (I2C); the LICHEN platform replaces it with an SPI
  controller because the T-Echo/RAK4631 firmware drives the radio on SPI1.
- **easyDMA: true** on the SPI controller so the SPIM (EasyDMA) register set is
  modeled — Zephyr's `nordic,nrf-spim` driver requires it.
- **FICR DEVICEID** is tagged with a non-zero value so `hwinfo` returns a stable
  hardware ID (LICHEN L2 refuses to start otherwise).
- **SX1262** — SPI peripheral that bridges TX/RX to lichen-sim over TCP. It
  resets its opcode state machine on CS (cs-gpios) deassert, because Renode's
  SPIM EasyDMA controller does not call `FinishTransmission` between transfers.

## Validation Status (Renode 1.16.1, linux-arm64)

Validated by bead `project-LICHEN-r7h4.5`:

- ✅ Boot — Zephyr boots, console observable on UARTE0 via the Renode overlay.
- ✅ SPI — firmware drives the SX1262 (real opcodes reach the peripheral).
- ✅ L2 init — `lora_l2` initializes; IPv6 link-local address derived.
- ✅ LoRa TX — beacons reach lichen-sim (`metrics.transmissions > 0`, correct airtime).
- ⚠️ LoRa RX — sim→bridge delivery works, but the firmware does not yet receive
  frames. `SX1262.cs` polls RX only once at `SetRx` (needs continuous polling +
  RxDone IRQ — bead `project-LICHEN-r7h4.6`), and the bridge/sim time-model
  interaction is unresolved (bead `project-LICHEN-r7h4.7`).

## Files

- `support/nrf52840_lichen.repl` — base platform definition
- `support/nrf52840_lichen.resc` — base Renode script
- `support/renode_console.overlay` / `.conf` — route console to UARTE0 for Renode
- `run_multi_node.py` — multi-node simulation launcher
- `test_mesh.py` / `conftest.py` — pytest-based boot + TX tests
- `../peripherals/SX1262.cs` — SX1262 C# peripheral model (shared)
