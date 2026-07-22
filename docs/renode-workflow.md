# Renode Development Workflow

This guide covers using Renode to simulate LICHEN mesh firmware with the lichen-sim RF simulator.

## Overview

The LICHEN project uses Renode for pre-hardware firmware testing. The simulation stack:

```
+------------------+     +------------------+
| Renode           |     | Renode           |
| (nRF52840 + FW)  |     | (nRF52840 + FW)  |
| SX1262 --------->|--+--|<-------- SX1262  |
+------------------+  |  +------------------+
                      |
                +-----v-----+
                | lichen-sim|
                | (RF sim)  |
                +-----------+
```

- **Renode** emulates the MCU (nRF52840, STM32WL) and runs the Zephyr firmware
- **SX1262.cs** is a custom Renode peripheral that bridges the SPI radio interface to lichen-sim via TCP
- **lichen-sim** handles RF propagation, collision detection, and provides realistic link-layer behavior

## Installing Renode

### macOS (Homebrew)

```bash
brew install renode
```

### Ubuntu/Debian (apt)

```bash
# Add Renode repository
wget https://builds.renode.io/renode.gpg
sudo install renode.gpg /etc/apt/trusted.gpg.d/
echo 'deb [arch=amd64] https://builds.renode.io/ nightly /' | sudo tee /etc/apt/sources.list.d/renode.list

# Install
sudo apt update
sudo apt install renode
```

### From Source

```bash
git clone https://github.com/renode/renode.git
cd renode
./build.sh
# Binary at output/bin/Release/Renode.exe (mono) or renode (Linux)
```

### Verify Installation

```bash
renode --version
# Expected: Renode, version X.X.X
```

## Running Single-Node Simulation

### 1. Start lichen-sim

The RF simulator must be running before Renode connects:

```bash
# Basic usage (default ports)
lichen-sim --node-port 5555 --api-port 5556

# With debug logging
lichen-sim --node-port 5555 --api-port 5556 --log-level DEBUG

# With packet capture
lichen-sim --node-port 5555 --api-port 5556 --pcap capture.pcapng
```

### 2. Build Firmware

```bash
# From the lichen/ directory (Zephyr workspace)
west build -b t_echo/nrf52840 lichen/apps/puck -d build/t_echo

# Or for RAK4631
west build -b rak4631/nrf52840 lichen/apps/puck -d build/rak4631
```

### 3. Run in Renode

```bash
# T-Echo board
renode lichen/boards/renode/t_echo/support/t_echo.resc \
    -e "\$elf=@build/t_echo/zephyr/zephyr.elf; start"

# RAK4631 board
renode lichen/boards/renode/rak4631/support/rak4631.resc \
    -e "\$elf=@build/rak4631/zephyr/zephyr.elf; start"

# TTGO LoRa32 (ESP32+SX1276) - new Renode backend (g80o)
renode lichen/boards/renode/ttgo_lora32/support/ttgo_lora32.resc \
    -e "\$elf=@build/ttgo_lora32/zephyr/zephyr.elf; start"
```

### 4. Interact

The Renode console shows UART output. In the Renode Monitor window you can:

```
# Pause/resume simulation
pause
start

# Check simulation time
machine GetTimeSourceInfo

# View CPU registers
cpu PC
cpu GetRegisters

# Interact with peripherals
sysbus ReadByte 0x40000000
```

## Running Multi-Node Mesh Simulation

The `run_multi_node.py` script automates launching multiple Renode instances with coordinated lichen-sim connections.

### Basic Usage

```bash
# 2x T-Echo nodes (default)
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py

# 3x T-Echo nodes
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py 3

# Mixed topology: T-Echo + RAK4631
python3 lichen/boards/renode/nrf52840_lichen/run_multi_node.py t_echo rak4631
```

### What It Does

1. Starts lichen-sim with nodes positioned 50m apart in a line
2. Launches one Renode instance per node on separate ports
3. Connects each node's SX1262 peripheral to lichen-sim
4. Tails UART output from all nodes to the console
5. Cleans up on Ctrl+C

### Node Positioning

Nodes are positioned linearly with 50m spacing:

```
Node 0          Node 1          Node 2
  (0,0,0)        (50,0,0)       (100,0,0)
    |--------------|--------------|
         50m            50m
```

For custom topologies, modify `run_multi_node.py` or use the REST API to reposition nodes after startup.

## Pytest Integration

The test harness runs mesh tests with firmware in Renode:

```bash
# Run all mesh tests
pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py -v

# With different board
pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py --board=rak4631

# With more nodes
pytest lichen/boards/renode/nrf52840_lichen/test_mesh.py --nodes=3
```

### Test Structure

Tests use async fixtures that:
1. Create a lichen-sim `Simulation` instance
2. Start `RenodeServer` instances for each node
3. Launch Renode processes with generated `.resc` scripts
4. Yield control for test assertions
5. Clean up all processes on completion

Example test:

```python
@pytest.mark.asyncio
async def test_mesh_boots(mesh_simulation):
    """Test that all nodes boot successfully."""
    nodes = mesh_simulation["nodes"]
    for node in nodes:
        assert node.proc is not None
        assert node.proc.returncode is None, f"Node {node.node_id} crashed"
```

## Writing Custom Peripherals

Custom peripherals are written in C# and loaded by Renode at runtime.

### File Location

```
lichen/boards/renode/peripherals/
├── SX1262.cs     # LoRa radio (bridges to lichen-sim)
├── BLE.cs        # BLE peripheral (stub)
└── GPS.cs        # GPS peripheral (stub)
```

### C# Patterns

**Basic SPI Peripheral:**

```csharp
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.SPI;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class MyRadio : ISPIPeripheral
    {
        public MyRadio(IMachine machine)
        {
            this.machine = machine;
        }

        public void Reset()
        {
            // Initialize state
        }

        public void FinishTransmission()
        {
            // Called when CS goes high
        }

        public byte Transmit(byte data)
        {
            // Called for each SPI byte
            // Return MISO response
            return 0;
        }

        private readonly IMachine machine;
    }
}
```

**GPIO Handling:**

```csharp
using Antmicro.Renode.Core;

public class MyRadio : ISPIPeripheral, IGPIOReceiver
{
    // Output GPIOs (peripheral -> MCU)
    public GPIO IRQ { get; } = new GPIO();
    public GPIO Busy { get; } = new GPIO();

    // Input GPIOs (MCU -> peripheral)
    public void OnGPIO(int number, bool value)
    {
        if (number == 0 && !value)  // RESET active-low
        {
            Reset();
        }
    }

    // Raise interrupt
    private void RaiseIRQ()
    {
        IRQ.Set(true);
    }
}
```

**TCP Bridge Pattern (like SX1262.cs):**

```csharp
using System.Net.Sockets;

public class MyRadio : ISPIPeripheral
{
    private TcpClient socket;
    private NetworkStream stream;

    private void EnsureConnected()
    {
        if (socket != null && socket.Connected)
            return;

        socket = new TcpClient();
        socket.NoDelay = true;
        socket.ReceiveTimeout = 100;
        socket.Connect("127.0.0.1", simPort);
        stream = socket.GetStream();
        this.Log(LogLevel.Info, "Connected to simulator");
    }

    // Length-prefixed protocol helpers
    private void WriteLE32(byte[] buf, int offset, uint value) { /* ... */ }
    private uint ReadLE32(byte[] buf, int offset) { /* ... */ }
}
```

### Platform Definition (.repl)

Wire the peripheral into the platform:

```
// In your_board.repl
using "platforms/cpus/nrf52840.repl"

// Add custom peripheral on SPI2
myradio: Wireless.MyRadio @ spi2
    simHost: "127.0.0.1"
    simPort: 5555

// Wire GPIO connections
gpio0:
    25 -> myradio@0   // RESET

myradio:
    IRQ -> gpio0@20   // IRQ output
    Busy -> gpio0@17  // BUSY output
```

### Renode Script (.resc)

Load and configure the peripheral:

```
:name: MyBoard

# Load peripheral source
include $ORIGIN/../../peripherals/MyRadio.cs

mach create "myboard"
machine LoadPlatformDescription $ORIGIN/myboard.repl

# Configure peripheral
spi2.myradio SimPort 5555

# Load firmware
sysbus LoadELF $elf

start
```

## Debugging Tips

### Log Levels

Control Renode logging verbosity:

```
# In Renode Monitor
logLevel 0 spi2.sx1262    # NOISY (all)
logLevel 1 spi2.sx1262    # DEBUG
logLevel 2 spi2.sx1262    # INFO
logLevel 3 spi2.sx1262    # WARNING
logLevel 4 spi2.sx1262    # ERROR

# Log all SPI traffic
logLevel 0 spi2
```

In C# peripherals:

```csharp
this.Log(LogLevel.Debug, "TX: {0} bytes", length);
this.Log(LogLevel.Warning, "Connection failed: {0}", ex.Message);
```

### Protocol Analyzers

View bus traffic:

```
# UART analyzer (graphical window)
showAnalyzer uart0

# SPI logging
logLevel 0 spi2

# Log to file (headless)
logFile @/tmp/renode.log true
uart0 CreateFileBackend @/tmp/uart.log true
```

### Common Issues

**Peripheral not found:**
```
Could not find peripheral: Wireless.SX1262
```
Solution: Ensure the `include` path to the `.cs` file is correct in your `.resc` script.

**Connection refused:**
```
Connect failed: Connection refused
```
Solution: Start `lichen-sim` before launching Renode.

**Wrong port:**
```
TX failed: not connected to lichen-sim
```
Solution: Verify the `SimPort` matches what lichen-sim is listening on.

**Simulation doesn't advance:**
Check that:
1. lichen-sim is running
2. The SX1262 peripheral connected successfully (look for "Connected to lichen-sim" in logs)
3. Firmware is calling radio TX/RX operations

### GDB Debugging

Attach GDB to the simulated CPU:

```
# In Renode Monitor
machine StartGdbServer 3333

# In another terminal
arm-none-eabi-gdb build/zephyr/zephyr.elf
(gdb) target remote :3333
(gdb) break main
(gdb) continue
```

## CI Integration

### GitHub Actions Example

```yaml
name: Renode Tests

on: [push, pull_request]

jobs:
  renode-mesh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Renode
        run: |
          wget https://builds.renode.io/renode-latest.linux-portable.tar.gz
          tar xf renode-latest.linux-portable.tar.gz
          echo "$PWD/renode_*_portable" >> $GITHUB_PATH

      - name: Install Python deps
        run: |
          pip install uv
          cd python && uv sync --locked --dev

      - name: Build firmware
        run: |
          # Assumes Zephyr toolchain is cached/installed
          west build -b t_echo/nrf52840 lichen/apps/puck

      - name: Run Renode tests
        run: |
          cd python
          uv run pytest ../lichen/boards/renode/nrf52840_lichen/test_mesh.py -v \
            --timeout=120 --timeout-method=thread
```

### Headless Execution

For CI, run Renode without GUI:

```bash
renode --disable-gui --port 10000 script.resc
```

The `--port` flag sets the Monitor port for scripted control.

### Test Timeouts

Renode tests can hang if:
- lichen-sim is not running
- Firmware enters an infinite loop
- Deadlock in barrier-sync time mode

Always use pytest timeouts:

```bash
pytest --timeout=120 --timeout-method=thread
```

### Artifacts

Capture useful debug artifacts:

```yaml
      - name: Upload logs
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: renode-logs
          path: |
            lichen/boards/renode/nrf52840_lichen/_node*.log
            lichen/boards/renode/nrf52840_lichen/_node*_uart.log
```

## File Reference

| Path | Description |
|------|-------------|
| `lichen/boards/renode/peripherals/SX1262.cs` | SX1262 LoRa radio peripheral |
| `lichen/boards/renode/t_echo/support/t_echo.resc` | T-Echo Renode script |
| `lichen/boards/renode/t_echo/support/t_echo.repl` | T-Echo platform definition |
| `lichen/boards/renode/nrf52840_lichen/run_multi_node.py` | Multi-node launcher |
| `lichen/boards/renode/nrf52840_lichen/test_mesh.py` | Pytest mesh tests |
| `python/src/lichen/sim/renode_server.py` | TCP server for Renode bridge |

## See Also

- [Simulation API Reference](simulation-api.md) - lichen-sim TCP/REST/WebSocket protocols
- [T-Echo README](../lichen/boards/renode/t_echo/README.md) - T-Echo specific details
- [nRF52840 LICHEN Platform](../lichen/boards/renode/nrf52840_lichen/README.md) - Platform overview
- [Renode Documentation](https://renode.readthedocs.io/) - Official Renode docs
