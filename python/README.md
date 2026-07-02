<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Python Prototype

The Python prototype validates LICHEN's protocol design before we commit to embedded implementations. If you're coming from Meshtastic and wondering what this is about, you're in the right place.

## What This Does

This is a full network simulator. You can spin up virtual LICHEN nodes, watch them discover each other, route packets through the mesh, and test what happens when things go wrong. No hardware required.

**Why simulate?** Real LoRa testing is slow (seconds per packet) and requires physical devices spread across real distances. The simulator runs thousands of packets in seconds and lets you test scenarios like "what if this node disappears" or "what if there's interference here" without leaving your desk.

## Quick Start

```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the test suite
pytest

# Start the simulator server
lichen-sim --node-port 4444 --api-port 4445

# In another terminal, launch an interactive node
lichen-tui --host localhost --port 4444 --sim default --node mynode
```

The TUI gives you a terminal interface to send and receive packets. Press `c` to connect, type a message, hit Enter to transmit. Press `r` to listen for incoming packets.

The simulator TUI and native LCI client are separate commands:

```bash
# Simulator node TUI
lichen-tui --host localhost --port 4444 --sim default --node mynode

# Native LCI client over IP/CoAP
lichen-native-client --coap-base-uri 'coap://[fe80::1]'

# Backward-compatible native-client alias
lichen-native-tui --coap-base-uri 'coap://[fe80::1]'
```

Install the native client dependencies from the project checkout with:

```bash
cd python
uv pip install -e ".[native-client]"
```

BLE support is optional and uses `bleak`:

```bash
uv pip install -e ".[native-client,ble]"
```

On macOS, the first BLE run may trigger the system Bluetooth permission prompt
for the terminal app. On Linux, real BLE use requires a running BlueZ stack,
adapter access for the user running the command, and any distribution-specific
permissions for D-Bus Bluetooth APIs. The default automated tests do not require
BLE hardware.

## What's Implemented

| Layer | Status | What It Does |
|-------|--------|--------------|
| **Simulator** | Complete | Radio propagation, collisions, multi-node topologies, chaos testing |
| **Link Layer** | Complete | Frame format, Schnorr signatures, replay protection |
| **SCHC** | Complete | IPv6+UDP+CoAP compression from 60+ bytes to ~10 bytes |
| **IPv6** | Complete | Addressing, packet encoding, ICMPv6 |
| **Announce Routing** | Complete | Peer-to-peer gradient routing with signed announcements |
| **RPL** | Complete | Border router tree routing |
| **LOADng** | Complete | Reactive route discovery |
| **CoAP** | Partial | Basic resources, OSCORE in progress |

## For Meshtastic Users

If you use Meshtastic and you're curious about LICHEN:

**Same hardware.** LICHEN runs on the same boards — T-Beam, Heltec, RAK4631, etc. Different firmware, same radios.

**Real IPv6.** Every node gets a real IPv6 address. You can ping nodes, run standard tools, connect to the internet through a border router.

**Real routing.** No flooding. Packets take specific paths through the mesh. The network scales beyond a few dozen nodes.

**Real security.** Every packet is signed. Senders are authenticated. Optional end-to-end encryption via OSCORE.

The Python prototype lets you experiment with the protocol before we have firmware ready. Run the simulator, connect some virtual nodes, see how routing works.

## For Contributors

We need help with:

1. **Rust implementation** — Reference implementation for embedded targets
2. **Zephyr port** — Real firmware for real hardware
3. **Radio drivers** — SX126x/SX127x integration
4. **Border router** — Linux daemon connecting mesh to internet
5. **Flutter app** — Cross-platform mobile client
6. **TypeScript client** — Web-based mesh interface
7. **Testing** — More scenarios, edge cases, stress tests

Start by running the tests and reading the code. The simulator tests in `tests/sim/` show how the pieces fit together. The protocol spec in `../spec/` explains the design decisions.

```bash
# Run tests with verbose output
pytest -v

# Run just the routing tests
pytest tests/sim/test_announce.py tests/sim/test_topology_scenarios.py -v
```

### Native TUI and Client Tests Without Hardware

The native client tests are designed to run on developer macOS and Linux CI
without BLE adapters, radios, or firmware. Use deterministic fakes for BLE,
IP/CoAP, Observe subscriptions, and TUI client state:

```bash
cd python
uv run pytest tests/tui tests/client -q
```

The BLE tests under `tests/client/test_ble.py` use fake scanners and fake BLE
clients. They must not require BlueZ adapter access or macOS CoreBluetooth
hardware. Any future test that needs a real phone, adapter, board, or radio
must be separated from this default suite behind an explicit hardware marker or
environment gate, and the software fake path must remain the default CI path.

Native TUI snapshot coverage is assertion-based rather than committed generated
SVG files: tests export terminal screenshots and assert stable text for the
connection state, inbox, compose, status, mesh, config, logs, and diagnostics
screens.

Check open issues:
```bash
bd ready        # See available work
bd show <id>    # View issue details
```

## Project Structure

```
src/lichen/
├── sim/        # Network simulator
├── tui/        # Interactive terminal UI
├── link/       # Link layer (frames, signatures)
├── schc/       # Header compression
├── announce/   # Peer-to-peer routing
├── rpl/        # Border router routing
├── loadng/     # Reactive routing
└── ...
```

## Documentation

- **Protocol spec:** `../spec/` — Full protocol documentation
- **Architecture:** `../spec/01-architecture.md` — Design principles
- **Routing:** `../spec/05-routing.md` — Multi-tier routing explained
- **API docs:** Run `lichen-sim --help`, `lichen-tui --help`, and
  `lichen-native-client --help`

## License

Copyright by the contributors to the LICHEN project.

GPL-3.0-or-later
