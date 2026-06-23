# LICHEN

**LoRa IPv6 CoAP Hybrid Extended Network**

A LoRa mesh protocol built entirely on IETF standards. Real IPv6. Real routing. Real security. No proprietary protocols.

## Why LICHEN?

Meshtastic, MeshCore, and LoRaWAN are neat. They're also deeply flawed.

| Problem | Meshtastic | MeshCore | LoRaWAN |
|---------|------------|----------|---------|
| Addressing | Proprietary 32-bit IDs | Proprietary | DevEUI (not routable) |
| Routing | Naive flooding | Source routing blobs | Star topology only |
| Security | AES-CTR without auth | Minimal | Join server dependency |
| Interop | Protobuf everything | Custom binary | Vendor lock-in |
| IP connectivity | None | None | Via application server |

The IETF already solved these problems. IPv6 gives us real addresses. RPL+LOADng give us real mesh routing. CoAP gives us real application protocols. SCHC gives us real compression for constrained links. OSCORE gives us real end-to-end security.

LICHEN assembles these existing standards into a working LoRa mesh. No novel protocols. No proprietary formats. Just standards, composed correctly.

## What It Is

```
┌─────────────────────────────────────────┐
│  Applications (Messaging, SOS, Telemetry)│
├─────────────────────────────────────────┤
│  CoAP + OSCORE (RFC 7252, 8613)         │
├─────────────────────────────────────────┤
│  UDP / IPv6 (RFC 768, 8200)             │
├─────────────────────────────────────────┤
│  Routing: RPL + Announce + LOADng       │
├─────────────────────────────────────────┤
│  SCHC Compression (RFC 8724)            │
├─────────────────────────────────────────┤
│  LICHEN Link Layer (Schnorr signatures) │
├─────────────────────────────────────────┤
│  LoRa PHY (SX126x/SX127x)               │
└─────────────────────────────────────────┘
```

**Key properties:**

- **Real IPv6 addresses** — Every node has link-local, ULA, and optionally global addresses
- **Real mesh routing** — Three-tier architecture (RPL + Announce + LOADng), not naive flooding
- **Real security** — Every packet signed; optional end-to-end encryption
- **Real interop** — Border routers connect mesh to internet; standard CoAP APIs
- **Bandwidth efficient** — SCHC compresses IPv6+UDP+CoAP from 60+ bytes to 6-12 bytes

## What It's For

Everything Meshtastic does, plus:

**Outdoor/Backcountry**
- Mutual position tracking ("blue force tracking")
- Text messaging without cell coverage
- Emergency SOS with mesh-wide alerting
- Waypoint and route sharing

**Tactical/Pro-Am**
- Search and rescue teams (SAR/CERT)
- Milsim and airsoft operations (multi-day, large AO)
- Event/race communications
- Amateur radio mesh experiments (with appropriate licensing)
- Field research expeditions
- Disaster response / NGO coordination

**Hobby/Maker**
- Sensor networks (weather, environmental, agricultural)
- Remote monitoring and control
- Mesh networking experimentation
- IPv6 learning platform

**Why not just use Meshtastic?**

Meshtastic works. But:
- Flooding doesn't scale (every packet touches every node)
- No real addresses (can't route to/from internet cleanly)
- Protobuf lock-in (can't use standard tools)
- AES-CTR without authentication (malleable ciphertext)

If you need a working solution today, use Meshtastic. If you want a technically sound foundation for the future, that's what LICHEN is for.

**Why not goTenna/Silvus/proprietary?**

goTenna Pro is $1,000+. Silvus is $5,000+. LICHEN runs on $30 hardware. You can equip 30 people for the price of one goTenna. For volunteer SAR teams, milsim groups, and disaster response orgs, that math changes everything.

## Target Hardware

LICHEN runs on Meshtastic-compatible hardware. Same radios, new firmware.

| Family | Examples | MCU | Radio |
|--------|----------|-----|-------|
| ESP32 + SX127x | TTGO T-Beam v1, Heltec V2 | ESP32 | SX1276/78 |
| ESP32-S3 + SX126x | Heltec V3, T-Beam Supreme | ESP32-S3 | SX1262 |
| nRF52840 + SX126x | RAK4631, LilyGo T-Echo | nRF52840 | SX1262 |
| RP2040 + SX126x | RAK11310 | RP2040 | SX1262 |
| STM32WL | RAK3172, Seeed Wio-E5 | STM32WL55 | Integrated |

Primary embedded target: **Zephyr RTOS** (native IPv6 stack).

## How It Works

### Addressing

Every node has an IPv6 address derived from its hardware ID:

```
Link-local:  fe80::1234:5678:9abc:def0        (always)
ULA:         fd12:3456:789a:1::1234:5678:...  (when mesh has root)
Global:      2001:db8:1::1234:5678:...        (when border router present)
```

Addresses are stable, routable, and work with standard IPv6 tools.

### Routing

LICHEN uses multi-tier hybrid routing, not one-size-fits-all:

| Tier | Protocol | Traffic Type |
|------|----------|--------------|
| 1 | **RPL** | Border router ↔ mesh (tree-shaped, upward/downward) |
| 2 | **Announce** | Peer-to-peer between active nodes (instant, proactive) |
| 3 | **LOADng** | Unknown destinations (reactive discovery fallback) |
| 4 | **GPSR** | Geographic routing using GPS coordinates |
| 5 | **Backpressure** | Congestion-aware path selection via queue depth |
| 6 | **DTN** | Store-and-forward for partitioned networks |
| 7 | **Opportunistic** | Coordinated multi-forwarder broadcast (ExOR-style) |

RPL builds a tree rooted at the border router for internet traffic. Announce routing builds gradients toward active mesh participants — nodes periodically broadcast signed announcements, so peers can reach each other instantly. LOADng provides reactive route discovery for new or sleeping nodes.

The advanced routing extensions (GPSR, backpressure, DTN, opportunistic) draw from techniques proven in tactical MANET radios like TSM-X and Wave Relay, adapted to LoRa's constrained bandwidth. See `spec/appendix-design-rationale.md` for inspirations and tradeoffs.

All methods populate a unified gradient table. No flooding for unicast traffic.

### Compression

SCHC (RFC 8724) compresses headers. A typical CoAP request:
- Uncompressed: 60+ bytes (IPv6 + UDP + CoAP)
- Compressed: 6-12 bytes (rule ID + residue)

### Security

- **Link layer:** Every packet signed (48-byte Schnorr signature)
- **Application:** OSCORE encrypts CoAP end-to-end
- **Key exchange:** EDHOC establishes OSCORE contexts
- **Trust model:** TOFU (like SSH), optional DANE/PKIX upgrade

### Applications

Standard CoAP resources:
```
GET  coap://[node]/sensors/location     # Position
POST coap://[node]/msg/inbox            # Send message
POST coap://[ff02::1]/sos               # Emergency broadcast
GET  coap://[node]/.well-known/core     # Resource discovery
```

## Project Status

**Phase: Prototype**

- [x] Protocol specification (see `spec/`)
- [x] Internet-Drafts for novel components (see `spec/drafts/`)
- [x] Python prototype with simulated radio
- [ ] Rust reference implementation
- [ ] Zephyr embedded implementation

The Python prototype includes a full network simulator with multi-node topologies, barrier-synchronized time, and integration tests for all routing algorithms. Not production-ready, but validates the protocol design.

## Repository Structure

```
LICHEN/
├── README.md               # This file
├── spec/                   # Protocol specification
│   ├── README.md           # Spec index
│   ├── 01-architecture.md  # Design principles
│   ├── 05-routing.md       # Multi-tier routing
│   ├── 06-security.md      # Security architecture
│   ├── appendix-design-rationale.md  # Inspirations & constraints
│   └── drafts/             # Internet-Drafts
├── python/                 # Python prototype
│   ├── src/lichen/         # Core protocol implementation
│   ├── tests/              # Unit and integration tests
│   └── tests/sim/          # Multi-node simulation tests
├── rust/                   # Rust reference implementation (in progress)
│   ├── lichen-core/        # no_std types and constants
│   ├── lichen-link/        # Link-layer frame codec
│   ├── lichen-schc/        # SCHC compression (RFC 8724)
│   └── lichen-*/           # Other protocol crates
├── lichen/                 # Zephyr west manifest (T2 workspace)
│   ├── west.yml            # Pins Zephyr v3.7.0
│   └── apps/               # Embedded applications
│       ├── puck/           # Field-device firmware
│       └── gateway/        # Border-router firmware
└── constants.toml          # Cross-language protocol constants
```

## Getting Started

**Run the simulator (Python prototype):**
```bash
cd python
pip install -e ".[dev]"
pytest                          # Run all tests
pytest tests/sim/               # Run simulation tests only
lichen-sim --help               # Start simulator server
```

**Build the Rust crates:**
```bash
# Install Rust toolchain (https://rustup.rs)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cd rust
cargo build
cargo test
cargo clippy
```

**Set up the Zephyr workspace (embedded targets):**

See `lichen/README.md` for full details. Quick start:
```bash
pip install west
# Run from inside project-LICHEN/:
west init -l lichen/
west update           # clones Zephyr v3.7.0 into zephyr/ alongside lichen/
west zephyr-export
pip install -r zephyr/scripts/requirements.txt

# Build puck firmware for RAK4631
west build -b rak4631_nrf52840 lichen/apps/puck
```

Requires the [Zephyr SDK](https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html) (≥ 0.16) with the `arm-zephyr-eabi` toolchain.

**Read the spec:**
```bash
ls spec/*.md
```

**Key documents:**
- `spec/README.md` — Table of contents
- `spec/01-architecture.md` — Why these design choices
- `spec/05-routing.md` — Multi-tier routing
- `spec/06-security.md` — Security architecture
- `spec/appendix-design-rationale.md` — Tactical radio inspirations
- `spec/drafts/` — Standalone components (Schnorr sigs, SCHC profile, RPL config)

## Contributing

This project uses [beads](https://github.com/gastownhall/beads) for issue tracking:
```bash
bd ready        # See available work
bd show <id>    # View issue details
```

Areas needing work:
1. Rust reference implementation
2. Zephyr embedded port
3. Real radio integration (SX126x/SX127x drivers)
4. Border router implementation

## FAQ

**Why not just use 6LoWPAN?**

6LoWPAN was designed for IEEE 802.15.4. Its compression assumes 127-byte MTU and 802.15.4 addressing. LoRa has different MTUs, no MAC-layer addresses, and different constraints. SCHC (RFC 8724) was designed specifically for LPWAN networks like LoRa.

**Why not LoRaWAN?**

LoRaWAN is star topology — every node talks to a gateway, no mesh. Good for city-scale IoT with infrastructure, not for off-grid mesh.

**Why so many routing protocols?**

Each solves a different problem. RPL excels at tree-shaped sensor→gateway traffic. Announce routing gives instant peer-to-peer between active nodes. LOADng discovers unknown destinations reactively. GPSR uses geographic coordinates when topology is unknown but positions are. Backpressure routes around congested nodes. DTN handles network partitions via store-and-forward. Opportunistic forwarding uses coordinated broadcast when multiple paths exist. These aren't all active simultaneously—they're tools selected based on conditions. See `spec/appendix-design-rationale.md` for how this draws from tactical MANET experience.

**Why Schnorr instead of Ed25519?**

Ed25519 signatures are 64 bytes. Our Schnorr variant is 48 bytes. At LoRa data rates, 16 bytes saved per packet is significant. See `spec/drafts/draft-lichen-schnorr-00.md`.

**Can I use this today?**

The Python simulator works and validates the protocol design. Real hardware support (Zephyr/ESP32) is not yet implemented. Use Meshtastic if you need radios working now; use LICHEN's simulator if you want to experiment with the protocol.

**What about encryption?**

LICHEN is authentication-first, not encryption-first. Every packet is signed (sender proven). Encryption is optional via OSCORE for CoAP traffic. We don't try to hide that nodes exist (traffic analysis), just prove who sent what.

## License

- Documentation: CC-BY-4.0
- Code: GPL-3.0 (when implemented)

## Acknowledgments

LICHEN stands on the shoulders of the IETF. The protocol is an assembly of:
- IPv6 (RFC 8200)
- RPL (RFC 6550) + LOADng (draft-ietf-roll-aodv-rpl)
- SCHC (RFC 8724)
- CoAP (RFC 7252)
- OSCORE (RFC 8613)
- EDHOC (RFC 9528)

And hardware compatibility thanks to the Meshtastic project's work identifying and documenting LoRa development boards.
