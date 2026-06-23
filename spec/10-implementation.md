<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Implementation Notes

## 16. Implementation Notes

### 16.1. Repository Structure

```
LICHEN/
├── docs/
│   ├── spec/                   # Protocol specification (CC-BY-4.0)
│   └── draft-lichen-*.md       # IETF-style I-Ds
│
├── rust/                       # Rust implementation (Linux, gateway, simulator)
│   ├── Cargo.toml              # Workspace root
│   ├── lichen-core/            # Core protocol logic (no_std)
│   ├── lichen-link/            # Link layer (Ed25519 signatures)
│   ├── lichen-schc/            # SCHC compression
│   ├── lichen-coap/            # CoAP + OSCORE
│   ├── lichen-senml/           # SenML encoding
│   ├── lichen-apps/            # Applications (messaging, SOS)
│   ├── lichen-node/            # Linux node binary
│   ├── lichen-gateway/         # Border router binary
│   └── lichen-sim/             # Network simulator
│
├── zephyr/                     # Zephyr implementation (embedded)
│   ├── west.yml                # West manifest
│   ├── CMakeLists.txt
│   ├── Kconfig                 # LICHEN Kconfig options
│   ├── subsys/
│   │   ├── lichen_link/        # Link layer module
│   │   ├── lichen_schc/        # SCHC module
│   │   ├── lichen_rpl/         # RPL tuning for LoRa
│   │   ├── lichen_apps/        # Applications
│   │   └── lichen_lci/         # Local Client Interface
│   ├── drivers/
│   │   └── lora/               # LoRa-specific adaptations
│   ├── boards/                 # Board-specific overlays
│   │   ├── heltec_lora32_v3.overlay
│   │   ├── rak4631.overlay
│   │   ├── tbeam_supreme.overlay
│   │   └── nucleo_wl55jc.overlay
│   └── samples/
│       ├── basic_node/         # Minimal node example
│       ├── sensor_node/        # Sensor + position beacon
│       └── border_router/      # 6LBR example
│
├── riot/                       # RIOT fallback (STM32WL if Zephyr too big)
│   └── ...
│
├── test/
│   ├── vectors/                # Shared test vectors (JSON)
│   ├── interop/                # Cross-implementation tests
│   └── hardware/               # Hardware-in-loop tests
│
├── tools/
│   ├── lichen-craft/           # Packet builder/parser CLI (Rust)
│   ├── wireshark-dissector/    # Wireshark Lua plugin
│   └── lichen-keygen/          # Key generation tool (Rust)
│
└── apps/
    ├── lichen-cli/             # Command-line client (Rust)
    ├── lichen-tui/             # Terminal UI (Rust)
    └── lichen-web/             # Web dashboard (border router)
```

### 16.2. Hardware Targets

#### Meshtastic-Compatible (Primary)

Reflash existing Meshtastic hardware with LICHEN firmware — same radios, different stack.

| Family | Examples | MCU | Radio |
|--------|----------|-----|-------|
| ESP32 + SX127x | TTGO T-Beam v1, Heltec LoRa 32 V2 | ESP32 | SX1276/78 |
| ESP32-S3 + SX126x | Heltec LoRa 32 V3, T-Beam Supreme | ESP32-S3 | SX1262 |
| nRF52840 + SX126x | RAK4631, LilyGo T-Echo | nRF52840 | SX1262 |
| RP2040 + SX126x | RAK11310 | RP2040 | SX1262 |
| STM32WL | RAK3172, Seeed Wio-E5 | STM32WL55 | Integrated |

#### Open Hardware Radios (Future)

| Project | Hardware | Notes |
|---------|----------|-------|
| [kv4p HT](https://www.kv4p.com/) | ESP32 + SA818 VHF/UHF | ~$50, Android app, has APRS modem |
| [OpenHT](https://github.com/M17-Project/OpenHT-hw) | AT86RF215 SDR + FPGA | True SDR, M17 project |
| [Module17](https://m17project.org/module17/) | STM32 M17 modem | OSHWA certified, plugs into FM radio |

Integration: Native LICHEN (if LoRa added), gateway to mesh, or LICHEN-over-FM.

#### Open Firmware Radios (Gateway Candidates)

| Radio | Firmware | Notes |
|-------|----------|-------|
| TYT MD-380/UV380 | [OpenRTX](https://openrtx.org/) | DMR handheld, M17 support |
| Radioddity GD-77 | OpenRTX | Popular, well documented |
| QuanSheng UV-K5 | [egzumer](https://github.com/egzumer/uv-k5-firmware-custom) | ~$25, huge community |
| Baofeng DM-1801 | OpenGD77 | Budget option |

Integration: Bridge APRS/packet ↔ LICHEN mesh via border router.

#### Border Router Hardware

Border routers benefit from good antennas and elevated placement — more direct reach = fewer hops to internet.

| Platform | Config | Cost | Notes |
|----------|--------|------|-------|
| Raspberry Pi 4/5 | + USB puck | ~$80 | Development |
| Pi Zero 2W | + SX1262 HAT | ~$40 | Low power deployment |
| GL.iNet routers | + USB puck | ~$70+ | OpenWRT, easy setup |
| RAK7391 WisGate | CM4 + LoRa + cell | ~$200 | Integrated solution |

Antenna matters more than compute:

| Level | Antenna | Placement | Range |
|-------|---------|-----------|-------|
| Basic | Rubber duck | Indoor | 1-2 km |
| Better | 5dBi fiberglass | Window | 5-10 km |
| Good | 8dBi collinear | Rooftop | 15-25 km |
| Excellent | Yagi/sector | Tower | 30+ km LOS |

**Memory budgets:**

| Platform | RAM | Flash | Constraint Level |
|----------|-----|-------|------------------|
| ESP32/ESP32-S3 | 320KB+ | 4MB+ | Comfortable |
| nRF52840 | 256KB | 1MB | Comfortable |
| RP2040 | 264KB | 2MB | Comfortable |
| STM32WL | 64KB | 256KB | **Constrained - risk** |

### 16.3. Software Architecture

**Tiered Implementation Strategy:**

| Platform | Stack | Notes |
|----------|-------|-------|
| Linux/Pi | Rust | Gateway, simulator, border router |
| ESP32, nRF52840, RP2040 | Zephyr RTOS | Primary embedded target |
| STM32WL | Zephyr or RIOT | RIOT fallback if Zephyr too big |

**Zephyr Stack Usage:**

| LICHEN Component | Zephyr Subsystem | Notes |
|------------------|------------------|-------|
| IPv6 | `CONFIG_NET_IPV6` | Native |
| 6LoWPAN | `CONFIG_NET_L2_IEEE802154` | Adapt for LoRa |
| UDP | `CONFIG_NET_UDP` | Native |
| CoAP | `CONFIG_COAP` | Native library |
| OSCORE | Custom or port | May need to implement |
| BLE (LCI) | `CONFIG_BT` | NimBLE or Zephyr BLE |
| LoRa radio | `CONFIG_LORA` | SX126x/SX127x drivers exist |
| Crypto | `CONFIG_MBEDTLS` or TinyCrypt | Ed25519 may need monocypher |

**What we build on top of Zephyr:**
- SCHC compression (custom, ~10KB flash)
- RPL tuning for LoRa timing
- Ed25519 truncated signatures
- LICHEN link layer framing
- Application layer (messaging, SOS, etc.)
- Local Client Interface

### 16.4. STM32WL Memory Budget

```
FLASH (256 KB available):
┌────────────────────────────────────┬────────┐
│ Component                          │ Est.   │
├────────────────────────────────────┼────────┤
│ Zephyr kernel + HAL                │ ~40 KB │
│ IPv6 + 6LoWPAN                     │ ~30 KB │
│ RPL                                │ ~15 KB │
│ CoAP                               │ ~15 KB │
│ OSCORE/DTLS                        │ ~20 KB │
│ SCHC                               │ ~10 KB │
│ Ed25519 (monocypher)               │ ~10 KB │
│ LoRa driver                        │ ~10 KB │
│ BLE (minimal)                      │ ~30 KB │
│ LICHEN application                 │ ~40 KB │
├────────────────────────────────────┼────────┤
│ TOTAL                              │ ~220KB │
│ Margin                             │ ~36 KB │
└────────────────────────────────────┴────────┘

RAM (64 KB available):
┌────────────────────────────────────┬────────┐
│ Component                          │ Est.   │
├────────────────────────────────────┼────────┤
│ Zephyr kernel                      │ ~4 KB  │
│ Network buffers (tuned down)       │ ~6 KB  │
│ IPv6 + neighbor cache              │ ~4 KB  │
│ RPL routing state                  │ ~3 KB  │
│ CoAP contexts                      │ ~3 KB  │
│ SCHC contexts                      │ ~2 KB  │
│ Key store (limited peers)          │ ~3 KB  │
│ Application state                  │ ~8 KB  │
│ Thread stacks (2-3 threads)        │ ~6 KB  │
│ BLE buffers                        │ ~4 KB  │
├────────────────────────────────────┼────────┤
│ TOTAL                              │ ~43 KB │
│ Margin                             │ ~21 KB │
└────────────────────────────────────┴────────┘
```

**Constraints on STM32WL:**
- Aggressive Kconfig tuning required
- Reduced network buffer count
- Limited routing table size
- May disable store-and-forward

**RIOT Fallback:** If Zephyr doesn't fit, use RIOT OS (~10KB RAM for full IPv6/6LoWPAN/RPL).

### 16.5. Dependencies

**Zephyr RTOS Modules:**

| Component | Zephyr Module | Notes |
|-----------|---------------|-------|
| Kernel | `CONFIG_KERNEL` | Threads, scheduling |
| IPv6 | `CONFIG_NET_IPV6` | Native stack |
| UDP | `CONFIG_NET_UDP` | Native |
| CoAP | `CONFIG_COAP` | Zephyr CoAP library |
| LoRa | `CONFIG_LORA` | SX126x, SX127x drivers |
| BLE | `CONFIG_BT` | For Local Client Interface |
| Crypto | `CONFIG_MBEDTLS` | AES, hashing |
| Shell | `CONFIG_SHELL` | Debug/CLI (optional) |

**Rust Crates (GPL-3.0 compatible):**

| Crate | Use | License |
|-------|-----|---------|
| ed25519-dalek | Signatures | BSD-3 |
| aes-gcm | OSCORE encryption | MIT/Apache-2.0 |
| heapless | no_std collections | MIT/Apache-2.0 |
| coap-lite | CoAP parsing | MIT |
| smoltcp | IP stack (Linux node) | 0BSD |

**C Libraries (for Zephyr modules):**

| Library | Use | License |
|---------|-----|---------|
| monocypher | Ed25519, AES | Public domain |
| libschc | SCHC reference | MIT |

**RIOT OS (STM32WL fallback):**

| Component | RIOT Module | Notes |
|-----------|-------------|-------|
| IPv6/6LoWPAN | GNRC | Proven ~10KB RAM |
| RPL | GNRC RPL | Lightweight |
| CoAP | gcoap | Efficient |
| LoRa | sx126x/sx127x | Drivers available |

### 16.6. IETF-Style Documents

| Document | Content |
|----------|---------|
| draft-lichen-link | Link layer, LLSec, Ed25519 |
| draft-lichen-schc | SCHC profile for LICHEN |
| draft-lichen-addr | IPv6 addressing, ULA, isolated mesh |
| draft-lichen-rpl | RPL configuration, MRHOF |
| draft-lichen-security | TOFU, DANE, OSCORE profile |
| draft-lichen-lci | Local Client Interface |
| draft-lichen-senml | SenML sensor profiles |
| draft-lichen-apps | Application protocols |
| draft-lichen-border | Border router behavior |

---

[← Previous: Packets and Timing](09-packets-timing.md) | [Index](README.md) | [Next: Local Client Interface →](11-lci.md)
