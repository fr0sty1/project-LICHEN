# Agent Instructions: LICHEN Protocol

**LICHEN** = **L**oRa **I**Pv6 **C**oAP **H**ybrid **E**xtended **N**etwork

A standards-based LoRa mesh networking protocol built on IPv6, SCHC, RPL, and CoAP.

**Licenses:**
- Documentation (specs, docs): **CC-BY-4.0**
- Software (reference implementations): **GPL-3.0**

## Task Tracking: Beads (NOT TodoWrite)

**CRITICAL:** This project uses **beads** (`bd`) for all task tracking.

**DO NOT USE:**
- `TodoWrite` tool
- `TaskCreate` / `TaskUpdate` / `TaskList` tools
- Markdown TODO lists or task files

**USE INSTEAD:**
```bash
bd ready                    # Find available work
bd create --title="..." --description="..." --type=task
bd update <id> --claim      # Claim work
bd close <id>               # Complete work
bd remember "insight"       # Persistent memory across sessions
```

Run `bd prime` for full command reference. See the Beads section at the end of this file for more details.

## Project Overview

**What we're building:** LICHEN — a LoRa mesh network that uses real IPv6 addressing (not proprietary node IDs), enabling direct communication with internet hosts via border routers. Think "Meshtastic but with proper IP."

**Relationship to Meshtastic:** LICHEN runs on the same hardware (reflash), but the protocol is **not backward compatible**. Different sync word (0x34 vs 0x2B), different framing, real IPv6 instead of proprietary addressing. A device runs one or the other, not both.

**Key specs:**
- `LICHEN-spec.md` - Protocol specification (the "what")
- `LICHEN-plan.md` - Implementation plan (the "how")

## Architecture at a Glance

```
Application:  CoAP / MQTT-SN / Raw UDP
Security:     OSCORE (E2E) + Ed25519 link signatures
Transport:    UDP (compressed via SCHC)
Network:      IPv6 (link-local fe80::/10 or global /64)
Routing:      RPL (DODAG mesh formation)
Adaptation:   6LoWPAN + SCHC header compression
Link:         Custom frame format with truncated Ed25519 sigs
Physical:     LoRa CSS (SX126x/SX127x)
```

## Dual Implementation Strategy

This project has **two parallel implementations**, both GPL-3.0:

| Language | Target | Location | Purpose |
|----------|--------|----------|---------|
| **Rust** | Linux, embedded (no_std) | `rust/` | Reference impl, simulators, border routers |
| **C** | Meshtastic hardware | `c/` | ESP32, nRF52840, RP2040, STM32WL |

**Critical rule:** Both implementations MUST produce identical output for all test vectors in `test/vectors/`. If Rust and C diverge, that's a bug.

**GPL-3.0 implications:**
- All distributed binaries must include source or offer to provide it
- Modifications must be released under GPL-3.0
- No proprietary forks; commercial use is fine if source is provided

## Key Technical Decisions

1. **Ed25519 truncated signatures (32 bytes)** - Non-standard but necessary for LoRa bandwidth. Security analysis required.

2. **SCHC compression** - Header compression from 48+ bytes to 3-6 bytes. Rules are pre-provisioned, not negotiated.

3. **RPL Non-Storing Mode** - Border router holds all routes, uses 6LoRH source routing for downward traffic.

4. **No TCP** - UDP only. Use CoAP Observe or MQTT-SN for reliable messaging.

5. **OSCORE for CoAP** - End-to-end encryption, not just link-layer.

6. **Decentralized trust model:**
   - **No PSK** - each node has its own keypair, no "network password"
   - **No mandatory CA** - works without enterprise PKI
   - **TOFU baseline** - accept keys on first contact, pin them (SSH-style)
   - **DANE optional** - verify keys via DNSSEC when internet available
   - **PKIX/ACME optional** - CA certificates fetched out-of-band or via CoAP
   - Trust is per-peer, not per-network

7. **Local Client Interface (LCI)** - see spec section 17:
   - Local client (phone app, etc.) is just another IPv6 neighbor
   - Communicates via CoAP over SLIP/BLE/IPC
   - Same protocol as mesh traffic (no separate API)
   - Node acts as router to mesh
   - Standard CoAP tools work for debugging/testing

8. **SenML for sensor data** - see spec Appendix F:
   - RFC 8428 SenML over CBOR (Content-Format 112)
   - Standard profiles for: location, battery, temp, humidity, pressure, IMU, air quality
   - Observable resources for streaming
   - Base name = `urn:dev:mac:<EUI-64>:`
   - Timestamps support batching (relative to base time)

9. **Standard applications** - see spec section 18:
   - Messaging (unicast, multicast, broadcast, canned messages, store-and-forward)
   - Position sharing (beacons, blue force tracking, privacy controls)
   - Waypoints and routes (shareable POIs, GeoJSON-like)
   - Emergency/SOS (priority alerts, automatic relay, hardware button)
   - Presence/status (available/away/busy, activity hints)
   - Check-in/roll call (group accountability)
   - Range testing (extended ping with RSSI/SNR, traceroute)
   - Groups/channels (multicast addressing, optional OSCORE group encryption)

## Development Phases

| Phase | Focus | Key Deliverables |
|-------|-------|------------------|
| 0 | Foundation | Workspace setup, first I-D drafts |
| 1 | PHY + Link | LoRa radio abstraction, Ed25519 frames |
| 2 | SCHC | Header compression engine, fragmentation |
| 3 | IPv6 | 6LoWPAN dispatch, ICMPv6 |
| 4 | RPL | DODAG formation, Trickle timers |
| 5 | Security | OSCORE, key management |
| 6 | Application | CoAP server/client, MQTT-SN |
| 7 | Border Router | 6LBR, gateway functions |
| 8 | Tooling | Simulator, Wireshark dissector |

## Code Organization

```
rust/
├── lora-phy/        # Radio abstraction (SX126x, SX127x, simulated)
├── lora-link/       # Link layer (framing, LLSec, replay protection)
├── schc/            # SCHC compression + fragmentation
├── sixlowpan/       # 6LoWPAN dispatch, IPv6 minimal
├── rpl/             # RPL routing, Trickle, MRHOF
├── coap/            # CoAP + OSCORE
├── mqtt-sn/         # MQTT-SN client
├── mesh-node/       # Full node binary
├── mesh-gateway/    # Border router binary
├── mesh-sim/        # Network simulator
└── ffi/             # C bindings (cbindgen)

c/
├── include/lora_mesh/  # Public headers
├── src/                # Implementation
└── port/               # Platform-specific (esp32, nrf52, rp2040, stm32wl)

docs/
└── draft-*.md       # IETF-style Internet-Drafts
```

## Coding Guidelines

### Rust
- Use `no_std` by default; `std` only in simulator and gateway
- Prefer `heapless` collections over `Vec` in core crates
- All public APIs must be `#![forbid(unsafe_code)]` except FFI
- Run `cargo clippy` and `cargo fmt` before commits

### C
- Target: C11, no dynamic allocation in hot paths
- Memory budget varies by platform:
  - ESP32: 320KB+ SRAM, 4MB+ Flash (comfortable)
  - nRF52840: 256KB RAM, 1MB Flash (comfortable)
  - STM32WL: 64KB RAM, 256KB Flash (constrained baseline)
- Use `static` for all file-scoped symbols
- No recursive functions (stack overflow risk on smaller stacks)

### Both
- Every packet format must have test vectors
- Crypto primitives from vetted libraries only (no hand-rolled crypto)
- Bit-level protocol parsing must be fuzzed

## Testing Requirements

1. **Unit tests** - Each crate/module in isolation
2. **Integration tests** - Multi-node scenarios in simulator
3. **Interop tests** - Rust ↔ C produce identical output
4. **Hardware tests** - Real LoRa radios on real MCUs
5. **Fuzz tests** - All parsing code (SCHC, CoAP, RPL messages)

Test vectors live in `test/vectors/` as JSON. Both implementations read and verify against these.

## IETF I-D Documents

We're writing protocol docs in IETF Internet-Draft style:

| Document | Content |
|----------|---------|
| `draft-lora-link-*.md` | Link layer frame format, LLSec |
| `draft-lora-schc-*.md` | SCHC compression profile |
| `draft-lora-rpl-*.md` | RPL configuration for LoRa |
| `draft-lora-security-*.md` | Ed25519 truncation, OSCORE |
| `draft-lora-coap-*.md` | CoAP usage, Resource Directory |
| `draft-lora-border-*.md` | Border router behavior |

Use RFC 2119 keywords (MUST, SHOULD, MAY) consistently.

## Open Questions (Check Before Implementing)

1. **Truncated Ed25519 derivation** - Exact algorithm for deriving second half from first
2. **SCHC rule distribution** - Pre-provisioned vs. negotiated
3. **Time synchronization** - NTP over CoAP, GPS, or piggyback on DIO?
4. **DANE record format** - Exact TLSA record structure for `_25519._mesh.<name>`

Check `bd list` for issues tracking these decisions.

## Resolved Decisions

- **Trust model**: TOFU baseline, DANE/PKIX optional upgrades (see spec 8.5)
- **License**: CC-BY-4.0 (docs), GPL-3.0 (code)
- **Hardware**: Meshtastic-compatible devices (reflash)
- **IPv6 addressing** (see spec 6.1, 12):
  - Link-local always (fe80:: + IID)
  - ULA default when DODAG root present (fd00::/8)
  - GUA optional when BR has upstream prefix
  - Isolated meshes work (self-elected root generates ULA)
  - Multiple BRs tolerated (no coordination required)
- **Local Client Interface** (see spec 17):
  - IPv6 + CoAP over SLIP/BLE/IPC (not proprietary protobuf)
  - Client gets link-local address, node routes to mesh
  - Resources: /config, /status, /keys, mesh proxy

## Hardware Targets

**We target all hardware that Meshtastic already supports.** This is a reflash, not new hardware. Users with existing Meshtastic devices can flash our firmware.

Meshtastic-compatible boards include:

| Family | Examples | Radio |
|--------|----------|-------|
| **ESP32 + SX127x** | TTGO T-Beam, Heltec LoRa 32 V2 | SX1276/78 |
| **ESP32-S3 + SX126x** | Heltec LoRa 32 V3, T-Beam Supreme | SX1262 |
| **nRF52840 + SX126x** | RAK4631, T-Echo | SX1262 |
| **RP2040 + SX126x** | RAK11310 | SX1262 |
| **STM32WL** | RAK3172, Seeed Wio-E5 | Integrated SX126x |

See [Meshtastic Supported Hardware](https://meshtastic.org/docs/hardware/devices/) for the full list.

**Development boards** (for contributors):
- Heltec LoRa 32 V3 - cheap, widely available
- T-Beam Supreme - GPS + SX1262
- RAK4631 - nRF52840 for BLE gateway work
- Any STM32WL board - for integrated radio testing

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** to avoid hanging on prompts:

```bash
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file
rm -rf directory            # NOT: rm -r directory
```

---

## Beads Issue Tracking

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking (not TodoWrite, TaskCreate, or markdown lists)
- Use `bd remember` for persistent knowledge (not MEMORY.md files)
- Run `bd prime` for detailed command reference

### Session Completion

**When ending work**, complete ALL steps:

1. File issues for remaining work
2. Run quality gates (tests, linters, builds)
3. Close finished issues
4. **PUSH TO REMOTE** (mandatory):
   ```bash
   git pull --rebase && git push
   git status  # Must show "up to date"
   ```
5. Provide handoff context for next session
