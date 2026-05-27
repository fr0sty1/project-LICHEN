# Implementation Plan: LICHEN Protocol

**LICHEN** = **L**oRa **I**Pv6 **C**oAP **H**ybrid **E**xtended **N**etwork

**Document:** Implementation Plan
**Spec Reference:** LICHEN-spec.md
**Date:** 2026-05-26
**Status:** Draft
**License:** CC-BY-4.0 (documentation)

---

## Executive Summary

This plan describes how to build the LICHEN protocol stack from the specification. The implementation spans:

- **Rust** for "bigger" machines (Linux gateways, border routers, test harnesses, simulators)
- **C** for constrained embedded targets (STM32WL, nRF52840, ESP32)
- **IETF-style I-Ds** in markdown for all protocol components

The architecture prioritizes a shared core logic (in Rust with `no_std`) that can either run natively or be compiled to C-callable libraries via `cbindgen`. Truly constrained devices get a hand-optimized C implementation sharing only the protocol constants and test vectors with the Rust reference.

---

## 1. Repository Structure

```
lora-ipv6-mesh/
├── docs/
│   └── draft-*.md              # IETF-style I-Ds (markdown)
├── rust/
│   ├── Cargo.toml              # Workspace root
│   ├── lora-phy/               # LoRa radio abstraction
│   ├── lora-link/              # Link layer (LLSec, framing)
│   ├── schc/                   # SCHC compression engine
│   ├── sixlowpan/              # 6LoWPAN adaptation
│   ├── rpl/                    # RPL routing
│   ├── coap/                   # CoAP + OSCORE
│   ├── mqtt-sn/                # MQTT-SN client
│   ├── mesh-node/              # Full node binary (Linux/embedded)
│   ├── mesh-gateway/           # Border router binary
│   ├── mesh-sim/               # Network simulator
│   └── ffi/                    # C bindings (cbindgen)
├── c/
│   ├── include/
│   │   └── lora_mesh/          # Public headers
│   ├── src/
│   │   ├── phy/                # Radio drivers
│   │   ├── link/               # Link layer
│   │   ├── schc/               # SCHC (C impl)
│   │   ├── ipv6/               # IPv6 minimal
│   │   ├── rpl/                # RPL
│   │   └── coap/               # CoAP + OSCORE
│   ├── port/                   # Platform ports
│   │   ├── stm32wl/
│   │   ├── nrf52/
│   │   └── esp32/
│   └── CMakeLists.txt
├── test/
│   ├── vectors/                # Shared test vectors (JSON)
│   ├── interop/                # Interop test scripts
│   └── hardware/               # Hardware-in-loop tests
├── tools/
│   ├── packet-craft/           # Packet builder/parser CLI
│   ├── wireshark-dissector/    # Wireshark plugin
│   └── key-manager/            # Key generation/provisioning
└── examples/
    ├── sensor-node/            # Reference leaf node
    ├── router/                 # Reference router
    └── border-router/          # Reference 6LBR
```

---

## 2. Phase Plan

### Phase 0: Foundation (Weeks 1-2)

**Goal:** Project scaffolding, tooling, first I-D drafts.

| Task | Output | Owner |
|------|--------|-------|
| Set up Rust workspace with `no_std` crates | `rust/Cargo.toml` | - |
| Set up C build (CMake + Zephyr integration) | `c/CMakeLists.txt` | - |
| Define shared constants (frequencies, sync words, ports) | `rust/lora-phy/src/constants.rs`, `c/include/lora_mesh/constants.h` | - |
| Write `draft-lora-link-01.md` (link layer) | `docs/draft-lora-link-01.md` | - |
| Write `draft-lora-schc-01.md` (SCHC profile) | `docs/draft-lora-schc-01.md` | - |
| Create test vector generator skeleton | `test/vectors/` | - |

**Exit Criteria:**
- `cargo build` succeeds for all crates (stub implementations)
- `cmake --build` succeeds for C library
- Two draft I-Ds reviewed

---

### Phase 1: Physical & Link Layer (Weeks 3-5)

**Goal:** Transmit and receive authenticated frames over LoRa.

#### 1.1 LoRa Radio Abstraction (Rust)

```rust
// lora-phy/src/lib.rs
pub trait Radio {
    fn configure(&mut self, config: &Config) -> Result<(), Error>;
    fn transmit(&mut self, data: &[u8]) -> Result<(), Error>;
    fn receive(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Error>;
    fn cad(&mut self) -> Result<bool, Error>;  // Channel activity detection
    fn rssi(&self) -> i16;
    fn snr(&self) -> i8;
}
```

Implementations:
- `sx126x`: SX1261/62/68 driver (SPI, embedded-hal)
- `sx127x`: SX1276/77/78/79 driver (SPI)
- `simulated`: For mesh-sim

#### 1.2 Link Layer (Rust)

```rust
// lora-link/src/lib.rs
pub struct LinkFrame {
    pub llsec: LLSecFlags,
    pub seq_num: u16,
    pub dst_addr: Address,
    pub payload: Vec<u8>,  // or heapless::Vec for no_std
    pub signature: [u8; 32],
}

pub trait LinkLayer {
    fn send(&mut self, frame: &LinkFrame) -> Result<(), Error>;
    fn recv(&mut self, timeout: Duration) -> Result<LinkFrame, Error>;
}
```

#### 1.3 Ed25519 Truncated Signatures

```rust
// lora-link/src/crypto.rs
pub fn sign_truncated(key: &SigningKey, message: &[u8]) -> [u8; 32] {
    let sig = key.sign(message);
    sig.to_bytes()[..32].try_into().unwrap()
}

pub fn verify_truncated(
    pubkey: &VerifyingKey,
    message: &[u8],
    truncated: &[u8; 32]
) -> bool {
    // Reconstruct full signature via deterministic derivation
    // See spec section 8.3 for algorithm
}
```

#### 1.4 Replay Protection

```rust
// lora-link/src/replay.rs
pub struct ReplayWindow {
    last_seq: u16,
    bitmap: u32,  // 32-packet window
}

impl ReplayWindow {
    pub fn check_and_update(&mut self, seq: u16) -> bool { ... }
}
```

#### 1.5 C Implementation

Mirror the Rust API for constrained devices:

```c
// c/include/lora_mesh/link.h
typedef struct {
    uint8_t llsec;
    uint16_t seq_num;
    lora_addr_t dst;
    uint8_t *payload;
    size_t payload_len;
    uint8_t signature[32];
} lora_link_frame_t;

int lora_link_send(lora_link_ctx_t *ctx, const lora_link_frame_t *frame);
int lora_link_recv(lora_link_ctx_t *ctx, lora_link_frame_t *frame, uint32_t timeout_ms);
```

**Exit Criteria:**
- Two nodes exchange authenticated frames
- Replay attack blocked in test
- Documented in `draft-lora-link-01.md`

---

### Phase 2: SCHC Compression (Weeks 6-8)

**Goal:** Implement RFC 8724 SCHC for IPv6/UDP/CoAP compression.

#### 2.1 SCHC Engine (Rust)

```rust
// schc/src/lib.rs
pub struct Rule {
    pub id: u8,
    pub fields: Vec<FieldDescriptor>,
}

pub struct FieldDescriptor {
    pub field_id: FieldId,
    pub target_value: Option<Vec<u8>>,
    pub matching_operator: MatchingOperator,
    pub compression_action: CompressionAction,
}

pub fn compress(rules: &[Rule], packet: &[u8]) -> Result<(u8, Vec<u8>), Error>;
pub fn decompress(rules: &[Rule], rule_id: u8, residue: &[u8], context: &Context) -> Result<Vec<u8>, Error>;
```

#### 2.2 Default Rules (per spec Appendix A)

| Rule | Use Case | Implementation Priority |
|------|----------|------------------------|
| 0 | Link-local IPv6 + UDP + CoAP | P0 |
| 1 | Global IPv6 + UDP + CoAP | P0 |
| 2 | ICMPv6 Echo | P1 |
| 3 | RPL DIO | P1 |
| 4 | RPL DAO | P1 |

#### 2.3 Fragmentation (ACK-on-Error)

```rust
// schc/src/fragment.rs
pub struct Fragmenter {
    rule_id: u8,
    window_size: u8,
    fcn_bits: u8,
}

impl Fragmenter {
    pub fn fragment(&self, packet: &[u8], mtu: usize) -> Vec<Fragment>;
    pub fn reassemble(&mut self, frag: Fragment) -> Option<Vec<u8>>;
}
```

#### 2.4 Test Vectors

Generate from Rust, verify in C:

```json
// test/vectors/schc-rule0.json
{
  "name": "Link-local CoAP GET",
  "uncompressed": "60000000...",  // Full IPv6+UDP+CoAP hex
  "rule_id": 0,
  "residue": "0011",              // Hex
  "compressed_total": "00001100..."
}
```

**Exit Criteria:**
- All default rules implemented and tested
- Fragmentation working with 60-byte MTU
- C and Rust produce identical output for all test vectors
- `draft-lora-schc-01.md` complete

---

### Phase 3: IPv6 and 6LoWPAN (Weeks 9-10)

**Goal:** Full IPv6 with SLAAC, 6LoWPAN dispatch.

#### 3.1 IPv6 Minimal (Rust)

```rust
// sixlowpan/src/ipv6.rs
pub struct Ipv6Packet {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub payload: Vec<u8>,
}

pub fn derive_iid_from_eui64(eui64: [u8; 8]) -> [u8; 8];
pub fn derive_iid_from_short(short: u16) -> [u8; 8];
```

#### 3.2 6LoWPAN Dispatch

```rust
// sixlowpan/src/dispatch.rs
pub enum Dispatch {
    Ipv6,           // 0x41 - uncompressed
    Iphc,           // 0x60-0x7F - RFC 6282 IPHC
    Schc(u8),       // 0x14 + rule_id - RFC 8724
    FragFirst,      // 0xC0-0xDF
    FragSubseq,     // 0xE0-0xFF
}
```

#### 3.3 ICMPv6

Essential subset:
- Echo Request/Reply (ping)
- Destination Unreachable
- Neighbor Solicitation/Advertisement (if needed for DAD)

**Exit Criteria:**
- Nodes can ping each other (link-local)
- Global addresses work via border router prefix
- ICMPv6 compressed via SCHC rule 2

---

### Phase 4: RPL Routing (Weeks 11-14)

**Goal:** Mesh formation, upward/downward routing.

#### 4.1 RPL Core (Rust)

```rust
// rpl/src/lib.rs
pub struct Dodag {
    pub instance_id: u8,
    pub dodag_id: Ipv6Addr,
    pub version: u8,
    pub rank: u16,
    pub parent: Option<Neighbor>,
    pub children: Vec<Neighbor>,
}

pub struct Neighbor {
    pub addr: Ipv6Addr,
    pub link_local: Ipv6Addr,
    pub rank: u16,
    pub etx: u16,  // Expected transmissions * 128
}
```

#### 4.2 Control Messages

| Message | Priority | Notes |
|---------|----------|-------|
| DIO | P0 | DODAG advertisement |
| DIS | P0 | Solicitation |
| DAO | P0 | Destination advertisement |
| DAO-ACK | P1 | Acknowledgment |

#### 4.3 Trickle Timer

```rust
// rpl/src/trickle.rs
pub struct Trickle {
    i_min: Duration,
    i_max: Duration,
    k: u8,
    i: Duration,
    t: Duration,
    c: u8,
}

impl Trickle {
    pub fn reset(&mut self);
    pub fn consistent(&mut self);
    pub fn should_transmit(&self) -> bool;
    pub fn next_interval(&mut self) -> Duration;
}
```

#### 4.4 Objective Function (MRHOF)

```rust
// rpl/src/of.rs
pub fn calculate_rank(parent_rank: u16, link_etx: u16) -> u16 {
    let path_etx = parent_rank.saturating_add((link_etx * MIN_HOP_RANK_INCREASE) / 128);
    path_etx
}

pub fn select_parent(candidates: &[Neighbor], current: Option<&Neighbor>) -> Option<&Neighbor> {
    // Prefer lowest rank, with hysteresis
}
```

#### 4.5 Non-Storing Mode + 6LoRH

```rust
// rpl/src/source_route.rs
pub fn insert_source_route(packet: &mut Ipv6Packet, hops: &[u16]) {
    // Insert 6LoRH (RFC 8138) header
}

pub fn process_source_route(packet: &Ipv6Packet) -> Option<u16> {
    // Return next hop short address
}
```

**Exit Criteria:**
- 5-node mesh forms DODAG
- Upward routing (leaf → root) works
- Downward routing (root → leaf via source route) works
- Parent switching on link failure
- `draft-lora-rpl-01.md` complete

---

### Phase 5: Security Layer (Weeks 15-17)

**Goal:** OSCORE for CoAP, secure RPL mode.

#### 5.1 OSCORE (Rust)

```rust
// coap/src/oscore.rs
pub struct SecurityContext {
    pub sender_id: Vec<u8>,
    pub recipient_id: Vec<u8>,
    pub master_secret: [u8; 16],
    pub sender_seq: u64,
}

pub fn protect(ctx: &mut SecurityContext, coap: &CoapMessage) -> Result<CoapMessage, Error>;
pub fn unprotect(ctx: &SecurityContext, coap: &CoapMessage) -> Result<CoapMessage, Error>;
```

#### 5.2 Key Management (Bootstrap)

Options to implement:
1. **Pre-shared keys** (simplest, for testing)
2. **EDHOC (RFC 9528)** - lightweight key exchange (stretch goal)

```rust
// mesh-node/src/keystore.rs
pub struct KeyStore {
    pub my_signing_key: SigningKey,
    pub peer_keys: HashMap<Ipv6Addr, VerifyingKey>,
    pub oscore_contexts: HashMap<Ipv6Addr, SecurityContext>,
}
```

#### 5.3 RPL Secure Mode

```rust
// rpl/src/security.rs
pub enum SecurityMode {
    Unsecured,
    Preinstalled { key: [u8; 16] },
    Authenticated { /* per-node keys */ },
}
```

**Exit Criteria:**
- OSCORE-protected CoAP exchange works end-to-end
- Unsigned RPL messages rejected in secure mode
- Key provisioning tool exists

---

### Phase 6: Application Layer (Weeks 18-20)

**Goal:** CoAP server/client, MQTT-SN client, Resource Directory.

#### 6.1 CoAP (Rust)

```rust
// coap/src/lib.rs
pub struct CoapMessage {
    pub msg_type: MessageType,
    pub code: Code,
    pub message_id: u16,
    pub token: Vec<u8>,
    pub options: Vec<CoapOption>,
    pub payload: Vec<u8>,
}

pub trait CoapHandler {
    fn handle(&self, request: &CoapMessage) -> CoapMessage;
}
```

Features:
- [P0] Basic GET/POST/PUT/DELETE
- [P0] Observe (RFC 7641)
- [P1] Block-wise transfer (RFC 7959)

#### 6.2 MQTT-SN Client (Rust)

```rust
// mqtt-sn/src/lib.rs
pub struct MqttSnClient {
    pub gateway: Ipv6Addr,
    pub client_id: String,
    pub topics: HashMap<u16, String>,  // topic_id → topic_name
}

impl MqttSnClient {
    pub fn connect(&mut self) -> Result<(), Error>;
    pub fn register(&mut self, topic: &str) -> Result<u16, Error>;
    pub fn publish(&mut self, topic_id: u16, payload: &[u8], qos: QoS) -> Result<(), Error>;
    pub fn subscribe(&mut self, topic: &str) -> Result<u16, Error>;
}
```

#### 6.3 Resource Directory Client

```rust
// coap/src/rd.rs
pub fn register(
    client: &CoapClient,
    rd_addr: Ipv6Addr,
    endpoint: &str,
    resources: &[Resource],
) -> Result<(), Error>;

pub fn lookup(
    client: &CoapClient,
    rd_addr: Ipv6Addr,
    resource_type: &str,
) -> Result<Vec<ResourceLink>, Error>;
```

**Exit Criteria:**
- Sensor node publishes temperature via CoAP
- MQTT-SN client publishes to broker via gateway
- Resource Directory discovers mesh nodes

---

### Phase 7: Border Router (Weeks 21-23)

**Goal:** Full 6LBR implementation connecting mesh to internet.

#### 7.1 Architecture

```
┌─────────────────────────────────────────────────┐
│               Border Router (Linux)              │
├─────────────────────────────────────────────────┤
│  ┌─────────┐  ┌──────────┐  ┌────────────────┐ │
│  │ LoRa    │  │ IPv6     │  │ Resource       │ │
│  │ Radio   │──│ Routing  │──│ Directory      │ │
│  └─────────┘  └──────────┘  └────────────────┘ │
│       │            │              │            │
│  ┌────┴────┐  ┌────┴────┐  ┌─────┴──────┐    │
│  │ SCHC    │  │ RPL     │  │ MQTT-SN    │    │
│  │ Gateway │  │ Root    │  │ Gateway    │    │
│  └─────────┘  └─────────┘  └────────────┘    │
│                    │                          │
│              ┌─────┴─────┐                    │
│              │ eth0/wlan │                    │
│              │ Internet  │                    │
│              └───────────┘                    │
└─────────────────────────────────────────────────┘
```

#### 7.2 Components

| Component | Function |
|-----------|----------|
| DODAG Root | Originates RPL instance, assigns prefix |
| Prefix Delegation | Obtains /64 from upstream (DHCPv6-PD or static) |
| Source Routing | Inserts 6LoRH for downward traffic |
| SCHC Context Manager | Distributes compression rules |
| MQTT-SN Gateway | Translates MQTT-SN ↔ MQTT 3.1.1/5.0 |
| Resource Directory | CoAP RD (RFC 9176) |
| NTP Server | Time sync for mesh (optional) |

**Exit Criteria:**
- Internet host can ping mesh node
- Mesh node can reach internet CoAP server
- MQTT-SN → MQTT bridging works

---

### Phase 8: Tooling & Testing (Weeks 24-26)

#### 8.1 Packet Craft CLI

```bash
# Craft a CoAP GET request
$ packet-craft coap --method GET --uri /sensors/temp \
    --compress rule0 --sign mykey.pem \
    --output packet.bin

# Parse a captured packet
$ packet-craft parse --input capture.bin --keys keys/
```

#### 8.2 Wireshark Dissector

Lua plugin for:
- LoRa link layer
- SCHC decompression
- RPL control messages
- CoAP with OSCORE

#### 8.3 Network Simulator

```rust
// mesh-sim/src/lib.rs
pub struct Simulator {
    pub nodes: Vec<SimNode>,
    pub topology: Topology,  // Distance matrix, path loss model
    pub time: SimTime,
}

impl Simulator {
    pub fn run(&mut self, duration: Duration);
    pub fn inject_fault(&mut self, node: NodeId, fault: Fault);
    pub fn collect_metrics(&self) -> Metrics;
}
```

Scenarios:
- Mesh formation time
- Convergence after node failure
- Throughput vs. hop count
- Duty cycle compliance

#### 8.4 Hardware-in-Loop Testing

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Dev Board 1 │────│  Dev Board 2 │────│  Dev Board 3 │
│  (STM32WL)   │RF  │  (nRF52840)  │RF  │  (ESP32+SX)  │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────────────┴────────────────────┘
                           │
                    ┌──────┴───────┐
                    │  Test Runner │
                    │  (pytest)    │
                    └──────────────┘
```

**Exit Criteria:**
- All components have unit tests (>80% coverage)
- Interop tests pass between Rust and C implementations
- Simulator reproduces known failure modes
- Hardware tests pass on 3 different MCU families

---

## 3. IETF-Style I-D Documents

| Document | Content | Target Completion |
|----------|---------|-------------------|
| `draft-lora-link-01.md` | Link layer frame format, LLSec, signatures | Phase 1 |
| `draft-lora-schc-01.md` | SCHC rules profile for LoRa IPv6 mesh | Phase 2 |
| `draft-lora-rpl-01.md` | RPL configuration, MRHOF parameters, 6LoRH | Phase 4 |
| `draft-lora-security-01.md` | Ed25519 truncation, OSCORE profile, key bootstrap | Phase 5 |
| `draft-lora-coap-01.md` | CoAP usage, Resource Directory profile | Phase 6 |
| `draft-lora-border-01.md` | Border router behavior, prefix delegation | Phase 7 |

### I-D Format Template

```markdown
# <Document Title>

**draft-lora-<component>-<version>**

**Status:** Informational (or Standards Track)
**Updates:** (if applicable)
**Obsoletes:** (if applicable)

## Abstract

[Brief description]

## Status of This Memo

[Standard IETF boilerplate for Internet-Draft]

## Table of Contents

1. Introduction
2. Terminology
3. Protocol Description
4. Packet Formats
5. Security Considerations
6. IANA Considerations
7. References
   7.1. Normative References
   7.2. Informative References
8. Acknowledgments

## 1. Introduction

[Context and motivation]

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

...
```

---

## 4. Hardware Requirements

### Development Boards (per developer)

| Board | MCU | Radio | Use |
|-------|-----|-------|-----|
| STM32WL Nucleo | STM32WL55 | Integrated SX126x | Primary dev |
| nRF52840 DK | nRF52840 | External SX1262 | BLE gateway tests |
| ESP32-S3 DevKit | ESP32-S3 | External SX1262 | WiFi border router |
| Heltec LoRa 32 V3 | ESP32-S3 | Integrated SX1262 | Cheap node testing |

### Test Lab (shared)

- 5× STM32WL boards for mesh testing
- 2× Raspberry Pi 4 (border router development)
- RF attenuators (for controlled link quality tests)
- Spectrum analyzer (optional, for regulatory compliance)

### Budget Estimate

| Item | Qty | Unit Cost | Total |
|------|-----|-----------|-------|
| STM32WL Nucleo | 8 | $50 | $400 |
| nRF52840 DK | 2 | $50 | $100 |
| ESP32-S3 + SX1262 | 4 | $25 | $100 |
| Heltec LoRa 32 V3 | 5 | $20 | $100 |
| Raspberry Pi 4 | 2 | $75 | $150 |
| RF attenuators | 4 | $30 | $120 |
| Antennas, cables, misc | - | - | $150 |
| **Total** | | | **~$1,120** |

---

## 5. Dependencies and Existing Code

### Rust Crates

| Crate | Use | License |
|-------|-----|---------|
| `embedded-hal` | Hardware abstraction | MIT/Apache-2.0 |
| `sx126x-rs` | SX1261/62 driver | MIT |
| `ed25519-dalek` | Signatures | BSD-3 |
| `aes-gcm` | AES-CCM (OSCORE) | MIT/Apache-2.0 |
| `coap-lite` | CoAP parsing (reference) | MIT |
| `smoltcp` | IP stack (reference) | 0BSD |

### C Libraries

| Library | Use | License |
|---------|-----|---------|
| `libschc` | SCHC reference | MIT |
| `liblwm2m` | LwM2M (future) | EPL/EDL |
| `monocypher` | Ed25519, AES | Public domain |
| `micro-ecc` | ECDSA fallback | BSD-2 |

### What We Build From Scratch

| Component | Reason |
|-----------|--------|
| Link layer | Custom frame format not in existing libs |
| Truncated Ed25519 | Non-standard truncation scheme |
| RPL for LoRa | Existing impls assume 802.15.4 timing |
| SCHC rules | Custom rule set for this profile |

---

## 6. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Truncated Ed25519 security concerns | High | Medium | Document security analysis; offer ECDSA fallback |
| RPL convergence too slow for LoRa | Medium | Medium | Tune Trickle parameters; test with simulator first |
| SCHC fragmentation complexity | Medium | Low | Start with ACK-on-Error; defer ACK-always |
| Hardware radio bugs | Low | Medium | Test on multiple radio chips early |
| Memory too tight on STM32WL | Medium | Low | Profile early; optimize hot paths in C |
| Duty cycle violations in EU | High | Low | Build duty cycle tracker into link layer |

---

## 7. Success Criteria

### Minimum Viable Network (MVP)

1. 3+ nodes form stable DODAG
2. Leaf node sends CoAP temperature reading to border router
3. Border router forwards to internet CoAP client
4. All traffic authenticated (Ed25519 link signatures)
5. SCHC compression < 15 bytes for typical telemetry

### Production Ready (v1.0)

1. 50+ node mesh stable over 24 hours
2. OSCORE encryption on all CoAP traffic
3. Automatic parent switching on link failure (<30 seconds)
4. MQTT-SN gateway operational
5. C implementation running on STM32WL (< 64KB RAM)
6. Full test vector compatibility between Rust and C
7. All 6 I-Ds complete and reviewed

---

## 8. Open Questions

1. **Truncated Ed25519 implementation:** Spec mentions deterministic derivation of second half. Need to specify exact algorithm. Consider RFC 8032 deterministic signing variant.

2. **SCHC rule distribution:** How do new nodes learn compression rules? Options:
   - Pre-provisioned (current assumption)
   - SCHC Rule ID negotiation (complex)
   - Simple version field in DIO

3. **Time synchronization:** Nodes need rough time sync for:
   - Replay window (SeqNum rollover)
   - Duty cycle tracking
   - Options: NTP over CoAP, GPS, piggyback on DIO

4. **Global prefix source:** Border router needs /64. Options:
   - Static configuration
   - DHCPv6-PD from upstream
   - ULA (fd00::/8) for isolated mesh

5. **Backward compatibility:** Spec says non-goal, but should we at least interop with standard 6LoWPAN/RPL implementations (e.g., Contiki-NG) at IP layer?

---

## 9. Team Structure (Suggested)

| Role | Responsibility |
|------|----------------|
| Protocol Lead | Spec interpretation, I-D authorship, security review |
| Rust Lead | Core Rust implementation, workspace management |
| Embedded Lead | C implementation, MCU porting, memory optimization |
| Test Lead | Simulator, test vectors, hardware-in-loop |
| Integration Lead | Border router, gateway, tooling |

---

## 10. Next Steps

1. **Immediate:** Review this plan, resolve open questions
2. **Week 1:** Set up repos, CI/CD, assign Phase 0 tasks
3. **Week 2:** First I-D drafts ready for review
4. **Week 3:** Begin Phase 1 implementation

---

*This plan is a living document. Update as implementation reveals new constraints.*
