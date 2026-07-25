# Plan: Bead Out Full Spec Implementation Across All Three Languages

**Status:** Draft plan, not yet filed as beads  
**Date:** 2026-07-24  
**Blocked by:** User approval before filing

## Problem

The spec exists (13 chapters + appendices). Three implementations exist (Python, Rust, Zephyr/C). But there's no systematic tracking of "is the spec fully implemented in all three?"

What we have:
- Parity audit (closed) — checked existing code matches across impls, filed gaps
- Ad-hoc gap beads — specific missing features
- Feature beads — individual enhancements

What we don't have:
- Master epic tracking spec completeness
- Per-chapter breakdown with per-language tasks
- Clear "done" criteria per spec section

## Proposed Structure

### Granularity Levels

The plan supports two granularity levels:

| Level | Description | Bead count | When to use |
|-------|-------------|------------|-------------|
| **Scaffolding** | Chapter epics + "complete X in language Y" tasks | ~47 | Initial tracking structure |
| **Implementation** | Per-feature, per-rule, per-protocol tasks | ~300-400 | Actual work breakdown |

**Start with scaffolding**, then explode each coarse task into implementation-level sub-beads as work begins on that chapter. Don't file 400 beads upfront — file the structure, then decompose on demand.

### Horizontal Slices (Chapters)

One P0 epic with per-chapter sub-epics. Each chapter epic has:
- One task per language (Python, Rust, Zephyr)
- One task for shared test vectors
- One task for cross-validation

### Vertical Slices (Thrulines)

Cross-cutting concerns that span multiple chapters get their own P1 epics:
- **Yggdrasil 200::/7** — address derivation, stability, routing (Ch04/05/06/08)
- **OSCORE E2E** — compression + encryption + CoAP integration (Ch03/06/07)
- **Key lifecycle** — identity, link, OSCORE keys across layers (Ch02/06/Ygg)
- **CCP time sync** — GNSS-PPS, NTP, drift, routing implications (Ch02a/05/gateway)

These reference chapter tasks but track end-to-end correctness separately.

### Master Epic

```
[P0 epic] Implement LICHEN spec v0.1 across all implementations
├── [P1 epic] Chapter 02: Physical and Link Layer
│   ├── [P1] Python: link layer complete
│   ├── [P1] Rust: link layer complete  
│   ├── [P1] Zephyr: link layer complete
│   ├── [P1] Vectors: link layer test vectors
│   └── [P1] Cross-validate: link layer parity
├── [P1 epic] Chapter 02a: Coordinated Capacity Profile (CCP)
│   ├── ...
├── [P1 epic] Chapter 03: Adaptation Layer (SCHC)
│   ├── ...
... (chapters 04-13)
└── [P2 epic] Appendices
    ├── ...
```

## Per-Chapter Breakdown

### Chapter 01: Architecture
**Scope:** Design principles, no implementation artifacts  
**Tracking needed:** None (informative only)

### Chapter 02: Physical and Link Layer
**Spec sections:**
- 2.1 LoRa PHY parameters (SF10, 125kHz, CR4/5)
- 2.2 Frame format (version, flags, addresses, payload, MIC)
- 2.3 Link-layer addressing (EUI-64 from pubkey)
- 2.4 Replay protection (32-bit sequence, per-peer windows)
- 2.5 Schnorr signatures (48-byte truncated)

**Current status (from parity audit):**
- Python: Complete (reference impl)
- Rust: Complete (lichen-link crate)
- Zephyr: Complete (lichen_l2 subsys)
- Vectors: `test/vectors/link-*.json` exist

**Remaining work:**
- Verify all edge cases covered in vectors
- Cross-validate replay window semantics

### Chapter 02a: Coordinated Capacity Profile (CCP)
**Spec sections:**
- Time synchronization (GNSS-PPS, NTP fallback)
- Channel plan negotiation
- Scheduled vs unscheduled capacity
- Multi-channel rendezvous

**Current status:**
- Python: Partial (simulator models exist)
- Rust: Not started
- Zephyr: Not started
- Vectors: None

**Remaining work:**
- `project-LICHEN-da2q.2` (All impls: CCP multi-channel) — already beaded
- `project-LICHEN-i9r0.3` (All impls: GNSS-PPS CCP) — already beaded
- Need vectors before impl

### Chapter 03: Adaptation Layer (SCHC)
**Spec sections:**
- SCHC compression rules 1-6
- Fragmentation/reassembly (RFC 8724 ACK-on-Error)
- Context matching
- Rule ID encoding

**Current status (from parity audit):**
- Python: Complete (uses OpenSCHC patterns)
- Rust: Partial — missing some headers/context (`project-LICHEN-qopb`)
- Zephyr: Partial — missing fragmentation (`project-LICHEN-bcds`)
- Vectors: `test/vectors/schc-*.json` exist but incomplete

**Remaining work:**
- `project-LICHEN-hwx9` [epic] Standardize RFC 8724 fragmentation — already beaded
- `project-LICHEN-vsiw` Specify SCHC Rules 5 and 6 — already beaded
- Need fragmentation vectors

### Chapter 04: Network Layer (IPv6)
**Spec sections:**
- Link-local addressing (fe80::/10 from EUI-64)
- Yggdrasil 200::/7 addresses
- ICMPv6 (Echo, unreachable)
- Neighbor discovery (minimal)

**Current status:**
- Python: Complete
- Rust: Complete
- Zephyr: Partial — missing ICMPv6 (`project-LICHEN-u54o`)
- Vectors: Minimal

**Remaining work:**
- Zephyr ICMPv6 implementation
- IPv6 address derivation vectors

### Chapter 05: Routing
**Spec sections:**
- Three-tier architecture (RPL + Announce + LOADng)
- RPL: DODAG formation, DIO/DAO/DIS
- Announce: gradient-based peer routing
- LOADng: reactive fallback

**Current status:**
- Python: Complete (simulator)
- Rust: Partial — DAO less complete (`project-LICHEN-r6r8`)
- Zephyr: Partial — RPL stub, needs DODAG root
- Vectors: RPL message vectors exist

**Remaining work:**
- `project-LICHEN-p2y5` [epic] Border router: RPL root — already beaded
- `project-LICHEN-2auf.44.9` Support prefix DAO targets — already beaded
- LOADng vectors needed

### Chapter 06: Security
**Spec sections:**
- Key hierarchy (identity, link, OSCORE)
- EDHOC key exchange
- OSCORE message protection
- Group OSCORE (optional)

**Current status:**
- Python: Complete
- Rust: Partial — OSCORE needs RFC 8613 AAD (`project-LICHEN-2okc`)
- Zephyr: Complete (oscore subsys)
- Vectors: OSCORE vectors exist, EDHOC vectors partial

**Remaining work:**
- Rust OSCORE AAD fix
- EDHOC full handshake vectors
- `project-LICHEN-r9pz` Add cross-language OSCORE SCHC vectors — already beaded

### Chapter 07: Transport and Application
**Spec sections:**
- UDP (native)
- CoAP (RFC 7252 + block transfer)
- MQTT-SN (optional)
- Resource Directory

**Current status:**
- Python: Complete
- Rust: Complete (lichen-coap)
- Zephyr: Partial — needs CoAP server (`project-LICHEN-o6pb`)
- Vectors: CoAP message vectors exist

**Remaining work:**
- Zephyr CoAP server implementation
- Block transfer verification (`project-LICHEN-k1p9`)

### Chapter 08: Node Types
**Scope:** Role definitions (puck, bridge, gateway)  
**Tracking needed:** None (informative, roles implemented via feature sets)

### Chapter 09: Packets and Timing
**Spec sections:**
- Packet size budgets
- Duty cycle limits
- Airtime calculations
- Timing constraints

**Current status:**
- Python: Complete (simulator enforces)
- Rust: Partial
- Zephyr: Partial
- Vectors: Timing calculation vectors needed

**Remaining work:**
- Airtime calculation vectors
- Duty cycle enforcement tests

### Chapter 10: Implementation Notes
**Scope:** Guidance, not normative  
**Tracking needed:** None (informative)

### Chapter 11: Local Client Interface (LCI)
**Spec sections:**
- KISS framing
- BLE GATT profile
- USB CDC
- Native app protocol

**Current status:**
- Python: Partial
- Rust: Not started (apps/lichen-cli uses different approach)
- Zephyr: Partial (BLE exists)
- Vectors: None

**Remaining work:**
- `project-LICHEN-jtup` Align Python LCI with mandatory CoAP proxying — already beaded
- LCI message vectors needed

### Chapter 12: Applications
**Spec sections:**
- Messaging (/messages)
- Presence (/presence)
- Location (/location)
- SOS (/sos)
- Sensor data (SenML)

**Current status:**
- Python: Complete
- Rust: Complete (lichen-apps)
- Zephyr: Partial
- Vectors: SenML vectors exist

**Remaining work:**
- `lora_ipv6_mesh-mfir` CLI calls paths firmware doesn't expose — already beaded
- Application message vectors

### Chapter 13: (none — spec ends at 12)

### Appendices
- **A (SCHC Rules):** Covered by Chapter 03 work
- **B (RPL Config):** Covered by Chapter 05 work
- **B2 (LOADng Config):** Needs implementation tracking
- **C-E (Misc):** Informative
- **F (SenML):** Covered by Chapter 12 work
- **G (Design Rationale):** Informative
- **H (Bufferbloat):** Implementation guidance, verify compliance
- **I (Border Router HW):** Informative
- **J (C Safety):** Compliance check, not implementation

### Example: Chapter 03 at Implementation Granularity

This shows what "exploding" a chapter epic looks like. Chapter 03 (SCHC) goes from 5 scaffolding beads to ~91 implementation beads:

```
[P1 epic] Chapter 03: Adaptation Layer (SCHC)
├── [P1 epic] SCHC Compression
│   ├── [P1 epic] Rule 1: IPv6/UDP Full
│   │   ├── [P1] Python: Rule 1 compression
│   │   ├── [P1] Python: Rule 1 decompression
│   │   ├── [P1] Rust: Rule 1 compression
│   │   ├── [P1] Rust: Rule 1 decompression
│   │   ├── [P1] Zephyr: Rule 1 compression
│   │   ├── [P1] Zephyr: Rule 1 decompression
│   │   └── [P1] Vectors: Rule 1 test cases
│   ├── [P1 epic] Rule 2: IPv6/UDP Compressed
│   │   └── ... (same 7 tasks)
│   ├── [P1 epic] Rule 3: IPv6/UDP Link-local
│   ├── [P1 epic] Rule 4: CoAP
│   ├── [P2 epic] Rule 5: OSCORE (optional per spec)
│   ├── [P2 epic] Rule 6: EDHOC (optional per spec)
│   ├── [P1] Context matching: rule selection logic
│   ├── [P1] Rule ID encoding: variable-length wire format
│   └── [P2] Cross-validate: compression parity
│
├── [P1 epic] SCHC Fragmentation (RFC 8724 ACK-on-Error)
│   ├── [P1 epic] Fragment transmission
│   │   ├── [P1] Python: fragment generation
│   │   ├── [P1] Rust: fragment generation
│   │   ├── [P1] Zephyr: fragment generation
│   │   ├── [P1] Tile sizing for LoRa MTU
│   │   └── [P1] Vectors: fragmentation test cases
│   ├── [P1 epic] Reassembly
│   │   ├── [P1] Python: reassembly state machine
│   │   ├── [P1] Rust: reassembly state machine
│   │   ├── [P1] Zephyr: reassembly state machine
│   │   ├── [P1] Out-of-order tile handling
│   │   ├── [P1] Duplicate tile detection
│   │   └── [P1] Vectors: reassembly test cases
│   ├── [P1 epic] ACK handling
│   │   ├── [P1] Python: ACK generation + processing
│   │   ├── [P1] Rust: ACK generation + processing
│   │   ├── [P1] Zephyr: ACK generation + processing
│   │   ├── [P1] Bitmap encoding/decoding
│   │   └── [P1] Vectors: ACK round-trip cases
│   ├── [P1 epic] Timeouts and errors
│   │   ├── [P1] Retransmission timer logic
│   │   ├── [P1] Inactivity timeout
│   │   ├── [P1] Abort handling (sender + receiver)
│   │   ├── [P2] Max-retry exhaustion behavior
│   │   └── [P1] Vectors: timeout/error scenarios
│   └── [P2] Cross-validate: fragmentation interop
│
├── [P1 epic] Integration
│   ├── [P1] Python: SCHC ↔ link layer integration
│   ├── [P1] Rust: SCHC ↔ link layer integration
│   ├── [P1] Zephyr: SCHC ↔ link layer integration
│   ├── [P2] Memory budget verification (Zephyr)
│   └── [P2] Reassembly buffer exhaustion handling
│
└── [P2 epic] Edge cases / hardening
    ├── [P2] Malformed Rule ID handling
    ├── [P2] Truncated fragment handling
    ├── [P2] Context mismatch recovery
    ├── [P2] Interleaved fragment streams
    └── [P2] Fuzz vectors: malformed SCHC packets
```

**Chapter 03 bead count:** ~63 P1 + ~28 P2 = ~91 total

Apply similar explosion to other chapters. Estimated multipliers:

| Chapter | Scaffolding | Multiplier | Implementation |
|---------|-------------|------------|----------------|
| 02 Link | 2 | 41× | 82 |
| 02a CCP | 5 | 27× | 134 |
| 03 SCHC | 5 | 18× | 91 |
| 04 IPv6 | 3 | 32× | 95 |
| 05 Routing | 5 | 29× | 144 |
| 06 Security | 4 | 27× | 107 |
| 07 Transport | 4 | 30× | 120 |
| 09 Timing | 3 | 34× | 103 |
| 11 LCI | 5 | 25× | 127 |
| 12 Apps | 3 | 49× | 147 |
| **Chapters total** | 47 | | **1150** |
| **+ Thrulines** | 4 | | ~92 |
| **Grand total** | **51** | | **~1242** |

**Note:** Counts include already-done items (marked `[DONE]`) for tracking completeness. See [spec-chapter-breakdowns.md](spec-chapter-breakdowns.md) for full trees.

## What's Already Beaded vs. What's Missing

### Already beaded (found in search):
- CCP multi-channel: `project-LICHEN-da2q.2`
- CCP GNSS-PPS: `project-LICHEN-i9r0.3`
- SCHC fragmentation: `project-LICHEN-hwx9`
- SCHC rules 5-6: `project-LICHEN-vsiw`
- Border router RPL: `project-LICHEN-p2y5`
- OSCORE vectors: `project-LICHEN-r9pz`
- Various gap bugs from parity audit

### Missing (need to file):
1. **Master tracking epic** — the umbrella
2. **Per-chapter status tracking** — which chapters are done in which languages
3. **Cross-validation tasks** — explicitly run same vectors through all three
4. **Vector completeness audit** — what vectors are missing per chapter
5. **Cross-cutting thrulines** — vertical slices that span chapters

## Cross-Cutting Thrulines

These are vertical epics that track end-to-end correctness across chapter boundaries. File as siblings to chapter epics under the master epic.

### Thruline 1: Yggdrasil 200::/7 Address Assurance

**Why separate:** Address derivation spans Ch04 (IPv6), Ch05 (routing), Ch06 (keys), Ch08 (gateway). A chapter-only view could miss cross-impl parity.

**Spec refs:** Ch04 §4.2 (Yggdrasil addressing), Ch06 §6.1 (identity keys)

```
[P1 epic] Yggdrasil 200::/7 address assurance
├── [P1 epic] Key → address derivation
│   ├── [P1] Python: ed25519 pubkey → 200::/7 address
│   ├── [P1] Rust: ed25519 pubkey → 200::/7 address
│   ├── [P1] Zephyr: ed25519 pubkey → 200::/7 address
│   ├── [P1] Vectors: known keys → expected addresses (10+ cases)
│   └── [P1] Cross-validate: same key → same address in all impls
├── [P1 epic] Address stability
│   ├── [P1] Persistent identity key across reboots
│   ├── [P1] Deterministic address from cold start
│   ├── [P2] Key rotation → address change propagation
│   └── [P1] Vectors: stability test scenarios
├── [P1 epic] Routing integration
│   ├── [P1] 200::/7 prefix in RPL DODAG
│   ├── [P1] Gateway advertises Ygg reachability
│   ├── [P1] Route selection: Ygg vs link-local paths
│   └── [P2] Mixed fe80 + 200::/7 in same DODAG
├── [P2 epic] Gateway ↔ Yggdrasil network
│   ├── [P2] Outbound: mesh node → Ygg peer (via gateway)
│   ├── [P2] Inbound: Ygg peer → mesh node (via gateway)
│   └── [P2] Ygg peering state visibility
└── [P2 epic] Edge cases
    ├── [P2] Address collision detection
    ├── [P2] Collision with non-LICHEN Ygg node
    └── [P2] Malformed pubkey handling
```

**Bead count:** ~20 P1 + ~8 P2 = ~28

### Thruline 2: OSCORE End-to-End

**Why separate:** OSCORE touches Ch03 (SCHC compression of OSCORE), Ch06 (OSCORE crypto), Ch07 (CoAP protection). Full path must work together.

**Spec refs:** Ch06 §6.3 (OSCORE), Ch03 Appendix A Rule 5, Ch07 §7.1

```
[P1 epic] OSCORE end-to-end assurance
├── [P1 epic] OSCORE message protection
│   ├── [P1] Python: encrypt + decrypt
│   ├── [P1] Rust: encrypt + decrypt (fix AAD per project-LICHEN-2okc)
│   ├── [P1] Zephyr: encrypt + decrypt
│   ├── [P1] Vectors: RFC 8613 test vectors
│   └── [P1] Cross-validate: ciphertext parity
├── [P1 epic] OSCORE + CoAP integration
│   ├── [P1] Protected CoAP request/response round-trip
│   ├── [P1] Block transfer with OSCORE
│   ├── [P1] Observe with OSCORE
│   └── [P1] Vectors: full CoAP+OSCORE exchanges
├── [P1 epic] OSCORE + SCHC compression
│   ├── [P1] Rule 5 compression of OSCORE messages
│   ├── [P1] Compressed OSCORE round-trip
│   └── [P1] Vectors: SCHC-compressed OSCORE (per project-LICHEN-r9pz)
├── [P2 epic] OSCORE context management
│   ├── [P2] Sender/recipient ID assignment
│   ├── [P2] Sequence number rollover
│   ├── [P2] Replay window enforcement
│   └── [P2] Context expiration / refresh
└── [P2 epic] Group OSCORE (if implemented)
    ├── [P2] Group key distribution
    ├── [P2] Multicast protection
    └── [P2] Vectors: group scenarios
```

**Bead count:** ~18 P1 + ~10 P2 = ~28

### Thruline 3: Key Lifecycle

**Why separate:** Keys feed into link layer (Schnorr), OSCORE, EDHOC, and Yggdrasil addresses. Lifecycle (generation, storage, rotation, revocation) must be consistent.

**Spec refs:** Ch02 §2.5 (link keys), Ch06 §6.1-6.2 (key hierarchy, EDHOC)

```
[P1 epic] Key lifecycle assurance
├── [P1 epic] Identity key management
│   ├── [P1] Generation: ed25519 keypair
│   ├── [P1] Storage: secure persistence
│   ├── [P1] Export: for Ygg address derivation
│   └── [P1] Vectors: key generation determinism
├── [P1 epic] Link key derivation
│   ├── [P1] Schnorr signing key from identity
│   ├── [P1] Per-peer link keys
│   └── [P1] Vectors: derivation consistency
├── [P1 epic] EDHOC key exchange
│   ├── [P1] Full handshake (all 3 impls)
│   ├── [P1] Session resumption
│   ├── [P1] Vectors: EDHOC message sequences
│   └── [P1] Cross-validate: derived secrets match
├── [P1 epic] OSCORE key derivation
│   ├── [P1] Master secret → sender/recipient keys
│   ├── [P1] Key update procedure
│   └── [P1] Vectors: OSCORE key derivation
└── [P2 epic] Key rotation / revocation
    ├── [P2] Identity key rotation procedure
    ├── [P2] Propagation of key change
    ├── [P2] Revocation announcement
    └── [P2] Stale key rejection
```

**Bead count:** ~16 P1 + ~4 P2 = ~20

### Thruline 4: CCP Time Synchronization

**Why separate:** CCP (Ch02a) depends on time sync, which affects routing (Ch05 timed announcements) and gateway behavior. Time errors cascade.

**Spec refs:** Ch02a §2a.1 (time sync), Ch05 §5.x (timed routing)

```
[P2 epic] CCP time synchronization assurance
├── [P2 epic] Time sources
│   ├── [P2] GNSS-PPS acquisition
│   ├── [P2] NTP fallback
│   ├── [P2] Source priority / failover
│   └── [P2] Vectors: time source scenarios
├── [P2 epic] Time distribution
│   ├── [P2] Beacon time field
│   ├── [P2] Receiver clock discipline
│   ├── [P2] Drift estimation
│   └── [P2] Vectors: sync convergence
├── [P2 epic] Desync handling
│   ├── [P2] Desync detection
│   ├── [P2] Recovery state machine (per CCP-13a)
│   ├── [P2] Graceful degradation
│   └── [P2] Vectors: desync recovery scenarios
└── [P2 epic] Routing implications
    ├── [P2] Scheduled slot validity
    ├── [P2] Stale schedule rejection
    └── [P2] Time-aware route selection
```

**Bead count:** ~0 P1 + ~16 P2 = ~16 (all P2 because CCP is optional)

### Thruline Summary

| Thruline | P1 | P2 | Total |
|----------|----|----|-------|
| Yggdrasil 200::/7 | 20 | 8 | 28 |
| OSCORE E2E | 18 | 10 | 28 |
| Key lifecycle | 16 | 4 | 20 |
| CCP time sync | 0 | 16 | 16 |
| **Thrulines total** | **54** | **38** | **92** |

## Recommended Filing Order

1. File master epic (P0, blocks nothing)
2. File chapter epics as children (P1/P2 per table)
3. File thruline epics as siblings to chapters (P1/P2)
4. Link existing beads as children where they fit
5. Cross-reference beads to thrulines where relevant
6. File new per-language tasks only for gaps not already beaded
7. File vector tasks for chapters without adequate vectors
8. Explode to implementation granularity on-demand (not upfront)

## Acceptance Criteria for "Spec Implemented"

Per chapter:
- [ ] Python implementation passes all vectors
- [ ] Rust implementation passes all vectors
- [ ] Zephyr implementation passes all vectors
- [ ] Cross-language interop test passes (if applicable)
- [ ] No known spec divergences

Per thruline:
- [ ] All sub-epics closed
- [ ] Cross-impl parity verified (same input → same output)
- [ ] Integration tests pass end-to-end

Master epic:
- [ ] All chapter epics closed
- [ ] All thruline epics closed
- [ ] Feature matrix shows 100% coverage
- [ ] CI runs all three against shared vectors

## Estimated Bead Counts

| Category | Scaffolding | Implementation |
|----------|-------------|----------------|
| Chapters (horizontal) | ~47 | ~1150 |
| Thrulines (vertical) | ~4 epics | ~92 |
| **Total** | **~51** | **~1242** |

**Breakdown by chapter (implementation granularity):**

| Chapter | P1 | P2 | Total |
|---------|----|----|-------|
| 02 Physical/Link | 55 | 27 | 82 |
| 02a CCP | 28 | 106 | 134 |
| 03 SCHC | 63 | 28 | 91 |
| 04 IPv6 | 47 | 48 | 95 |
| 05 Routing | 108 | 36 | 144 |
| 06 Security | 71 | 36 | 107 |
| 07 Transport/App | 78 | 42 | 120 |
| 09 Packets/Timing | 72 | 31 | 103 |
| 11 LCI | 92 | 35 | 127 |
| 12 Applications | 76 | 71 | 147 |
| **Chapters** | **690** | **460** | **1150** |
| **+ Thrulines** | ~54 | ~38 | ~92 |
| **Grand Total** | **~744** | **~498** | **~1242** |

File scaffolding first (~51 beads). Explode on-demand as work starts.

**Full detailed breakdowns:** See [spec-chapter-breakdowns.md](spec-chapter-breakdowns.md) for complete epic/task trees for all chapters.

## Open Questions

1. **Should CCP (Chapter 02a) be P1 or P2?** It's optional in the spec. Currently beaded as P2.

2. **What about DTN (only in Zephyr)?** Per parity audit, DTN is Zephyr-only. Is this spec-compliant or a gap?

3. ~~**How to handle "partial" implementations?** Some features exist but edge cases are missing. Per-feature sub-beads or one "complete chapter X" bead?~~ **Resolved:** File scaffolding first, explode to implementation granularity when starting work on a chapter.

4. **LCI chapter is underspecified.** The spec says "KISS framing" but implementations vary. Spec gap or implementation gap?

5. **When to explode scaffolding → implementation?** When an agent claims a chapter epic, it should first explode that chapter to implementation-level beads (per the Ch03 example), then work through the sub-beads.

---

## Agent Prompt: Explode This Plan Into Beads

Copy the prompt below and give it to an agent to file all beads systematically.

---

```markdown
# Task: File Beads for Full Spec Implementation Tracking

You are filing beads to track implementing the LICHEN spec (v0.1) across all three implementations: Python, Rust, and Zephyr/C.

## Context

Read `docs/spec-implementation-plan.md` for the full breakdown. The spec has 12 chapters plus appendices. Some work is already beaded; you will link existing beads and file new ones for gaps.

## Instructions

### Step 1: File Master Epic

```bash
bd new --type epic --priority P0 \
  --title "Implement LICHEN spec v0.1 across all implementations" \
  --description "Track full spec implementation in Python, Rust, and Zephyr. Each chapter gets a sub-epic with per-language tasks and shared test vectors. Acceptance: all chapters closed, feature matrix 100%, CI validates all three against shared vectors."
```

Save the returned ID as MASTER_EPIC.

### Step 2: File Chapter Epics

For each normative chapter (skip 01, 08, 10 — informative only), file a sub-epic under MASTER_EPIC:

| Chapter | Title | Priority | Notes |
|---------|-------|----------|-------|
| 02 | Physical and Link Layer | P1 | Core, mostly complete |
| 02a | Coordinated Capacity Profile (CCP) | P2 | Optional feature |
| 03 | Adaptation Layer (SCHC) | P1 | Has existing beads |
| 04 | Network Layer (IPv6) | P1 | Zephyr ICMPv6 gap |
| 05 | Routing | P1 | Has existing beads |
| 06 | Security | P1 | Rust OSCORE gap |
| 07 | Transport and Application | P1 | Zephyr CoAP server gap |
| 09 | Packets and Timing | P2 | Vectors needed |
| 11 | Local Client Interface | P2 | Underspecified |
| 12 | Applications | P1 | Partial Zephyr |

For each, run:
```bash
bd new --type epic --priority <PRIORITY> --parent <MASTER_EPIC> \
  --title "Chapter XX: <Title>" \
  --description "<From plan: spec sections, current status, remaining work>"
```

### Step 3: File Per-Language Tasks Under Each Chapter Epic

For chapters that are NOT already complete in all three languages, file tasks:

**Template per language:**
```bash
bd new --type task --priority P1 --parent <CHAPTER_EPIC> \
  --title "Python: <chapter short name> complete" \
  --description "Implement all spec sections from chapter XX in Python. Pass all shared test vectors. Acceptance: pytest passes, no spec divergences."
```

Repeat for Rust and Zephyr. Adjust title/description per language idioms.

**Skip filing if already complete** (per plan):
- Chapter 02: Python ✓, Rust ✓, Zephyr ✓ — file only cross-validation
- Chapter 04: Python ✓, Rust ✓ — file only Zephyr ICMPv6
- Chapter 06: Python ✓, Zephyr ✓ — file only Rust OSCORE
- Chapter 07: Python ✓, Rust ✓ — file only Zephyr CoAP server
- Chapter 12: Python ✓, Rust ✓ — file only Zephyr apps

### Step 4: File Test Vector Tasks

For each chapter epic, file:
```bash
bd new --type task --priority P1 --parent <CHAPTER_EPIC> \
  --title "Vectors: <chapter short name> test vectors" \
  --description "Create/complete test vectors in test/vectors/ for chapter XX. Cover: <list spec sections>. Format: JSON with inputs, expected outputs, edge cases. All three implementations must pass."
```

### Step 5: File Cross-Validation Tasks

For each chapter epic, file:
```bash
bd new --type task --priority P2 --parent <CHAPTER_EPIC> \
  --title "Cross-validate: <chapter short name> parity" \
  --description "Run identical inputs through Python, Rust, and Zephyr implementations. Verify outputs match. Document any spec ambiguities found. Acceptance: zero divergences or spec clarifications filed."
```

### Step 6: File Thruline Epics

File the four cross-cutting thrulines as siblings to chapter epics under MASTER_EPIC:

```bash
# Yggdrasil
bd new --type epic --priority P1 --parent <MASTER_EPIC> \
  --title "Thruline: Yggdrasil 200::/7 address assurance" \
  --description "Cross-cutting: verify Ygg address derivation, stability, and routing across all impls. Spans Ch04/05/06/08. Key → 200::/7 must be identical in Python/Rust/Zephyr."

# OSCORE E2E
bd new --type epic --priority P1 --parent <MASTER_EPIC> \
  --title "Thruline: OSCORE end-to-end assurance" \
  --description "Cross-cutting: OSCORE message protection + CoAP integration + SCHC compression. Spans Ch03/06/07. Full protected round-trip must work."

# Key lifecycle
bd new --type epic --priority P1 --parent <MASTER_EPIC> \
  --title "Thruline: Key lifecycle assurance" \
  --description "Cross-cutting: identity keys, link keys, EDHOC, OSCORE keys. Spans Ch02/06/Ygg. Generation, storage, derivation, rotation must be consistent."

# CCP time sync
bd new --type epic --priority P2 --parent <MASTER_EPIC> \
  --title "Thruline: CCP time synchronization assurance" \
  --description "Cross-cutting: GNSS-PPS, NTP, drift, desync recovery, routing implications. Spans Ch02a/05. P2 because CCP is optional."
```

Then file sub-epics and tasks per the thruline breakdowns in the plan. Reference (don't duplicate) chapter tasks where they overlap.

### Step 7: Link Existing Beads

These beads already exist and should be linked as children to the appropriate chapter epics (or thrulines where noted):

| Existing Bead | Link to Chapter |
|---------------|-----------------|
| `project-LICHEN-da2q.2` | Chapter 02a (CCP) |
| `project-LICHEN-i9r0.3` | Chapter 02a (CCP) |
| `project-LICHEN-hwx9` | Chapter 03 (SCHC) |
| `project-LICHEN-vsiw` | Chapter 03 (SCHC) |
| `project-LICHEN-qopb` | Chapter 03 (SCHC) — Rust gap |
| `project-LICHEN-bcds` | Chapter 03 (SCHC) — Zephyr gap |
| `project-LICHEN-u54o` | Chapter 04 (IPv6) — Zephyr ICMPv6 |
| `project-LICHEN-p2y5` | Chapter 05 (Routing) |
| `project-LICHEN-2auf.44.9` | Chapter 05 (Routing) |
| `project-LICHEN-r6r8` | Chapter 05 (Routing) — Rust DAO |
| `project-LICHEN-2okc` | Chapter 06 (Security) — Rust OSCORE |
| `project-LICHEN-r9pz` | Chapter 06 (Security) |
| `project-LICHEN-o6pb` | Chapter 07 (Transport) — Zephyr CoAP |
| `project-LICHEN-k1p9` | Chapter 07 (Transport) |
| `project-LICHEN-jtup` | Chapter 11 (LCI) |
| `lora_ipv6_mesh-mfir` | Chapter 12 (Apps) |

Also link to thrulines where relevant:
| Existing Bead | Also link to Thruline |
|---------------|----------------------|
| `project-LICHEN-2okc` | OSCORE E2E (Rust AAD fix) |
| `project-LICHEN-r9pz` | OSCORE E2E (SCHC vectors) |

To link:
```bash
bd update <EXISTING_BEAD_ID> --parent <CHAPTER_EPIC>
# For thruline cross-refs, add a note rather than reparenting:
bd update <EXISTING_BEAD_ID> --note "Also tracked under Thruline: OSCORE E2E"
```

### Step 8: Verify Structure

After filing, run:
```bash
bd show <MASTER_EPIC>
```

Confirm:
- Master epic has 10 chapter epic children + 4 thruline epic children
- Each chapter epic has: per-language tasks (where needed), vector task, cross-validation task
- Each thruline epic has: sub-epics per the plan breakdown
- Existing beads are linked appropriately
- Relevant beads are cross-referenced to thrulines
- No duplicate tasks for already-complete work

### Step 9: Report Summary

Output two tables:

**Chapters:**
| Chapter | Epic ID | Python | Rust | Zephyr | Vectors | Cross-val | Linked Existing |
|---------|---------|--------|------|--------|---------|-----------|-----------------|

**Thrulines:**
| Thruline | Epic ID | Sub-epics | Tasks | Cross-refs |
|----------|---------|-----------|-------|------------|

Mark each cell with the bead ID or "already complete" or "N/A".

## Rules

1. **Do not file duplicate beads.** If a task already exists (check `bd search`), link it instead of filing new.
2. **Skip informative chapters.** Chapters 01, 08, 10 have no implementation artifacts.
3. **Match priority to plan.** P1 for core, P2 for optional/deferred.
4. **Use consistent naming.** "Python: X complete", "Rust: X complete", "Zephyr: X complete", "Vectors: X test vectors", "Cross-validate: X parity".
5. **Include acceptance criteria** in every task description.
6. **Reference spec file** in epic descriptions: `spec/0X-*.md`.

## Acceptance Criteria for This Task

- [ ] Master epic filed
- [ ] 10 chapter epics filed as children
- [ ] 4 thruline epics filed as children
- [ ] Per-language tasks filed for incomplete implementations
- [ ] Vector tasks filed for all chapters
- [ ] Cross-validation tasks filed for all chapters
- [ ] 16+ existing beads linked to chapter epics
- [ ] Relevant beads cross-referenced to thrulines
- [ ] Summary tables output (chapters + thrulines)
- [ ] `bd show <MASTER_EPIC>` shows complete tree
```

---

## Next Steps

When ready to file, copy the agent prompt above and run it. The agent will systematically file all beads and link existing work.
