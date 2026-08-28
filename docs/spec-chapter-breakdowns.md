## Full Chapter Breakdowns (Implementation Granularity)

These breakdowns show the full bead structure when exploding scaffolding to implementation level.

### Chapter 02: Physical and Link Layer

**Scope:** LoRa PHY config, frame format, LLSec, Schnorr-48 signatures, replay protection, short address assignment

```
[P1 epic] Chapter 02: Physical and Link Layer
├── [P1 epic] 3.x Physical Layer Configuration
│   ├── [P2] Python: LoRa PHY parameters (SF/BW/CR config) [mostly done in radio drivers]
│   ├── [P2] Rust: LoRa PHY parameters (lichen-hal) [mostly done]
│   ├── [P2] Zephyr: LoRa PHY parameters [mostly done in sx126x driver]
│   ├── [P2 epic] Adaptive Data Rate (ADR) - spec 3.4
│   │   ├── [P2] Python: SNR tracking + SF adjustment
│   │   ├── [P2] Rust: SNR tracking + SF adjustment
│   │   ├── [P2] Zephyr: SNR tracking + SF adjustment
│   │   └── [P2] Vectors: ADR state transition test cases
│   └── [P2] Vectors: regional frequency plan validation
│
├── [P1 epic] 4.1 Frame Format
│   ├── [P1] Python: frame parse/serialize [DONE - link/frame.py]
│   ├── [P1] Rust: frame parse/serialize [DONE - lichen-link/frame.rs]
│   ├── [P1] Zephyr: frame parse/serialize [DONE - link/frame.c]
│   ├── [P1] Vectors: frame.json coverage [DONE - 11 vectors]
│   └── [P1] Cross-validate: roundtrip parity [DONE - shared vectors]
│
├── [P1 epic] 4.2 LLSec Byte Encoding
│   ├── [P1] Python: LLSec encode/decode [DONE]
│   ├── [P1] Rust: LLSec encode/decode [DONE]
│   ├── [P1] Zephyr: LLSec encode/decode [DONE]
│   ├── [P1 epic] Version 2 SenderID Field - spec 4.2
│   │   ├── [P1] Python: SenderID field (10-byte extended sender)
│   │   ├── [P1] Rust: SenderID field support
│   │   ├── [P1] Zephyr: SenderID field support
│   │   ├── [P1] Bit 7 / bit 5 parity validation
│   │   └── [P1] Vectors: Version 2 frame test cases
│   └── [P2] Vectors: reserved MIC length rejection
│
├── [P1 epic] 4.3 Addressing Modes
│   ├── [P1] Python: 4 addressing modes [DONE]
│   ├── [P1] Rust: 4 addressing modes [DONE]
│   ├── [P1] Zephyr: 4 addressing modes [DONE]
│   ├── [P2] Python: elided mode context derivation
│   ├── [P2] Rust: elided mode context derivation
│   ├── [P2] Zephyr: elided mode context derivation
│   └── [P1] Vectors: all 4 modes covered [PARTIAL - need elided]
│
├── [P1 epic] 4.4 Epoch and Sequence Number
│   ├── [P1 epic] Replay Window
│   │   ├── [P1] Python: 64-slot replay window [DONE]
│   │   ├── [P1] Rust: 64-slot replay window [DONE - replay.rs]
│   │   ├── [P1] Zephyr: 64-slot replay window [DONE - replay.c]
│   │   ├── [P1] 24-bit serial arithmetic (epoch << 16 | seqnum) [DONE all]
│   │   ├── [P1] Per-peer window tracking [DONE - Zephyr has table]
│   │   └── [P1] Vectors: replay window test cases
│   ├── [P1 epic] Epoch Persistence
│   │   ├── [P1] Python: epoch persistence across restarts
│   │   ├── [P1] Rust: epoch persistence across restarts
│   │   ├── [P1] Zephyr: epoch persistence [DONE - epoch_persist.c]
│   │   └── [P1] Vectors: epoch wrap scenarios
│   ├── [P2] Epoch recovery after flash failure
│   └── [P2] Cross-validate: replay window parity
│
├── [P1 epic] 4.5 Short Address Assignment
│   ├── [P1 epic] Coordinator-Managed Assignment
│   │   ├── [P1] Python: address assignment via DAO-ACK
│   │   ├── [P1] Rust: address assignment via DAO-ACK
│   │   ├── [P1] Zephyr: address assignment via DAO-ACK
│   │   ├── [P1] Address table maintenance (coordinator)
│   │   └── [P1] Vectors: coordinator assignment scenarios
│   ├── [P1 epic] DAD (Duplicate Address Detection)
│   │   ├── [P1] Python: DAD probe/conflict messages
│   │   ├── [P1] Rust: DAD probe/conflict messages
│   │   ├── [P1] Zephyr: DAD probe/conflict messages
│   │   ├── [P1] CRC16(EUI-64) candidate computation
│   │   ├── [P1] 3-probe with random jitter (0-500ms)
│   │   ├── [P1] Conflict resolution (retry with +1 mod 0xffef)
│   │   └── [P1] Vectors: DAD exchange scenarios
│   ├── [P2 epic] Collision Detection (Safety Net)
│   │   ├── [P2] Signature mismatch collision detection
│   │   ├── [P2] Multiple pubkey tracking per short addr
│   │   └── [P2] Collision logging/warning
│   └── [P2] Transition: self-assigned to coordinator-managed
│
├── [P1 epic] Schnorr-48 Signatures (draft-lichen-schnorr-00)
│   ├── [P1 epic] Keypair Derivation
│   │   ├── [P1] Python: seed -> Ed25519 keypair [DONE - schnorr48.py]
│   │   ├── [P1] Rust: seed -> Ed25519 keypair [DONE - schnorr.rs]
│   │   ├── [P1] Zephyr: seed -> Ed25519 keypair [DONE - schnorr48.c]
│   │   └── [P1] Vectors: keypair derivation [DONE - schnorr48.json]
│   ├── [P1 epic] Signing
│   │   ├── [P1] Python: deterministic sign [DONE]
│   │   ├── [P1] Rust: deterministic sign [DONE]
│   │   ├── [P1] Zephyr: deterministic sign [DONE]
│   │   ├── [P1] Frame signing (header+payload) [DONE all]
│   │   └── [P1] Vectors: signature generation [DONE - 5 valid vectors]
│   ├── [P1 epic] Verification
│   │   ├── [P1] Python: verify + defense-in-depth [DONE]
│   │   ├── [P1] Rust: verify + defense-in-depth [DONE]
│   │   ├── [P1] Zephyr: verify + defense-in-depth [DONE]
│   │   ├── [P1] Low-order point rejection [DONE all]
│   │   ├── [P1] Non-canonical scalar rejection [DONE all]
│   │   └── [P1] Vectors: invalid signature cases [DONE - 10 vectors]
│   └── [P1] Cross-validate: sign in A, verify in B/C
│
├── [P1 epic] Dispatch Byte Processing
│   ├── [P1] Python: dispatch classification [DONE - l2_payload.py]
│   ├── [P1] Rust: dispatch classification [DONE]
│   ├── [P1] Zephyr: dispatch classification [DONE]
│   ├── [P1] SCHC dispatch (0x14) routing
│   ├── [P1] Routing/control dispatch (0x15) routing
│   └── [P2] Unknown dispatch rejection
│
├── [P1 epic] Integration
│   ├── [P1] Python: LinkLayer RX/TX pipeline
│   ├── [P1] Rust: LinkLayer RX/TX pipeline [DONE - link_layer.rs]
│   ├── [P1] Zephyr: LinkLayer RX/TX pipeline [DONE]
│   ├── [P2] Memory budget verification (Zephyr)
│   └── [P2] Frame buffer pool management
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Malformed LLSec byte handling
    ├── [P2] Truncated signature handling
    ├── [P2] Replay window exhaustion
    ├── [P2] Epoch wrap under high traffic
    ├── [P2] Concurrent DAD probes from multiple nodes
    └── [P2] Fuzz vectors: malformed link frames
```

**Bead count:** ~55 P1 + ~27 P2 = ~82 total

**Notes:** Many core features (frame format, Schnorr-48, replay windows) are COMPLETE in all 3 languages. Major gaps: (1) SenderID field / Version 2 frames not implemented, (2) Short Address Assignment (DAD, coordinator) not implemented in any language, (3) Epoch persistence only in Zephyr, (4) ADR not implemented. Test vectors for frame.json (11) and schnorr48.json (15) exist and pass. Python link layer in python/src/lichen/link/. Rust link layer in rust/lichen-link/. Zephyr link layer in lichen/subsys/lichen/link/.

### Chapter 02a: Coordinated Capacity Profile (CCP)

**Scope:** OPTIONAL MAC overlay for time-scheduled and multi-channel TDMA operation with GNSS-PPS synchronization

```
```
[P2 epic] Chapter 02a: Coordinated Capacity Profile (CCP)
├── [P2 epic] Channel Plan Infrastructure
│   ├── [P2] Python: regional plan data structures
│   ├── [P2] Rust: regional plan data structures
│   ├── [P2] Zephyr: regional plan data structures
│   ├── [P2] Python: channel mask intersection logic
│   ├── [P2] Rust: channel mask intersection logic
│   ├── [P2] Zephyr: channel mask intersection logic
│   ├── [P2] Python: PHY profile constants (ID 0x01)
│   ├── [P2] Rust: PHY profile constants (ID 0x01)
│   ├── [P2] Zephyr: PHY profile constants (ID 0x01)
│   └── [P2] Vectors: channel plan validation cases
│
├── [P2 epic] Capability Advertisement (CCP-6)
│   ├── [P2] Python: 36-byte DIO option encode
│   ├── [P2] Python: 36-byte DIO option decode
│   ├── [P2] Rust: 36-byte DIO option encode
│   ├── [P2] Rust: 36-byte DIO option decode
│   ├── [P2] Zephyr: 36-byte DIO option encode
│   ├── [P2] Zephyr: 36-byte DIO option decode
│   ├── [P2] Python: capability flag handling
│   ├── [P2] Rust: capability flag handling
│   ├── [P2] Zephyr: capability flag handling
│   ├── [P2] Vectors: capability option test cases
│   └── [P2] Integration: RPL DIO option extension
│
├── [P1 epic] GNSS-PPS Slot Clock (CCP-7) [existing: project-LICHEN-i9r0.3]
│   ├── [P1] Python: GPS time to ASN derivation
│   ├── [P1] Rust: GPS time to ASN derivation
│   ├── [P1] Zephyr: GPS time to ASN derivation
│   ├── [P1] Python: PPS edge capture and association
│   ├── [P1] Rust: PPS edge capture and association
│   ├── [P1] Zephyr: PPS edge capture and association
│   ├── [P1] Python: drift bound tracking (B(h) = B(0) + rho*h)
│   ├── [P1] Rust: drift bound tracking
│   ├── [P1] Zephyr: drift bound tracking
│   ├── [P1] Python: holdover calculation and expiry
│   ├── [P1] Rust: holdover calculation and expiry
│   ├── [P1] Zephyr: holdover calculation and expiry
│   ├── [P1] Python: guard budget validation (G >= B_i + B_j + J_i + J_j + P + M)
│   ├── [P1] Rust: guard budget validation
│   ├── [P1] Zephyr: guard budget validation
│   ├── [P1] Vectors: ASN derivation test cases
│   ├── [P1] Vectors: drift/holdover boundary cases
│   └── [P2] Cross-validate: ASN parity across impls
│
├── [P2 epic] Superframes and Cells (CCP-8)
│   ├── [P2] Python: slot offset calculation (ASN mod slots_per_superframe)
│   ├── [P2] Rust: slot offset calculation
│   ├── [P2] Zephyr: slot offset calculation
│   ├── [P2] Python: cell record structure (19-byte format)
│   ├── [P2] Rust: cell record structure
│   ├── [P2] Zephyr: cell record structure
│   ├── [P2] Python: schedule validation (slot fit check)
│   ├── [P2] Rust: schedule validation
│   ├── [P2] Zephyr: schedule validation
│   ├── [P2] Python: execution window timing (t0+setup+G boundaries)
│   ├── [P2] Rust: execution window timing
│   ├── [P2] Zephyr: execution window timing
│   └── [P2] Vectors: superframe/cell calculation cases
│
├── [P2 epic] Control Message Codecs (CCP-10)
│   ├── [P2 epic] JOIN_REQUEST
│   │   ├── [P2] Python: JOIN_REQUEST encode
│   │   ├── [P2] Python: JOIN_REQUEST decode
│   │   ├── [P2] Rust: JOIN_REQUEST encode
│   │   ├── [P2] Rust: JOIN_REQUEST decode
│   │   ├── [P2] Zephyr: JOIN_REQUEST encode
│   │   ├── [P2] Zephyr: JOIN_REQUEST decode
│   │   └── [P2] Vectors: JOIN_REQUEST codec cases
│   ├── [P2 epic] SCHEDULE authority object
│   │   ├── [P2] Python: SCHEDULE encode (155+ byte authority object)
│   │   ├── [P2] Python: SCHEDULE decode
│   │   ├── [P2] Rust: SCHEDULE encode
│   │   ├── [P2] Rust: SCHEDULE decode
│   │   ├── [P2] Zephyr: SCHEDULE encode
│   │   ├── [P2] Zephyr: SCHEDULE decode
│   │   ├── [P2] Python: schedule digest computation (SHA-256 truncated)
│   │   ├── [P2] Rust: schedule digest computation
│   │   ├── [P2] Zephyr: schedule digest computation
│   │   ├── [P2] Python: page reassembly logic
│   │   ├── [P2] Rust: page reassembly logic
│   │   ├── [P2] Zephyr: page reassembly logic
│   │   └── [P2] Vectors: SCHEDULE codec and digest cases
│   ├── [P2 epic] REVOKE and DISABLE
│   │   ├── [P2] Python: REVOKE encode/decode
│   │   ├── [P2] Rust: REVOKE encode/decode
│   │   ├── [P2] Zephyr: REVOKE encode/decode
│   │   ├── [P2] Python: DISABLE encode/decode
│   │   ├── [P2] Rust: DISABLE encode/decode
│   │   ├── [P2] Zephyr: DISABLE encode/decode
│   │   └── [P2] Vectors: REVOKE/DISABLE codec cases
│   └── [P2 epic] CHANNEL_REQUEST/GRANT/REJECT
│       ├── [P2] Python: CHANNEL_REQUEST encode/decode
│       ├── [P2] Rust: CHANNEL_REQUEST encode/decode
│       ├── [P2] Zephyr: CHANNEL_REQUEST encode/decode
│       ├── [P2] Python: CHANNEL_GRANT encode/decode
│       ├── [P2] Rust: CHANNEL_GRANT encode/decode
│       ├── [P2] Zephyr: CHANNEL_GRANT encode/decode
│       ├── [P2] Python: CHANNEL_REJECT encode/decode
│       ├── [P2] Rust: CHANNEL_REJECT encode/decode
│       ├── [P2] Zephyr: CHANNEL_REJECT encode/decode
│       └── [P2] Vectors: rendezvous message codec cases
│
├── [P2 epic] CSMA Channel Rendezvous (CCP-11)
│   ├── [P2] Python: rendezvous initiator state machine
│   ├── [P2] Rust: rendezvous initiator state machine
│   ├── [P2] Zephyr: rendezvous initiator state machine
│   ├── [P2] Python: rendezvous grantor state machine
│   ├── [P2] Rust: rendezvous grantor state machine
│   ├── [P2] Zephyr: rendezvous grantor state machine
│   ├── [P2] Python: channel selection hash (SHA-256 based)
│   ├── [P2] Rust: channel selection hash
│   ├── [P2] Zephyr: channel selection hash
│   ├── [P2] Python: switch guard timing
│   ├── [P2] Rust: switch guard timing
│   ├── [P2] Zephyr: switch guard timing
│   ├── [P2] Vectors: channel selection hash cases
│   └── [P2] Vectors: rendezvous timing scenarios
│
├── [P1 epic] Desync Recovery State Machine (CCP-13a)
│   ├── [P1] Python: state machine (UNJOINED/JOINED/DRIFT/RECOVER)
│   ├── [P1] Rust: state machine
│   ├── [P1] Zephyr: state machine
│   ├── [P1] Python: drift watchdog timer (T_DRIFT_WARN)
│   ├── [P1] Rust: drift watchdog timer
│   ├── [P1] Zephyr: drift watchdog timer
│   ├── [P1] Python: recovery countdown (T_DRIFT_MAX, T_GIVE_UP)
│   ├── [P1] Rust: recovery countdown
│   ├── [P1] Zephyr: recovery countdown
│   ├── [P2] Python: extended RX window in DRIFT (50%)
│   ├── [P2] Rust: extended RX window in DRIFT
│   ├── [P2] Zephyr: extended RX window in DRIFT
│   ├── [P2] Python: multi-root conflict resolution
│   ├── [P2] Rust: multi-root conflict resolution
│   ├── [P2] Zephyr: multi-root conflict resolution
│   ├── [P2] Python: SFN wraparound handling
│   ├── [P2] Rust: SFN wraparound handling
│   ├── [P2] Zephyr: SFN wraparound handling
│   ├── [P1] Vectors: state transition test cases
│   └── [P2] Vectors: wraparound and multi-root cases
│
├── [P2 epic] Security and Replay Protection (CCP-14)
│   ├── [P2] Python: authority sequence tracking
│   ├── [P2] Rust: authority sequence tracking
│   ├── [P2] Zephyr: authority sequence tracking
│   ├── [P2] Python: root signature verification (Schnorr48)
│   ├── [P2] Rust: root signature verification
│   ├── [P2] Zephyr: root signature verification
│   ├── [P2] Python: replay detection by (root IID, seq, page)
│   ├── [P2] Rust: replay detection
│   ├── [P2] Zephyr: replay detection
│   ├── [P2] Python: join request rate limiting
│   ├── [P2] Rust: join request rate limiting
│   ├── [P2] Zephyr: join request rate limiting
│   └── [P2] Vectors: security boundary test cases
│
├── [P2 epic] Multi-Channel Operation (CCP-12) [existing: project-LICHEN-da2q.2]
│   ├── [P2] Python: scheduled cell execution
│   ├── [P2] Rust: scheduled cell execution
│   ├── [P2] Zephyr: scheduled cell execution
│   ├── [P2] Python: channel switch timing
│   ├── [P2] Rust: channel switch timing
│   ├── [P2] Zephyr: channel switch timing
│   ├── [P2] Python: half-duplex conflict prevention
│   ├── [P2] Rust: half-duplex conflict prevention
│   ├── [P2] Zephyr: half-duplex conflict prevention
│   └── [P2] Vectors: multi-channel timing cases
│
├── [P2 epic] Simulator Gates (CCP-16)
│   ├── [P2] Gate 1: byte-exact codec verification
│   ├── [P2] Gate 2: canonical LoRa airtime vectors
│   ├── [P2] Gate 3: slot fit verification
│   ├── [P2] Gate 4: GNSS PPS alignment verification
│   ├── [P2] Gate 5: GNSS loss/spoof discontinuity
│   ├── [P2] Gate 6: zero scheduler-created overlap (topologies)
│   ├── [P2] Gate 7: no simultaneous TX/RX on single-radio
│   ├── [P2] Gate 8: concurrent cells limited by chain count
│   ├── [P2] Gate 9: atomic schedule activation
│   ├── [P2] Gate 10: randomized join without starvation
│   ├── [P2] Gate 11: per-hop rendezvous recovery
│   ├── [P2] Gate 12: plan mismatch rejection
│   ├── [P2] Gate 13: legacy behavior unchanged
│   ├── [P2] Gate 14-15: gateway radio modeling
│   ├── [P2] Gate 16: forged/replayed control rejection
│   └── [P2] Gate 17: paired seed metrics (4x payload ratio)
│
└── [P2 epic] Integration and Cross-validation
    ├── [P2] Python: CCP to link layer integration
    ├── [P2] Rust: CCP to link layer integration
    ├── [P2] Zephyr: CCP to link layer integration
    ├── [P2] Python: CCP to RPL integration
    ├── [P2] Rust: CCP to RPL integration
    ├── [P2] Zephyr: CCP to RPL integration
    ├── [P2] Cross-validate: control message parity
    └── [P2] Cross-validate: end-to-end scheduled operation
```
```

**Bead count:** ~28 P1 + ~106 P2 = ~134 total

**Notes:** CCP is OPTIONAL per spec (CCP-1). Most tasks are P2 except GNSS-PPS slot clock (CCP-7) and desync recovery state machine (CCP-13a) which are P1 because they enable scheduled mode. Two existing beads: project-LICHEN-da2q.2 (multi-channel) and project-LICHEN-i9r0.3 (GNSS-PPS). CCP-16 defines 17 simulator gate conditions that MUST pass before production implementation. No existing CCP implementations found in Python, Rust, or Zephyr. No existing CCP test vectors in spec/test-vectors/.

### Chapter 04: Network Layer (IPv6)

**Scope:** IPv6 addressing (link-local, Yggdrasil native), IID derivation, multicast/broadcast with rate limiting, ICMPv6 diagnostics, and short address assignment

```
```
[P1 epic] Chapter 04: Network Layer (IPv6)
├── [P1 epic] IPv6 Addressing (spec 6.1)
│   ├── [P1 epic] Link-Local Address (fe80::/10)
│   │   ├── [P1] Python: link-local from IID (DONE - addr.py)
│   │   ├── [P1] Rust: link-local from EUI-64 (DONE - lichen-ipv6/lib.rs)
│   │   ├── [P1] Zephyr: link-local from IID (DONE - ipv6_addr.c)
│   │   └── [P1] Vectors: link-local derivation test cases
│   ├── [P1 epic] Native Yggdrasil Address (0200::/8)
│   │   ├── [P1] Python: AddrForKey(Ed25519 pubkey) derivation
│   │   ├── [P1] Rust: AddrForKey(Ed25519 pubkey) derivation
│   │   ├── [P1] Zephyr: AddrForKey(Ed25519 pubkey) derivation
│   │   ├── [P1] Address collision detection
│   │   ├── [P1] Reject native address != AddrForKey(known pubkey)
│   │   ├── [P1] Vectors: expand yggdrasil_address.json (10+ cases)
│   │   └── [P1] Cross-validate: same key -> same address in all impls
│   ├── [P2 epic] Isolated Mesh Root Election
│   │   ├── [P2] Python: root election (lowest native /128)
│   │   ├── [P2] Rust: root election (lowest native /128)
│   │   ├── [P2] Zephyr: root election (lowest native /128)
│   │   ├── [P2] Self-elected root forms DODAG without prefix
│   │   └── [P2] Vectors: root election scenarios
│   ├── [P2 epic] Root Failure Detection
│   │   ├── [P2] Python: DIO timeout (3x Imax) detection
│   │   ├── [P2] Rust: DIO timeout detection
│   │   ├── [P2] Zephyr: DIO timeout detection
│   │   ├── [P2] Re-election with random delay (0-5s)
│   │   └── [P2] Vectors: root failure/re-election scenarios
│   ├── [P2 epic] Root Demotion Protocol
│   │   ├── [P2] Python: DEMOTION_REQUEST ICMPv6 message
│   │   ├── [P2] Rust: DEMOTION_REQUEST message
│   │   ├── [P2] Zephyr: DEMOTION_REQUEST message
│   │   ├── [P2] Evidence hash + Schnorr signature
│   │   ├── [P2] Vote tracking (>50% threshold)
│   │   ├── [P2] Demoted node 1-hour exclusion
│   │   └── [P2] Vectors: demotion vote scenarios
│   └── [P2 epic] Multiple Border Routers
│       ├── [P2] Node joins multiple DODAGs (distinct Instance IDs)
│       ├── [P2] Native /128 retained across DODAG changes
│       └── [P2] Grounded root preference via objective function
│
├── [P1 epic] IID Derivation (spec 6.2)
│   ├── [P1 epic] From EUI-64
│   │   ├── [P1] Python: EUI-64 U/L bit flip (DONE - addr.py)
│   │   ├── [P1] Rust: EUI-64 U/L bit flip (DONE - lichen-ipv6)
│   │   ├── [P1] Zephyr: EUI-64 U/L bit flip (DONE - ipv6_addr.c)
│   │   └── [P1] Vectors: EUI-64 to IID test cases
│   ├── [P1 epic] From Public Key
│   │   ├── [P1] Python: SHA-256(pubkey)[0:8] with U/L cleared
│   │   ├── [P1] Rust: SHA-256(pubkey)[0:8] with U/L cleared
│   │   ├── [P1] Zephyr: pubkey_to_iid (DONE - ipv6_addr.c)
│   │   └── [P1] Vectors: pubkey to IID test cases
│   └── [P1 epic] From Short Address
│       ├── [P1] Python: 0000:00FF:FE00:XXXX format
│       ├── [P1] Rust: short address to IID
│       ├── [P1] Zephyr: short address to IID
│       └── [P1] Vectors: short address to IID cases
│
├── [P1 epic] Multicast and Broadcast (spec 6.3)
│   ├── [P1 epic] Multicast Scopes
│   │   ├── [P1] Python: scope detection (ff01-ff0e)
│   │   ├── [P1] Rust: scope detection
│   │   ├── [P1] Zephyr: scope detection
│   │   └── [P1] Standard group constants (ff02::1, ff02::1a, ff03::fc)
│   ├── [P2 epic] Hop-Limited Broadcast
│   │   ├── [P2] Python: hop-by-hop option (TBD1 type)
│   │   ├── [P2] Rust: hop-by-hop option parsing/building
│   │   ├── [P2] Zephyr: hop-by-hop option
│   │   ├── [P2] Original Hop Limit (1-7) preservation
│   │   ├── [P2] LICHEN Broadcast Sequence (32-bit counter)
│   │   ├── [P2] Realm identifier (RPL Instance + DODAGID)
│   │   └── [P2] Vectors: hop-limited broadcast scenarios
│   ├── [P2 epic] Broadcast Rate Limiting
│   │   ├── [P2] Python: per-origin rate tracking
│   │   ├── [P2] Rust: per-origin rate tracking
│   │   ├── [P2] Zephyr: per-origin rate tracking
│   │   ├── [P2] Hop-aware budgets (HL 1: 200/hr, HL 5-7: 10/hr)
│   │   ├── [P2] Yellow zone probabilistic relay (50% at 50% budget)
│   │   ├── [P2] Packet ID cache (SHA-256 truncated)
│   │   ├── [P2] 2-hour state expiration
│   │   └── [P2] Vectors: rate limiting scenarios
│   ├── [P2 epic] Broadcast Replay Protection
│   │   ├── [P2] Python: 32-bit serial replay window per origin
│   │   ├── [P2] Rust: serial replay window
│   │   ├── [P2] Zephyr: serial replay window
│   │   ├── [P2] Half-space rule for wrap-around
│   │   └── [P2] Vectors: replay window edge cases
│   └── [P2 epic] Border Router Multicast Filtering
│       ├── [P2] Drop multicast at mesh/Yggdrasil boundary
│       ├── [P2] Unicast-only Yggdrasil forwarding
│       └── [P2] Vectors: BR multicast filtering scenarios
│
├── [P1 epic] ICMPv6 (spec 6.4)
│   ├── [P1 epic] Echo Request/Reply
│   │   ├── [P1] Python: Echo Request/Reply (DONE - icmpv6.py)
│   │   ├── [P1] Rust: Echo Request/Reply (DONE - lichen-ipv6)
│   │   ├── [P1] Zephyr: Echo Request/Reply (DONE - icmpv6.c)
│   │   ├── [P1] Checksum verification
│   │   └── [P1] Vectors: ICMPv6 echo test cases
│   ├── [P1 epic] Error Messages
│   │   ├── [P1] Python: Destination Unreachable (DONE)
│   │   ├── [P1] Rust: Destination Unreachable
│   │   ├── [P1] Zephyr: Destination Unreachable (DONE)
│   │   ├── [P1] Python: Packet Too Big (DONE)
│   │   ├── [P1] Rust: Packet Too Big
│   │   ├── [P1] Zephyr: Packet Too Big (DONE)
│   │   ├── [P1] Python: Time Exceeded (DONE)
│   │   ├── [P1] Rust: Time Exceeded
│   │   ├── [P1] Zephyr: Time Exceeded (DONE)
│   │   └── [P1] Vectors: ICMPv6 error message test cases
│   └── [P2 epic] Neighbor Discovery (minimal)
│       ├── [P2] Python: Neighbor Solicitation/Advertisement
│       ├── [P2] Rust: NS/NA (DONE - lichen-ipv6)
│       ├── [P2] Zephyr: NS/NA
│       └── [P2] Vectors: NDP test cases
│
├── [P1 epic] Short Address Assignment (spec 12.3)
│   ├── [P1] Python: hash-based short address from EUI-64
│   ├── [P1] Rust: hash-based short address
│   ├── [P1] Zephyr: hash-based short address
│   ├── [P1] Duplicate Address Detection (DAD)
│   ├── [P2] DODAG root pool allocation (optional)
│   └── [P1] Vectors: short address derivation + collision
│
├── [P1 epic] Integration
│   ├── [P1] Python: IPv6 <-> SCHC layer integration
│   ├── [P1] Rust: IPv6 <-> SCHC layer integration
│   ├── [P1] Zephyr: IPv6 <-> SCHC layer integration
│   ├── [P1] Address derivation on key provisioning
│   └── [P2] Cross-validate: IPv6 parity across impls
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Malformed IPv6 header handling (existing P3 bugs)
    ├── [P2] ICMPv6 checksum edge cases (existing P3 bugs)
    ├── [P2] IPv6 payload_len validation (existing P3 bugs)
    ├── [P2] TOFU binding conflicts
    ├── [P2] Native address ambiguity handling
    └── [P2] Fuzz vectors: malformed IPv6/ICMPv6 packets
```
```

**Bead count:** ~47 P1 + ~48 P2 = ~95 total

**Notes:** Key findings:
1. Link-local and IID from EUI-64: DONE in all three implementations
2. ICMPv6 Echo/errors: DONE in all three (Zephyr ICMPv6 bead closed)
3. Yggdrasil AddrForKey: NOT implemented in any - vectors exist (1 case from upstream Go)
4. Root election/demotion: NOT implemented - spec section 6.1 defines protocol
5. Realm-local multicast with rate limiting: NOT implemented - major spec section 6.3
6. NDP (NS/NA): Only implemented in Rust lichen-ipv6
7. Short address assignment: NOT implemented
8. Existing P3 bugs for ICMPv6/IPv6 validation issues should be linked to edge cases epic
Dependencies: Yggdrasil addressing feeds into routing (Chapter 05) and security (Chapter 06)

### Chapter 05: Routing

**Scope:** Three-tier routing: RPL for border router traffic, Announce for peer-to-peer primary, LOADng for fallback discovery, plus unified gradient table

```
```
[P1 epic] Chapter 05: Routing
├── [P1 epic] 7. Routing Overview
│   ├── [P1 epic] 7.2 Routing Decision Logic
│   │   ├── [P1] Python: route_packet() dispatcher (exists in node.py)
│   │   ├── [P1] Rust: route_packet() dispatcher (exists in hybrid.rs)
│   │   ├── [P1] Zephyr: route_packet() dispatcher
│   │   ├── [P1] Address classification table implementation
│   │   ├── [P1] LOCAL_EVIDENCE_LIFETIME tracking (1200s)
│   │   └── [P1] Vectors: routing decision test cases
│   └── [P1 epic] 7.3 Conformance by Device Class
│       ├── [P2] Constrained device feature subset
│       ├── [P2] Router device feature subset
│       └── [P2] Border Router feature subset
│
├── [P1 epic] 8. RPL (Border Router Traffic)
│   ├── [P1 epic] 8.3 DODAG Configuration
│   │   ├── [P1] Python: MRHOF objective function (complete)
│   │   ├── [P1] Rust: MRHOF objective function (complete in dodag.rs)
│   │   ├── [P1] Zephyr: MRHOF objective function
│   │   ├── [P1] Trickle timer (Imin=4s, Imax=17min)
│   │   └── [P1] Vectors: DODAG config option encoding (exists)
│   ├── [P1 epic] 8.4 DIO Processing
│   │   ├── [P1] Python: DIO encode/decode (complete)
│   │   ├── [P1] Rust: DIO encode/decode (complete in message.rs)
│   │   ├── [P1] Zephyr: DIO encode/decode
│   │   ├── [P1] Python: DIO receive handler (complete)
│   │   ├── [P1] Rust: DIO receive handler (complete in dodag.rs)
│   │   ├── [P1] Zephyr: DIO receive handler
│   │   └── [P1] Vectors: DIO message test cases (exists)
│   ├── [P1 epic] 8.4 DIS Processing
│   │   ├── [P1] Python: DIS encode/decode (complete)
│   │   ├── [P1] Rust: DIS encode/decode (complete)
│   │   ├── [P1] Zephyr: DIS encode/decode
│   │   ├── [P1] DIS solicitation handling
│   │   └── [P1] Vectors: DIS message test cases (exists)
│   ├── [P1 epic] 8.4 DAO Processing
│   │   ├── [P1] Python: DAO encode/decode (complete)
│   │   ├── [P1] Rust: DAO encode/decode (complete in message.rs)
│   │   ├── [P1] Zephyr: DAO encode/decode
│   │   ├── [P1] Python: DAO generation for leaf nodes
│   │   ├── [P1] Rust: DAO generation for leaf nodes (complete)
│   │   ├── [P1] Zephyr: DAO generation for leaf nodes
│   │   ├── [P1] Python: DAO processing at root (complete)
│   │   ├── [P1] Rust: DAO processing at root (complete in routing.rs)
│   │   ├── [P1] Zephyr: DAO processing at root
│   │   └── [P1] Vectors: DAO message test cases (exists)
│   ├── [P1 epic] 8.4 DAO-ACK Processing
│   │   ├── [P1] Python: DAO-ACK encode/decode (complete)
│   │   ├── [P1] Rust: DAO-ACK encode/decode (complete)
│   │   ├── [P1] Zephyr: DAO-ACK encode/decode
│   │   └── [P1] Vectors: DAO-ACK test cases (exists)
│   ├── [P1 epic] 8.5 Source Routing Header (Downward)
│   │   ├── [P1] Python: SRH encode/decode
│   │   ├── [P1] Rust: SRH encode/decode (complete in routing.rs)
│   │   ├── [P1] Zephyr: SRH encode/decode
│   │   ├── [P1] SRH insertion at root
│   │   ├── [P1] SRH processing at intermediate nodes
│   │   └── [P1] Vectors: SRH encoding test cases
│   ├── [P1 epic] RPL Options (TLV)
│   │   ├── [P1] RPL Target option (type 5) - all impls
│   │   ├── [P1] Transit Information option (type 6) - all impls
│   │   ├── [P1] DODAG Configuration option (type 4) - all impls
│   │   └── [P1] Vectors: RPL option encoding (exists)
│   └── [P1 epic] Trickle Timer
│       ├── [P1] Python: Trickle state machine
│       ├── [P1] Rust: Trickle state machine (complete in trickle.rs)
│       ├── [P1] Zephyr: Trickle state machine
│       ├── [P1] Consistency detection
│       ├── [P1] Timer reset on inconsistency
│       └── [P1] Vectors: Trickle timer behavior tests
│
├── [P1 epic] 9. Announce Routing (Peer-to-Peer Primary)
│   ├── [P1 epic] 9.2 Announce Message Format
│   │   ├── [P1] Python: Announce encode/decode (complete in messages.py)
│   │   ├── [P1] Rust: Announce encode/decode (complete in announce.rs)
│   │   ├── [P1] Zephyr: Announce encode/decode
│   │   ├── [P1] Origin epoch + seq_num handling (24-bit serial)
│   │   ├── [P1] Key token derivation from pubkey
│   │   └── [P1] Vectors: Announce message encoding
│   ├── [P1 epic] 9.2 Announce Signature
│   │   ├── [P1] Python: Schnorr signature over signed_data (complete)
│   │   ├── [P1] Rust: Schnorr signature over signed_data (complete)
│   │   ├── [P1] Zephyr: Schnorr signature over signed_data
│   │   ├── [P1] Domain string: "LICHEN-ANN-v1"
│   │   └── [P1] Vectors: Announce signature verification
│   ├── [P1 epic] 9.3 Announce Processing
│   │   ├── [P1] Python: Announce processor (complete in processor.py)
│   │   ├── [P1] Rust: Announce processor (complete in announce.rs)
│   │   ├── [P1] Zephyr: Announce processor
│   │   ├── [P1] Signature verification
│   │   ├── [P1] Key token validation
│   │   ├── [P1] TOFU trust store pinning
│   │   ├── [P1] Duplicate/stale detection (RFC 1982)
│   │   ├── [P1] Gradient table update
│   │   └── [P1] Hop count limit enforcement (MAX=15)
│   ├── [P1 epic] 9.3 Announce Relay
│   │   ├── [P1] Python: Relay decision + hop increment (complete)
│   │   ├── [P1] Rust: Relay decision + hop increment (complete)
│   │   ├── [P1] Zephyr: Relay decision + hop increment
│   │   └── [P1] Vectors: Relay behavior tests
│   ├── [P1 epic] 9.4 Announce Scheduler
│   │   ├── [P1] Python: Periodic announce (complete in scheduler.py)
│   │   ├── [P1] Rust: Periodic announce (complete in scheduler.rs)
│   │   ├── [P1] Zephyr: Periodic announce
│   │   ├── [P1] ANNOUNCE_INTERVAL (300s)
│   │   └── [P1] ANNOUNCE_JITTER (0-30s random)
│   ├── [P1 epic] 9.6 TOFU Trust Model
│   │   ├── [P1] Python: First-contact binding (complete)
│   │   ├── [P1] Rust: First-contact binding (complete)
│   │   ├── [P1] Zephyr: First-contact binding
│   │   ├── [P1] Identity collision detection
│   │   ├── [P1] Key change rejection
│   │   └── [P2] Vectors: TOFU edge cases
│   ├── [P1 epic] 9.7 Geographic Coordinates in App Data
│   │   ├── [P1] Python: Type 0x01 coords encode/decode (complete in coords.py)
│   │   ├── [P1] Rust: Type 0x01 coords encode/decode (complete)
│   │   ├── [P1] Zephyr: Type 0x01 coords encode/decode
│   │   ├── [P1] LatE7/LonE7 signed 32-bit encoding
│   │   └── [P1] Vectors: Coordinate encoding (exists in announce_coords.json)
│   ├── [P2 epic] 9.7 GPSR Geographic Fallback
│   │   ├── [P2] Python: Greedy forwarding
│   │   ├── [P2] Rust: Greedy forwarding (complete in routing.rs)
│   │   ├── [P2] Zephyr: Greedy forwarding
│   │   ├── [P2] Haversine distance calculation
│   │   ├── [P2] Progress requirement enforcement
│   │   ├── [P2] Coordinate validation (NaN, inf, null island)
│   │   └── [P2] Vectors: GPSR forwarding scenarios
│   ├── [P2 epic] 9.8 Store-and-Forward (DTN)
│   │   ├── [P2] Python: DTN buffer (simulator exists)
│   │   ├── [P2] Rust: DTN buffer (complete in routing.rs)
│   │   ├── [P2] Zephyr: DTN buffer
│   │   ├── [P2] Absolute TTL (Unix timestamp)
│   │   ├── [P2] Max buffer (64KB)
│   │   ├── [P2] Oldest-first eviction
│   │   ├── [P2] Type 0x03 expiry app data
│   │   ├── [P2] Type 0x04 pending destinations app data
│   │   └── [P2] Vectors: DTN buffering scenarios
│   └── [P2 epic] 9.9 Opportunistic Forwarding
│       ├── [P2] Forwarder list header (IID ranking)
│       ├── [P2] Timed suppression (SLOT_TIME=100ms)
│       ├── [P2] MAX_CANDIDATES=4
│       └── [P2] Vectors: Opportunistic forwarding scenarios
│
├── [P1 epic] 10. LOADng (Peer-to-Peer Fallback)
│   ├── [P1 epic] 10.2 LOADng Triggering
│   │   ├── [P1] Python: recent_local_evidence() check (complete)
│   │   ├── [P1] Rust: recent_local_evidence() check
│   │   ├── [P1] Zephyr: recent_local_evidence() check
│   │   └── [P1] Reject discovery for unknown 0200::/8
│   ├── [P1 epic] 10.3 RREQ Processing
│   │   ├── [P1] Python: RREQ encode/decode (complete in messages.py)
│   │   ├── [P1] Rust: RREQ encode/decode (complete in loadng.rs)
│   │   ├── [P1] Zephyr: RREQ encode/decode
│   │   ├── [P1] Python: RREQ receive handler (complete in discovery.py)
│   │   ├── [P1] Rust: RREQ receive handler
│   │   ├── [P1] Zephyr: RREQ receive handler
│   │   ├── [P1] Duplicate RREQ suppression
│   │   ├── [P1] Reverse gradient installation
│   │   ├── [P1] Intermediate reply (gradient exists)
│   │   ├── [P1] Expanding ring (INITIAL_HOP_LIMIT=4)
│   │   └── [P1] Vectors: RREQ message encoding
│   ├── [P1 epic] 10.4 RREP Processing
│   │   ├── [P1] Python: RREP encode/decode (complete in messages.py)
│   │   ├── [P1] Rust: RREP encode/decode (complete in loadng.rs)
│   │   ├── [P1] Zephyr: RREP encode/decode
│   │   ├── [P1] Python: RREP receive handler (complete in discovery.py)
│   │   ├── [P1] Rust: RREP receive handler (complete in hybrid.rs)
│   │   ├── [P1] Zephyr: RREP receive handler
│   │   ├── [P1] Forward gradient installation
│   │   ├── [P1] Reverse path following
│   │   └── [P1] Vectors: RREP message encoding
│   ├── [P1 epic] 10.6 RERR Processing
│   │   ├── [P1] Python: RERR encode/decode (complete in messages.py)
│   │   ├── [P1] Rust: RERR encode/decode (complete)
│   │   ├── [P1] Zephyr: RERR encode/decode
│   │   ├── [P1] Gradient invalidation on link failure
│   │   └── [P1] Vectors: RERR message encoding
│   ├── [P1 epic] 10.7 LOADng Parameters
│   │   ├── [P1] RREQ_WAIT_TIME (5s)
│   │   ├── [P1] RREQ_RETRIES (3)
│   │   ├── [P1] MAX_HOP_LIMIT (15)
│   │   └── [P1] Suppress window (10s)
│   └── [P1 epic] LOADng Discovery State Machine
│       ├── [P1] Python: Discovery orchestration (complete in discovery.py)
│       ├── [P1] Rust: Discovery orchestration (complete in loadng.rs/hybrid.rs)
│       ├── [P1] Zephyr: Discovery orchestration
│       ├── [P1] Packet queuing during discovery
│       └── [P1] Vectors: Discovery state transitions
│
├── [P1 epic] 11. Gradient Table
│   ├── [P1 epic] 11.1 Unified Structure
│   │   ├── [P1] Python: GradientTable (complete in gradient.py)
│   │   ├── [P1] Rust: GradientTable (complete in gradient.rs)
│   │   ├── [P1] Zephyr: GradientTable
│   │   ├── [P1] GradientEntry fields per spec
│   │   ├── [P1] Coords field for GPSR
│   │   └── [P1] Vectors: Gradient entry encoding
│   ├── [P1 epic] 11.1 Gradient Sources
│   │   ├── [P1] Source: announce
│   │   ├── [P1] Source: rrep
│   │   ├── [P1] Source: rpl
│   │   ├── [P1] Source: data (passive learning)
│   │   └── [P1] Source priority ranking
│   ├── [P1 epic] 11.2 Passive Learning
│   │   ├── [P2] Python: Learn from forwarded data
│   │   ├── [P2] Rust: Learn from forwarded data
│   │   ├── [P2] Zephyr: Learn from forwarded data
│   │   ├── [P2] DATA_GRADIENT_TIMEOUT (60s)
│   │   ├── [P2] Require OSCORE or origin signature
│   │   └── [P2] Reject ambiguous destinations
│   ├── [P1 epic] 11.3 Entry Priority + Replacement
│   │   ├── [P1] Python: Priority-based replacement (complete)
│   │   ├── [P1] Rust: Priority-based replacement (complete)
│   │   ├── [P1] Zephyr: Priority-based replacement
│   │   ├── [P1] RFC 1982 sequence comparison
│   │   └── [P1] Hop count tiebreaker
│   ├── [P1 epic] Table Operations
│   │   ├── [P1] Lookup (with expiry check)
│   │   ├── [P1] Update (with priority check)
│   │   ├── [P1] Remove by destination
│   │   ├── [P1] Remove via next-hop (link failure)
│   │   └── [P1] Expire old entries
│   ├── [P1 epic] LRU Eviction
│   │   ├── [P1] Python: LRU bounded table (complete)
│   │   ├── [P1] Rust: LRU bounded table (complete)
│   │   ├── [P1] Zephyr: LRU bounded table
│   │   └── [P1] MAX_ENTRIES (64)
│   └── [P2 epic] 11.4 Backpressure (Optional)
│       ├── [P2] Neighbor queue depth tracking
│       ├── [P2] Type 0x02 congestion app data
│       ├── [P2] Python: Congestion parsing (complete)
│       ├── [P2] Rust: Congestion parsing (complete)
│       ├── [P2] Zephyr: Congestion parsing
│       └── [P2] Vectors: Backpressure scenarios
│
├── [P1 epic] Integration Tasks
│   ├── [P1] Python: Routing ↔ link layer integration
│   ├── [P1] Rust: Routing ↔ link layer integration (exists in hybrid.rs)
│   ├── [P1] Zephyr: Routing ↔ link layer integration
│   ├── [P1] Python: RPL + Announce + LOADng dispatch
│   ├── [P1] Rust: RPL + Announce + LOADng dispatch (exists)
│   ├── [P1] Zephyr: RPL + Announce + LOADng dispatch
│   └── [P2] Cross-validate: routing parity across impls
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Identity collision handling
    ├── [P2] Ambiguous destination rejection
    ├── [P2] Announce replay state persistence
    ├── [P2] RREQ flood prevention
    ├── [P2] Gradient table memory exhaustion
    ├── [P2] Sequence number wraparound (RFC 1982)
    ├── [P2] Timer wraparound safety (u32 ms)
    ├── [P2] Malformed message handling
    └── [P2] Fuzz vectors: malformed routing messages
```
```

**Bead count:** ~108 P1 + ~36 P2 = ~144 total

**Notes:** Python and Rust implementations are largely complete for core functionality. Zephyr has only link layer - needs full routing stack. LOADng vectors missing. GPSR/DTN are P2 optional features. RPL message vectors exist. Existing beads: project-LICHEN-p2y5 (border router RPL), project-LICHEN-2auf.44.9 (prefix DAO targets), project-LICHEN-r6r8 (Rust DAO). DTN implementation exists in Rust but tests show Zephyr-only in parity audit.

### Chapter 06: Security

**Scope:** Link signatures (Schnorr48), key management (TOFU/BR-provisioned), OSCORE end-to-end security, EDHOC key exchange, replay protection

```
```
[P1 epic] Chapter 06: Security
├── [P1 epic] 8.3 Link-Layer Signatures (Schnorr48)
│   ├── [P1 epic] Schnorr48 signing
│   │   ├── [done] Python: Schnorr48 sign (crypto/schnorr48.py)
│   │   ├── [done] Rust: Schnorr48 sign (lichen-link/src/schnorr.rs)
│   │   ├── [done] Zephyr: Schnorr48 sign (link/schnorr48.c)
│   │   └── [done] Vectors: Schnorr48 signing test cases (schnorr48.json)
│   ├── [P1 epic] Schnorr48 verification
│   │   ├── [done] Python: Schnorr48 verify
│   │   ├── [done] Rust: Schnorr48 verify with defense-in-depth checks
│   │   ├── [done] Zephyr: Schnorr48 verify
│   │   └── [done] Vectors: Invalid signature rejection cases
│   ├── [P1] Cross-validate: Schnorr48 signature parity
│   ├── [P2] Vectors: Low-order point rejection cases
│   └── [P2] Vectors: Non-canonical scalar rejection cases
│
├── [P1 epic] 8.4-8.5 Signature Semantics
│   ├── [P1 epic] Signed field handling
│   │   ├── [P1] Python: Verify signed fields list per spec
│   │   ├── [P1] Rust: Verify signed fields list per spec
│   │   ├── [P1] Zephyr: Verify signed fields list per spec
│   │   └── [P1] Vectors: Signed field coverage test cases
│   ├── [P1 epic] Relay re-signing
│   │   ├── [P1] Python: Relay verifies, mutates, re-signs
│   │   ├── [P1] Rust: Relay verifies, mutates, re-signs
│   │   ├── [P1] Zephyr: Relay verifies, mutates, re-signs
│   │   └── [P1] Vectors: Multi-hop relay signature chain
│   ├── [P2 epic] Signature caching
│   │   ├── [P2] Python: Signature cache with 30s expiry
│   │   ├── [P2] Rust: Signature cache with 30s expiry
│   │   ├── [P2] Zephyr: Signature cache with 30s expiry
│   │   └── [P2] Vectors: Cache hit/miss/expiry scenarios
│   └── [P2] Cross-validate: Relay re-signing interop
│
├── [P1 epic] 8.6 Key Management
│   ├── [P1 epic] Self-provisioned bootstrap
│   │   ├── [done] Python: Ed25519 keypair generation (crypto/identity.py)
│   │   ├── [done] Rust: Ed25519 keypair generation (lichen-link/src/identity.rs)
│   │   ├── [done] Zephyr: Ed25519 keypair generation (crypto/monocypher*)
│   │   ├── [P1] Python: IID/Ygg address derivation from pubkey
│   │   ├── [P1] Rust: IID/Ygg address derivation from pubkey
│   │   ├── [P1] Zephyr: IID/Ygg address derivation from pubkey
│   │   └── [done] Vectors: Yggdrasil address derivation (yggdrasil_address.json)
│   ├── [P1 epic] TOFU (Trust On First Use)
│   │   ├── [P1] Python: TOFU key pinning on first contact
│   │   ├── [P1] Rust: TOFU key pinning on first contact
│   │   ├── [P1] Zephyr: TOFU key pinning on first contact
│   │   ├── [P1] Python: Key mismatch rejection + alert
│   │   ├── [P1] Rust: Key mismatch rejection + alert
│   │   ├── [P1] Zephyr: Key mismatch rejection + alert
│   │   └── [P1] Vectors: TOFU pin/reject scenarios
│   ├── [P2 epic] BR-provisioned (optional)
│   │   ├── [P2] Python: Commissioning mode support
│   │   ├── [P2] Rust: Commissioning mode support
│   │   ├── [P2] Zephyr: Commissioning mode support
│   │   ├── [P2] Trust anchor list CoAP resource
│   │   ├── [P2] Trust anchor OSCORE protection
│   │   └── [P2] Vectors: Provisioning flow test cases
│   ├── [P2 epic] Revocation handling
│   │   ├── [P2] Python: Remove revoked key from store
│   │   ├── [P2] Rust: Remove revoked key from store
│   │   ├── [P2] Zephyr: Remove revoked key from store
│   │   └── [P2] Vectors: Revocation propagation
│   ├── [P2] DANE (RFC 6698): TLSA record verification (optional)
│   ├── [P2] PKIX/ACME: Certificate provisioning (optional)
│   └── [P2] Cross-validate: Key derivation parity
│
├── [P1 epic] 8.7 OSCORE (RFC 8613)
│   ├── [P1 epic] Context creation
│   │   ├── [done] Python: OSCORE context from master secret
│   │   ├── [done] Rust: OSCORE context from master secret
│   │   ├── [done] Zephyr: OSCORE context from master secret
│   │   └── [done] Vectors: RFC 8613 key derivation test vectors
│   ├── [P1 epic] Request protection
│   │   ├── [done] Python: protect_request (encrypt)
│   │   ├── [done] Rust: protect_request (encrypt)
│   │   ├── [done] Zephyr: protect_request (encrypt)
│   │   ├── [done] Python: unprotect_request (decrypt)
│   │   ├── [done] Rust: unprotect_request (decrypt)
│   │   ├── [done] Zephyr: unprotect_request (decrypt)
│   │   └── [done] Vectors: RFC 8613 request protection vectors
│   ├── [P1 epic] Response protection
│   │   ├── [done] Python: protect_response with request AAD
│   │   ├── [done] Rust: protect_response with request AAD
│   │   ├── [done] Zephyr: protect_response with request AAD
│   │   ├── [done] Python: unprotect_response
│   │   ├── [done] Rust: unprotect_response
│   │   ├── [done] Zephyr: unprotect_response
│   │   └── [done] Vectors: RFC 8613 response protection vectors
│   ├── [P1 epic] Replay protection
│   │   ├── [done] Python: OSCORE replay window
│   │   ├── [done] Rust: OSCORE replay window (32-bit)
│   │   ├── [done] Zephyr: OSCORE replay window
│   │   └── [P1] Vectors: Replay detection edge cases
│   ├── [P1 epic] Sequence number handling
│   │   ├── [done] Rust: SeqExhausted error at u32::MAX
│   │   ├── [P1] Python: Sequence exhaustion handling
│   │   ├── [P1] Zephyr: Sequence exhaustion handling
│   │   └── [P1] Vectors: Sequence exhaustion scenarios
│   ├── [P1] Cross-validate: OSCORE roundtrip all impls
│   └── [P2] Vectors: ID Context handling
│
├── [P1 epic] 8.8 EDHOC (RFC 9528)
│   ├── [P1 epic] Key derivation
│   │   ├── [done] Python: X25519 from Ed25519 seed
│   │   ├── [done] Rust: X25519 from Ed25519 seed
│   │   ├── [P1] Zephyr: X25519 from Ed25519 seed
│   │   └── [P1] Vectors: Key derivation consistency
│   ├── [P1 epic] Message 1 (Initiator)
│   │   ├── [done] Python: create_message_1
│   │   ├── [done] Rust: create_message_1
│   │   ├── [P1] Zephyr: create_message_1
│   │   └── [P1] Vectors: Message 1 format test cases
│   ├── [P1 epic] Message 2 (Responder)
│   │   ├── [done] Python: process_message_1 + create_message_2
│   │   ├── [done] Rust: process_message_1 + create_message_2
│   │   ├── [P1] Zephyr: process_message_1 + create_message_2
│   │   └── [P1] Vectors: Message 2 format test cases
│   ├── [P1 epic] Message 3 (Initiator)
│   │   ├── [done] Python: process_message_2 + create_message_3
│   │   ├── [done] Rust: process_message_2 + signature verification
│   │   ├── [P1] Zephyr: process_message_2 + create_message_3
│   │   └── [P1] Vectors: Message 3 format test cases
│   ├── [P1 epic] Message 3 processing (Responder)
│   │   ├── [done] Python: process_message_3 + signature verification
│   │   ├── [done] Rust: process_message_3 + signature verification
│   │   ├── [P1] Zephyr: process_message_3 + signature verification
│   │   └── [P1] Vectors: Signature verification cases
│   ├── [P1 epic] OSCORE context export
│   │   ├── [done] Python: export_oscore after handshake
│   │   ├── [done] Rust: export_oscore after handshake
│   │   ├── [P1] Zephyr: export_oscore after handshake
│   │   └── [P1] Vectors: Exported context validation
│   ├── [P1 epic] Suite negotiation
│   │   ├── [done] Rust: SUITES_I array parsing (RFC 9528 Section 3.3.2)
│   │   ├── [P1] Python: SUITES_I array parsing
│   │   ├── [P1] Zephyr: SUITES_I array parsing
│   │   └── [P1] Vectors: Suite negotiation scenarios
│   ├── [P1] Cross-validate: EDHOC handshake interop
│   ├── [P1] Cross-validate: Derived OSCORE context parity
│   ├── [P2] Python: Session resumption
│   ├── [P2] Rust: Session resumption
│   ├── [P2] Zephyr: Session resumption
│   └── [P2] Vectors: Session resumption scenarios
│
├── [P1 epic] 8.9 RPL Security
│   ├── [P1 epic] Link-layer signature baseline
│   │   ├── [P1] Python: DIO/DAO/DIS carry link signatures
│   │   ├── [P1] Rust: DIO/DAO/DIS carry link signatures
│   │   ├── [P1] Zephyr: DIO/DAO/DIS carry link signatures
│   │   └── [P1] Vectors: RPL message signature verification
│   ├── [P1 epic] Root Authorization Option
│   │   ├── [P1] Python: Root signature in DIO
│   │   ├── [P1] Rust: Root signature in DIO
│   │   ├── [P1] Zephyr: Root signature in DIO
│   │   ├── [P1] Verify DODAGID == AddrForKey(root_pubkey)
│   │   └── [P1] Vectors: Root authorization validation
│   ├── [P2 epic] Preinstalled mode (optional defense-in-depth)
│   │   ├── [P2] Python: PSK-protected control plane
│   │   ├── [P2] Rust: PSK-protected control plane
│   │   ├── [P2] Zephyr: CONFIG_LICHEN_RPL_SECURE_MODE
│   │   └── [P2] Vectors: Secure mode message handling
│   └── [P2] Cross-validate: RPL security interop
│
├── [P1 epic] 15.3 Replay Protection
│   ├── [P1 epic] Link-layer replay window
│   │   ├── [done] Python: Per-sender (epoch, seqnum) tracking
│   │   ├── [done] Rust: Per-sender replay window
│   │   ├── [done] Zephyr: Per-sender replay window (link/replay.c)
│   │   ├── [P1] Python: 64-entry sliding window
│   │   ├── [P1] Rust: 64-entry sliding window
│   │   ├── [P1] Zephyr: 64-entry sliding window
│   │   └── [P1] Vectors: Out-of-order tolerance scenarios
│   ├── [P1 epic] Epoch persistence
│   │   ├── [done] Zephyr: epoch_persist.c
│   │   ├── [P1] Python: Epoch increment on wrap/reboot
│   │   ├── [P1] Rust: Epoch increment on wrap/reboot
│   │   └── [P1] Vectors: Epoch rollover scenarios
│   └── [P1] Cross-validate: Replay window semantics parity
│
├── [P1 epic] 15.2 Key Storage
│   ├── [P1] Python: Secure key persistence
│   ├── [P1] Rust: Zeroize on drop (verify)
│   ├── [P1] Zephyr: Secure element / flash readout protection
│   └── [P2] Vectors: Key zeroization verification
│
├── [P1 epic] Integration
│   ├── [P1] Python: Security ↔ link layer integration
│   ├── [P1] Rust: Security ↔ link layer integration
│   ├── [P1] Zephyr: Security ↔ link layer integration
│   ├── [P1] OSCORE ↔ CoAP integration (all impls)
│   ├── [P1] EDHOC ↔ OSCORE context handoff
│   └── [P2] OSCORE ↔ SCHC compression (Rule 5)
│
└── [P2 epic] Edge cases / hardening
    ├── [P2] Malformed OSCORE option handling
    ├── [P2] Truncated EDHOC message handling
    ├── [P2] Invalid signature recovery behavior
    ├── [P2] Key derivation failure recovery
    ├── [P2] Context exhaustion handling
    ├── [P2] Concurrent EDHOC sessions
    └── [P2] Fuzz vectors: Malformed security messages
```
```

**Bead count:** ~71 P1 + ~36 P2 = ~107 total

**Notes:** Many core primitives (Schnorr48, OSCORE, EDHOC) are already implemented across all three languages. Marked as [done] where verified. Key gaps: 1) Zephyr EDHOC needs verification of full message flow, 2) TOFU implementation needs explicit verification, 3) Cross-language interop testing needed for EDHOC handshakes, 4) SCHC Rule 5 (OSCORE compression) integration. Existing beads referenced in plan (project-LICHEN-2okc for Rust OSCORE AAD, project-LICHEN-r9pz for OSCORE+SCHC vectors) should be linked as children. The plan estimated ~40 beads; expanded to 107 for full implementation granularity including done items.

### Chapter 07: Transport and Application

**Scope:** UDP port dispatch, Compact CoT, SenML, Cayenne, APRS-IS, NMEA, CoAP client/server/observe, MQTT-SN, duty cycle, Resource Directory

```
```
[P1 epic] Chapter 07: Transport and Application
├── [P1 epic] UDP Port Dispatch (Section 9.1)
│   ├── [P1] Python: port dispatch for 568x and 10883 (complete - node.py)
│   ├── [P1] Rust: port dispatch for 568x and 10883 (complete - port_dispatch.rs)
│   ├── [P1] Zephyr: port dispatch for 568x and 10883
│   ├── [P1] SCHC rule for MQTT-SN port 10883
│   └── [P1] Vectors: port dispatch test cases
│
├── [P1 epic] Compact CoT (Port 5681, Section 10.1.1)
│   ├── [P1 epic] PLI Encoding
│   │   ├── [P1] Python: PLI encode/decode (complete - compact_cot.py)
│   │   ├── [P1] Rust: PLI encode/decode
│   │   ├── [P1] Zephyr: PLI encode/decode
│   │   ├── [P1] Field validation (lat/lon/alt/course/speed bounds)
│   │   └── [P1] Vectors: PLI test cases (complete - compact_cot.json)
│   ├── [P1 epic] Chat Encoding
│   │   ├── [P1] Python: Chat encode/decode (complete - compact_cot.py)
│   │   ├── [P1] Rust: Chat encode/decode
│   │   ├── [P1] Zephyr: Chat encode/decode
│   │   ├── [P1] Destination types: broadcast/team/direct
│   │   └── [P1] Vectors: Chat test cases (complete - compact_cot.json)
│   ├── [P1 epic] XML Gateway Conversion
│   │   ├── [P1] Python: XML to compact (complete - compact_cot.py)
│   │   ├── [P1] Python: compact to XML (complete - compact_cot.py)
│   │   ├── [P2] Rust: XML to compact (gateway only)
│   │   └── [P1] Vectors: XML round-trip test cases
│   ├── [P2] Marker encoding (0x10) - TBD per spec
│   ├── [P2] Alert encoding (0x20) - TBD per spec
│   └── [P1] Cross-validate: Compact CoT parity
│
├── [P1 epic] SenML (Port 5682, Section 10.1.2)
│   ├── [P1 epic] CBOR Codec
│   │   ├── [P1] Python: SenML pack/unpack (complete - senml/codec.py)
│   │   ├── [P1] Rust: SenML pack/unpack (complete - lichen-senml)
│   │   ├── [P1] Zephyr: SenML pack/unpack (complete - senml/senml.c)
│   │   ├── [P1] RFC 8428 numeric key mapping
│   │   └── [P1] Vectors: SenML CBOR test cases
│   ├── [P1 epic] Field Validation (RFC 8428)
│   │   ├── [P2] Reject conflicting value fields (project-LICHEN-tu65)
│   │   ├── [P2] Enforce base version (project-LICHEN-k198)
│   │   └── [P2] Validate numeric encodings (project-LICHEN-e6n0)
│   ├── [P1] IPSO Smart Object ID support (3303, 3304, etc.)
│   └── [P1] Cross-validate: SenML parity
│
├── [P2 epic] Cayenne LPP (Port 5685, Section 10.1.3)
│   ├── [P2] Python: Cayenne encode/decode
│   ├── [P2] Rust: Cayenne encode/decode
│   ├── [P2] Zephyr: Cayenne encode/decode
│   ├── [P2] Type codes: 103/104/115/136
│   └── [P2] Vectors: Cayenne LPP test cases
│
├── [P2 epic] APRS-IS (Port 5686, Section 10.1.4)
│   ├── [P2] Python: APRS-IS parse/format
│   ├── [P2] Rust: APRS-IS parse/format (partial - lichen-kiss/aprs.rs)
│   ├── [P2] Zephyr: APRS-IS parse/format
│   ├── [P2] Gateway: APRS-IS to AX.25 RF translation
│   └── [P2] Vectors: APRS-IS test cases
│
├── [P2 epic] NMEA (Port 5687, Section 10.1.5)
│   ├── [P2] Python: NMEA sentence passthrough
│   ├── [P2] Rust: NMEA sentence passthrough
│   ├── [P2] Zephyr: NMEA sentence passthrough
│   ├── [P2] Gateway: NMEA to SenML/CoT conversion
│   └── [P2] Vectors: NMEA test cases
│
├── [P1 epic] CoAP (Port 5683, Section 10.2)
│   ├── [P1 epic] Message Parsing (RFC 7252)
│   │   ├── [P1] Python: CoAP message parse/serialize (complete - aiocoap)
│   │   ├── [P1] Rust: CoAP message parse/serialize (complete - lichen-coap)
│   │   ├── [P1] Zephyr: CoAP message parse/serialize (complete - coap_*)
│   │   └── [P1] Vectors: CoAP message test cases
│   ├── [P1 epic] CoAP Client
│   │   ├── [P1] Python: CoAP client (complete - ip_coap.py, packet_coap.py)
│   │   ├── [P1] Rust: CoAP client (complete - lichen-coap/client.rs)
│   │   ├── [P1] Zephyr: CoAP client (complete - coap_client.c)
│   │   └── [P1] Request/response round-trip validation
│   ├── [P1 epic] CoAP Server
│   │   ├── [P1] Python: CoAP server (complete - udp_server.py)
│   │   ├── [P1] Rust: CoAP server
│   │   ├── [P1] Zephyr: CoAP server (complete - coap_server.c, CLOSED)
│   │   └── [P1] Resource handler registration
│   ├── [P1 epic] LoRa Parameters (Section 10.2.2)
│   │   ├── [P1] Python: ACK_TIMEOUT=15s, MAX_RETRANSMIT=2
│   │   ├── [P1] Rust: ACK_TIMEOUT=15s, MAX_RETRANSMIT=2
│   │   ├── [P1] Zephyr: ACK_TIMEOUT=15s, MAX_RETRANSMIT=2
│   │   ├── [P1] Prefer NON over CON guidance
│   │   └── [P1] Vectors: timeout/retry scenarios
│   ├── [P1 epic] Duty Cycle Awareness (Section 10.2.3)
│   │   ├── [P1] Python: duty cycle tracking
│   │   ├── [P1] Rust: duty cycle tracking
│   │   ├── [P1] Zephyr: duty cycle tracking
│   │   ├── [P1] Congestion levels: Normal/Elevated/Critical/Exhausted
│   │   ├── [P1] 5.03 Service Unavailable response generation
│   │   ├── [P1] Priority queue: P0-P4 traffic types
│   │   ├── [P1] Application-to-priority mapping
│   │   └── [P1] Vectors: congestion/load-shedding scenarios
│   ├── [P1 epic] Content-Format Dispatch (Section 10.2.1)
│   │   ├── [P1] Content-Format 60 (CBOR)
│   │   ├── [P1] Content-Format 110 (SenML+CBOR)
│   │   ├── [P1] Content-Format 112 (SenML+JSON)
│   │   └── [P1] Content-Format 11542 (OCF)
│   └── [P2] Cross-validate: CoAP parity
│
├── [P1 epic] CoAP Observe (Section 10.3)
│   ├── [P1] Python: Observe subscribe/notify (complete - aiocoap)
│   ├── [P1] Rust: Observe subscribe/notify
│   ├── [P1] Zephyr: Observe subscribe/notify
│   ├── [P1] Observe sequence number handling (project-LICHEN-xh1t)
│   ├── [P1] Per-registration OSCORE Observe (project-LICHEN-05zu)
│   └── [P1] Vectors: Observe notification sequences
│
├── [P2 epic] MQTT-SN (Port 10883, Section 10.4)
│   ├── [P2 epic] Message Handling
│   │   ├── [P2] Python: MQTT-SN message parse/serialize
│   │   ├── [P2] Rust: MQTT-SN message parse/serialize
│   │   ├── [P2] Zephyr: MQTT-SN message parse/serialize
│   │   └── [P2] Message types: CONNECT/PUBLISH/SUBSCRIBE/etc.
│   ├── [P2 epic] Gateway Architecture
│   │   ├── [P2] MQTT-SN to MQTT 3.1.1/5.0 translation
│   │   ├── [P2] Topic ID registration
│   │   └── [P2] QoS -1 fire-and-forget support
│   ├── [P2] SCHC rule consistency (project-LICHEN-cf8r)
│   └── [P2] Vectors: MQTT-SN message test cases
│
├── [P1 epic] Fragmentation Guidance (Section 10.5)
│   ├── [P1] Documentation: SCHC preferred over CoAP Block-wise
│   ├── [P1] Block-wise verification (CLOSED - project-LICHEN-k1p9)
│   ├── [P2] Application chunking protocol for >12KB transfers
│   └── [P2] Vectors: large transfer scenarios
│
├── [P1 epic] Resource Directory (Section 10.6, RFC 9176)
│   ├── [P1] Python: RD registration endpoint (/rd)
│   ├── [P1] Python: RD lookup endpoint (/rd-lookup/res)
│   ├── [P1] Rust: RD registration endpoint
│   ├── [P1] Rust: RD lookup endpoint
│   ├── [P1] Zephyr: RD registration endpoint
│   ├── [P1] Zephyr: RD lookup endpoint
│   ├── [P2] Unbounded entries DoS (project-LICHEN-ad1r)
│   └── [P1] Vectors: RD registration/lookup test cases
│
├── [P2 epic] Gateway Translation (Section 9.1 mesh-internal)
│   ├── [P2] Compact CoT (5681) to CoT XML over TCP 8087
│   ├── [P2] SenML (5682) to CoAP Content-Format 110
│   ├── [P2] Cayenne (5685) to LoRaWAN app server
│   ├── [P2] APRS-IS (5686) to APRS-IS TCP/AX.25 RF
│   └── [P2] NMEA (5687) to Serial/CoAP/SenML
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Invalid port number handling
    ├── [P2] Truncated payload handling
    ├── [P2] Malformed CoAP option handling
    ├── [P2] Duty cycle rollover edge cases
    ├── [P2] Observe subscription limits
    ├── [P2] MQTT-SN topic ID exhaustion
    └── [P2] Fuzz vectors: malformed application payloads
```
```

**Bead count:** ~78 P1 + ~42 P2 = ~120 total

**Notes:** Already closed: project-LICHEN-o6pb (Zephyr CoAP server), project-LICHEN-k1p9 (block transfer). Many CoAP bugs already filed (44 total). SenML bugs already filed (31 total). Python CoAP complete via aiocoap. Zephyr SenML may leverage upstream LwM2M. Cayenne/APRS-IS/NMEA codecs are largely missing across all impls. Duty cycle tracking not explicitly implemented anywhere.

### Chapter 09: Packets and Timing

**Scope:** Packet format examples, size budgets, timing parameters (Trickle/DAO), duty cycle compliance, CSMA/CA, and time synchronization provider

```
```
[P2 epic] Chapter 09: Packets and Timing
├── [P1 epic] Packet Format Documentation and Validation
│   ├── [P1] Vectors: complete packet walkthrough test cases (CoAP→SCHC→L2→PHY)
│   ├── [P1] Vectors: RPL DIO packet format validation
│   ├── [P2] Python: packet size budget calculator
│   ├── [P2] Rust: packet size budget calculator
│   └── [P2] Zephyr: packet size budget calculator
│
├── [P1 epic] Trickle Timer (RFC 6206)
│   ├── [P1] Python: Trickle timer implementation [DONE - rpl/trickle.py]
│   ├── [P1] Rust: Trickle timer implementation [DONE - lichen-rpl/src/trickle.rs]
│   ├── [P1] Zephyr: Trickle timer implementation [DONE - subsys/lichen/rpl/trickle.c]
│   ├── [P1] Vectors: Trickle timer test cases (Imin=4s, Imax=17min, k=10)
│   ├── [P1] Python: spec constants alignment (Imin/Imax/k) [DONE - constants.py]
│   ├── [P1] Rust: spec constants alignment (Imin=256ms should be 4096ms)
│   └── [P2] Cross-validate: Trickle timer behavior parity
│
├── [P1 epic] DAO Timing
│   ├── [P1] Python: DAO initial delay (random 0-2s)
│   ├── [P1] Python: DAO retry backoff (4, 8, 16s exponential)
│   ├── [P1] Python: DAO refresh timer (15 min; half 30-min lifetime)
│   ├── [P1] Rust: DAO initial delay (random 0-2s)
│   ├── [P1] Rust: DAO retry backoff (4, 8, 16s exponential)
│   ├── [P1] Rust: DAO refresh timer (15 min; half 30-min lifetime)
│   ├── [P1] Zephyr: DAO initial delay (random 0-2s)
│   ├── [P1] Zephyr: DAO retry backoff (4, 8, 16s exponential)
│   ├── [P1] Zephyr: DAO refresh timer (15 min; half 30-min lifetime)
│   └── [P1] Vectors: DAO timing scenarios
│
├── [P1 epic] Duty Cycle Tracking
│   ├── [P1] Python: duty cycle tracker implementation [DONE - sim/duty_cycle.py]
│   ├── [P1] Rust: duty cycle tracker implementation [DONE - lichen-core/duty_cycle.rs]
│   ├── [P1] Zephyr: duty cycle tracker implementation
│   ├── [P1] Python: regional limit configuration (EU 1%, US FCC)
│   ├── [P1] Rust: regional limit configuration (EU 1%, US FCC)
│   ├── [P1] Zephyr: regional limit configuration (EU 1%, US FCC)
│   ├── [P1] Vectors: duty cycle calculation test cases
│   ├── [P2] Python: per-channel and sub-band budget tracking
│   ├── [P2] Rust: per-channel and sub-band budget tracking
│   ├── [P2] Zephyr: per-channel and sub-band budget tracking
│   └── [P2] Cross-validate: duty cycle enforcement parity
│
├── [P1 epic] Airtime Calculation
│   ├── [P1] Python: LoRa airtime formula (SF/BW/CR/preamble/payload)
│   ├── [P1] Rust: LoRa airtime formula (SF/BW/CR/preamble/payload)
│   ├── [P1] Zephyr: LoRa airtime formula (SF/BW/CR/preamble/payload)
│   ├── [P1] Vectors: airtime calculation test cases (SF10/125kHz spec examples)
│   └── [P2] Cross-validate: airtime calculation parity
│
├── [P1 epic] CSMA/CA Parameters
│   ├── [P1] Python: CAD timeout constant (3 symbols) [PARTIAL - 2 symbols in constants.py]
│   ├── [P1] Python: backoff unit (10ms) [DONE - CAD_SLOT_MS]
│   ├── [P1] Python: backoff max (5 exponent) [DONE - CAD_MAX_BACKOFF_EXPONENT]
│   ├── [P1] Python: retry limit (3) [DONE - CAD_MAX_CYCLES]
│   ├── [P1] Rust: CSMA/CA parameter constants
│   ├── [P1] Zephyr: CSMA/CA parameter constants
│   ├── [P1] Python: CAD-based CSMA backoff state machine
│   ├── [P1] Rust: CAD-based CSMA backoff state machine
│   ├── [P1] Zephyr: CAD-based CSMA backoff state machine
│   └── [P1] Vectors: CSMA/CA backoff sequence test cases
│
├── [P1 epic] Time Provider Architecture
│   ├── [P1 epic] Monotonic Time
│   │   ├── [P1] Python: monotonic uptime tracking
│   │   ├── [P1] Rust: monotonic uptime tracking
│   │   ├── [P1] Zephyr: monotonic uptime tracking
│   │   └── [P1] Vectors: monotonic time test cases
│   │
│   ├── [P1 epic] Wall Clock Time
│   │   ├── [P1] Python: wall clock validity tracking
│   │   ├── [P1] Rust: wall clock validity tracking
│   │   ├── [P1] Zephyr: wall clock validity tracking
│   │   └── [P1] Vectors: wall clock establishment test cases
│   │
│   ├── [P1 epic] Epoch Floor Validation
│   │   ├── [P1] Python: firmware build epoch floor
│   │   ├── [P1] Rust: firmware build epoch floor
│   │   ├── [P1] Zephyr: firmware build epoch floor
│   │   ├── [P1] Zephyr: board provision epoch handling
│   │   └── [P1] Vectors: epoch floor rejection test cases
│   │
│   ├── [P1 epic] Source Classes
│   │   ├── [P1] Python: source class enumeration (GNSS/Network/Local/Manual/RTC/Monotonic)
│   │   ├── [P1] Rust: source class enumeration
│   │   ├── [P1] Zephyr: source class enumeration
│   │   ├── [P1] Python: source precedence policy
│   │   ├── [P1] Rust: source precedence policy
│   │   ├── [P1] Zephyr: source precedence policy
│   │   └── [P1] Vectors: source class acceptance test cases
│   │
│   ├── [P1 epic] Time Stratum (DIO Time Option)
│   │   ├── [P1] Python: stratum tracking (0-4)
│   │   ├── [P1] Rust: stratum tracking (0-4)
│   │   ├── [P1] Zephyr: stratum tracking (0-4)
│   │   ├── [P1] Python: DIO Time Option encoding/decoding
│   │   ├── [P1] Rust: DIO Time Option encoding/decoding
│   │   ├── [P1] Zephyr: DIO Time Option encoding/decoding
│   │   └── [P1] Vectors: DIO Time Option test cases
│   │
│   ├── [P2 epic] Constrained Node Behavior
│   │   ├── [P2] Python: wall_clock_valid=false handling
│   │   ├── [P2] Rust: wall_clock_valid=false handling
│   │   ├── [P2] Zephyr: wall_clock_valid=false handling
│   │   ├── [P2] SenML relative timestamp fallback
│   │   └── [P2] Vectors: constrained node time scenarios
│   │
│   └── [P2 epic] Border Router Time Responsibilities
│       ├── [P2] Gateway: NTS/Roughtime client
│       ├── [P2] Gateway: time advertisement in DIO
│       ├── [P2] Gateway: CoAP time provider status
│       └── [P2] Vectors: BR time distribution scenarios
│
├── [P1 epic] Data Traffic Timing Guidelines
│   ├── [P2] Python: telemetry interval configuration (5-60 min)
│   ├── [P2] Rust: telemetry interval configuration (5-60 min)
│   ├── [P2] Zephyr: telemetry interval configuration (5-60 min)
│   ├── [P2] Python: heartbeat/keepalive timer (30 min)
│   ├── [P2] Rust: heartbeat/keepalive timer (30 min)
│   └── [P2] Zephyr: heartbeat/keepalive timer (30 min)
│
├── [P1 epic] Integration
│   ├── [P1] Python: duty cycle ↔ TX queue gating
│   ├── [P1] Rust: duty cycle ↔ TX queue gating
│   ├── [P1] Zephyr: duty cycle ↔ TX queue gating
│   ├── [P1] Python: airtime tracking in duty cycle
│   ├── [P1] Rust: airtime tracking in duty cycle
│   ├── [P1] Zephyr: airtime tracking in duty cycle
│   └── [P2] Cross-validate: timing integration parity
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Duty cycle budget exhaustion handling
    ├── [P2] Time source failover behavior
    ├── [P2] CSMA/CA max retry exhaustion
    ├── [P2] Trickle timer overflow handling [DONE - all impls have saturating math]
    ├── [P2] DAO retry exhaustion behavior
    ├── [P2] Clock wrap-safe timer arithmetic
    └── [P2] Fuzz vectors: malformed DIO Time Option
```
```

**Bead count:** ~72 P1 + ~31 P2 = ~103 total

**Notes:** Several implementations already complete: Trickle timer in all three languages, duty cycle in Python/Rust. Rust Trickle uses Imin=256ms (should be 4096ms per spec). Python CAD_SYMBOLS=2 but spec says 3. Time provider is partially designed (docs/firmware-time-provider.md) but implementation tracked separately. No existing test vectors for timing. Cross-references: Ch02a CCP time sync thruline, Ch05 routing (Trickle for DIO, DAO timing), Ch06 keys (replay protection uses monotonic, not wall clock).

### Chapter 11: Local Client Interface (LCI)

**Scope:** Transport bindings (SLIP/BLE/IPC), CoAP resources (/config, /status, /diag, /keys, /msg), forward proxy, and access control

```
```
[P2 epic] Chapter 11: Local Client Interface (LCI)
├── [P1 epic] Transport Bindings
│   ├── [P1 epic] SLIP Framing (Serial/USB)
│   │   ├── [P1] Python: SLIP frame encode/decode — DONE (interface/kiss/framing.py)
│   │   ├── [P1] Python: SLIP stream reader (incremental) — DONE (KissReader class)
│   │   ├── [P1] Rust: SLIP frame encode/decode — DONE (lichen-kiss/framing.rs)
│   │   ├── [P1] Rust: SLIP stream reader (no_std) — DONE (KissReader struct)
│   │   ├── [P1] Zephyr: SLIP transport layer — DONE (transport/slip_transport.c)
│   │   ├── [P1] Zephyr: USB CDC-ACM binding
│   │   └── [P1] Vectors: SLIP framing test cases
│   ├── [P1 epic] BLE GATT Service
│   │   ├── [P1] Python: GATT service stub — DONE (interface/kiss/gatt.py)
│   │   ├── [P1] Python: GATT platform binding (bless)
│   │   ├── [P1] Rust: BLE TNC handler — DONE (lichen-kiss/ble.rs)
│   │   ├── [P1] Rust: BLE platform binding (btleplug/embassy-nrf)
│   │   ├── [P1] Zephyr: BLE IPSP transport — DONE (transport/ble_ipsp_transport.c)
│   │   ├── [P1] Zephyr: GATT service registration
│   │   ├── [P2] Zephyr: MTU negotiation handling
│   │   └── [P1] Vectors: BLE GATT frame reassembly tests
│   ├── [P2 epic] Bluetooth Classic (SPP)
│   │   ├── [P2] Python: SPP/RFCOMM transport
│   │   ├── [P2] Rust: SPP/RFCOMM transport
│   │   └── [P2] Zephyr: SPP transport binding
│   ├── [P2 epic] RTOS IPC (Same-Device)
│   │   ├── [P1] Zephyr: message queue IPC — DONE (app_interface subsys)
│   │   ├── [P2] Zephyr: pipe-based IPC alternative
│   │   └── [P2] Documentation: IPC API usage guide
│   └── [P2 epic] KISS Command Handling
│       ├── [P1] Python: KISS command dispatch — DONE (KissHandler)
│       ├── [P1] Rust: KISS command parsing — DONE (KissCommand enum)
│       ├── [P1] Zephyr: KISS transport — DONE (transport/kiss_transport.c)
│       └── [P2] Vectors: KISS command test cases
│
├── [P1 epic] Client IPv6 Addressing
│   ├── [P1] Python: link-local address assignment
│   ├── [P1] Rust: link-local address assignment
│   ├── [P1] Zephyr: link-local address assignment
│   ├── [P2] EUI-64 derived client address option
│   └── [P1] Vectors: IPv6 address derivation test cases
│
├── [P1 epic] CoAP Resources
│   ├── [P1 epic] Discovery (/.well-known/core)
│   │   ├── [P1] Python: WKC resource + link format — DONE (aiocoap WKCResource)
│   │   ├── [P1] Python: link format parsing — DONE (lci.py parse_link_format)
│   │   ├── [P1] Rust: link format parsing
│   │   ├── [P1] Zephyr: WKC resource — DONE (coap_server.c)
│   │   └── [P1] Vectors: CoRE Link Format test cases
│   ├── [P1 epic] Configuration Resources
│   │   ├── [P1 epic] /config
│   │   │   ├── [P1] Python: GET /config — DONE (ConfigResource)
│   │   │   ├── [P1] Python: PUT /config — DONE (ConfigResource with auth)
│   │   │   ├── [P1] Rust: GET /config client
│   │   │   ├── [P1] Rust: PUT /config client
│   │   │   ├── [P1] Zephyr: GET /config — DONE (coap_config.c)
│   │   │   ├── [P1] Zephyr: PUT /config — DONE (coap_config.c)
│   │   │   └── [P1] Vectors: /config CBOR payloads
│   │   ├── [P1 epic] /config/radio
│   │   │   ├── [P1] Python: GET /config/radio — DONE (via node_info)
│   │   │   ├── [P1] Python: PUT /config/radio
│   │   │   ├── [P1] Rust: GET /config/radio client
│   │   │   ├── [P1] Rust: PUT /config/radio client
│   │   │   ├── [P1] Zephyr: GET /config/radio — DONE
│   │   │   ├── [P1] Zephyr: PUT /config/radio
│   │   │   └── [P1] Vectors: radio config CBOR payloads
│   │   └── [P1 epic] /config/identity
│   │       ├── [P1] Python: GET /config/identity — DONE
│   │       ├── [P1] Rust: GET /config/identity client
│   │       ├── [P1] Zephyr: GET /config/identity — DONE
│   │       └── [P1] Vectors: identity CBOR payloads
│   ├── [P1 epic] Status Resources
│   │   ├── [P1 epic] /status
│   │   │   ├── [P1] Python: GET /status — DONE (StatusResource)
│   │   │   ├── [P1] Python: Observe /status — DONE (ObservableResource)
│   │   │   ├── [P1] Rust: GET /status client — DONE (lichen-client/status.rs)
│   │   │   ├── [P1] Zephyr: GET /status — DONE (coap_status.c)
│   │   │   ├── [P1] Zephyr: Observe /status
│   │   │   ├── [P1] Time object in status payload
│   │   │   └── [P1] Vectors: /status CBOR payloads
│   │   ├── [P1 epic] /status/neighbors
│   │   │   ├── [P1] Python: GET /status/neighbors — DONE (NeighborsResource)
│   │   │   ├── [P1] Python: Observe /status/neighbors
│   │   │   ├── [P1] Rust: GET /status/neighbors client
│   │   │   ├── [P1] Zephyr: GET /status/neighbors — DONE
│   │   │   ├── [P1] Zephyr: Observe /status/neighbors
│   │   │   └── [P1] Vectors: neighbor table CBOR payloads
│   │   └── [P1 epic] /status/routes
│   │       ├── [P1] Python: GET /status/routes — DONE (via lci.py)
│   │       ├── [P1] Rust: GET /status/routes client
│   │       ├── [P1] Zephyr: GET /status/routes
│   │       └── [P1] Vectors: routing table CBOR payloads
│   ├── [P2 epic] Diagnostic Resources
│   │   ├── [P2 epic] /diag
│   │   │   ├── [P2] Python: GET /diag — DONE (lci.py get_diagnostics)
│   │   │   ├── [P2] Rust: GET /diag client
│   │   │   └── [P2] Zephyr: GET /diag
│   │   ├── [P2 epic] /diag/raw/rx
│   │   │   ├── [P2] Python: GET /diag/raw/rx — DONE (lci.py get_raw_rx_status)
│   │   │   ├── [P2] Python: PUT /diag/raw/rx (arm) — DONE (lci.py arm_raw_rx)
│   │   │   ├── [P2] Python: Observe /diag/raw/rx/events — DONE (RawRxSubscription)
│   │   │   ├── [P2] Rust: raw RX client
│   │   │   ├── [P2] Zephyr: raw RX resource
│   │   │   ├── [P2] Zephyr: raw RX arming with TTL
│   │   │   └── [P2] Vectors: raw RX event CBOR payloads
│   │   └── [P2 epic] /diag/raw/tx
│   │       ├── [P2] Python: POST /diag/raw/tx — DONE (lci.py send_raw_tx)
│   │       ├── [P2] Rust: raw TX client
│   │       ├── [P2] Zephyr: raw TX resource
│   │       ├── [P2] Zephyr: rate limiting + regulatory validation
│   │       └── [P2] Vectors: raw TX CBOR payloads
│   ├── [P1 epic] Key Store (/keys)
│   │   ├── [P1] Python: GET /keys listing
│   │   ├── [P1] Python: GET /keys/{addr}/{key-id}
│   │   ├── [P1] Python: PUT /keys/{addr}/{key-id} (trust update)
│   │   ├── [P1] Python: DELETE /keys/{addr}/{key-id}
│   │   ├── [P1] Rust: key store client
│   │   ├── [P1] Zephyr: GET /keys — DONE (coap_keys.c)
│   │   ├── [P1] Zephyr: PUT /keys — DONE (coap_keys.c)
│   │   ├── [P1] Zephyr: DELETE /keys — DONE (coap_keys.c)
│   │   ├── [P1] Key ID validation (SHA-256 of pubkey)
│   │   ├── [P2] 4.09 Conflict for ambiguous address lookups
│   │   └── [P1] Vectors: key store CBOR payloads
│   ├── [P1 epic] Forward Proxy (Mesh Reachability)
│   │   ├── [P1] Python: ProxyResource — DONE (resources.py ProxyResource)
│   │   ├── [P1] Python: Proxy-Uri validation (SSRF prevention) — DONE
│   │   ├── [P1] Rust: Proxy-Uri option parsing — DONE (lichen-coap/option.rs)
│   │   ├── [P1] Rust: forward proxy implementation
│   │   ├── [P1] Zephyr: forward proxy resource
│   │   ├── [P1] Zephyr: mesh address validation
│   │   ├── [P1] Authorization: method + target filtering
│   │   └── [P1] Vectors: proxy request/response test cases
│   └── [P1 epic] Messaging Resources
│       ├── [P1 epic] /msg/inbox
│       │   ├── [P1] Python: GET /msg/inbox — DONE (MessagesResource)
│       │   ├── [P1] Python: POST /msg/inbox — DONE (MessagesResource)
│       │   ├── [P1] Python: Observe /msg/inbox — DONE (ObservableResource)
│       │   ├── [P1] Rust: messaging client — DONE (lichen-client/msg.rs)
│       │   ├── [P1] Zephyr: GET /msg/inbox — DONE (coap_msg.c)
│       │   ├── [P1] Zephyr: POST /msg/inbox — DONE (coap_msg.c)
│       │   ├── [P1] Zephyr: Observe /msg/inbox
│       │   └── [P1] Vectors: messaging CBOR payloads
│       ├── [P1 epic] /msg/sent
│       │   ├── [P1] Python: GET /msg/sent — DONE (SentMessagesResource)
│       │   ├── [P1] Python: GET /msg/sent/{id} — DONE (SentMessageDetailResource)
│       │   ├── [P1] Rust: sent messages client
│       │   ├── [P1] Zephyr: GET /msg/sent
│       │   └── [P1] Vectors: sent messages CBOR payloads
│       └── [P1 epic] /msg/ack
│           ├── [P1] Python: POST /msg/ack — DONE (MessageReceiptsResource)
│           ├── [P1] Rust: receipts client
│           ├── [P1] Zephyr: POST /msg/ack
│           └── [P1] Vectors: receipt CBOR payloads
│
├── [P1 epic] Security
│   ├── [P1 epic] Transport Security
│   │   ├── [P1] Zephyr: BLE LE Secure Connections requirement
│   │   ├── [P2] Documentation: transport security matrix
│   │   └── [P2] Vectors: transport security validation
│   ├── [P1 epic] Application Security (OSCORE)
│   │   ├── [P1] Python: OSCORE over local link
│   │   ├── [P1] Rust: OSCORE over local link
│   │   ├── [P1] Zephyr: OSCORE context for local link — DONE (coap_oscore.c)
│   │   └── [P1] Vectors: OSCORE-protected LCI exchanges
│   └── [P1 epic] Access Control
│       ├── [P1] Python: access level enforcement — DONE (ConfigResource auth)
│       ├── [P1] Rust: access level types
│       ├── [P1] Zephyr: access level enforcement
│       ├── [P1] Read-only principal restrictions
│       ├── [P1] Standard principal restrictions (no /diag/raw/*)
│       ├── [P1] Admin principal full access
│       └── [P1] Vectors: access control test matrix
│
├── [P1 epic] Integration
│   ├── [P1] Python: LCI client abstraction — DONE (lci.py LciClient)
│   ├── [P1] Python: transport protocol trait — DONE (ResourceTransport)
│   ├── [P1] Rust: LCI client abstraction
│   ├── [P1] Zephyr: CoAP server integration — DONE (coap_server.c)
│   ├── [P2] Cross-validate: Python client ↔ Zephyr firmware
│   ├── [P2] Cross-validate: Rust client ↔ Zephyr firmware
│   └── [P2] Cross-validate: all transports interop
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Malformed CBOR payload handling
    ├── [P2] Observe registration limits
    ├── [P2] Large payload fragmentation (Block1/Block2)
    ├── [P2] Connection timeout handling
    ├── [P2] BLE disconnect recovery
    ├── [P2] Raw diagnostic abuse prevention
    ├── [P2] Legacy protocol rejection (0xC1 framing)
    └── [P2] Fuzz vectors: malformed LCI packets
```
```

**Bead count:** ~92 P1 + ~35 P2 = ~127 total

**Notes:** Many Python CoAP resources and Zephyr firmware CoAP handlers are already implemented. Key gaps: Rust forward proxy, Rust key store client, Zephyr forward proxy, BLE platform bindings, and comprehensive test vectors. Existing bead project-LICHEN-jtup covers Python LCI CoAP proxying alignment.

### Chapter 12: Applications

**Scope:** Application-layer CoAP resources: messaging, position, waypoints, SOS, presence, check-in, range testing, and groups

```
```
[P1 epic] Chapter 12: Applications
├── [P1 epic] 18.1 Messaging
│   ├── [P1 epic] Core Messaging
│   │   ├── [P1] Python: /msg/inbox GET (Observable) [DONE]
│   │   ├── [P1] Python: /msg/sent POST + GET [DONE]
│   │   ├── [P1] Python: /msg/ack POST [DONE]
│   │   ├── [P1] Rust: msg domain types + CBOR codec [DONE]
│   │   ├── [P1] Zephyr: /msg/inbox GET (Observable) [DONE]
│   │   ├── [P1] Zephyr: /msg/sent POST + /msg/sent/{id} GET [DONE]
│   │   └── [P1] Zephyr: /msg/ack POST [DONE]
│   ├── [P1 epic] Delivery Receipts
│   │   ├── [P1] Python: receipt status handling (delivered/read/failed)
│   │   ├── [P1] Rust: receipt types + codec
│   │   ├── [P1] Zephyr: receipt status propagation
│   │   └── [P1] Vectors: receipt round-trip test cases
│   ├── [P2 epic] Canned Messages
│   │   ├── [P2] Python: /msg/canned GET + POST by canned ID
│   │   ├── [P2] Rust: canned message types
│   │   ├── [P2] Zephyr: /msg/canned resource
│   │   └── [P2] Vectors: canned message encoding
│   ├── [P2 epic] Store-and-Forward
│   │   ├── [P2] Python: S&F node capability + storage limits
│   │   ├── [P2] Python: eviction policy (expired -> per-dest fairness -> FIFO)
│   │   ├── [P2] Python: back-pressure signaling (5.03, 4.13, etc.)
│   │   ├── [P2] Rust: S&F types + status codes
│   │   ├── [P2] Zephyr: S&F storage with memory reservation
│   │   ├── [P2] Zephyr: S&F delivery on destination reachable
│   │   └── [P2] Vectors: S&F storage/eviction/delivery scenarios
│   └── [P1] Vectors: messaging inbox/sent/ack round-trip
│
├── [P1 epic] 18.2 Position Sharing
│   ├── [P1 epic] Position Beacon
│   │   ├── [P1] Python: /pos PUT (SenML+CBOR) [DONE - /location]
│   │   ├── [P1] Rust: Position SenML codec [DONE]
│   │   ├── [P1] Zephyr: /sensors/location GET [DONE]
│   │   ├── [P1] Zephyr: position beacon broadcast (interval: 60s moving, 300s stationary)
│   │   └── [P1] Vectors: SenML position encoding (lat/lon/alt/speed/heading)
│   ├── [P1 epic] Position Cache
│   │   ├── [P1] Python: /pos/cache GET (peer positions)
│   │   ├── [P1] Rust: position cache types
│   │   ├── [P1] Zephyr: /pos/cache GET with age_s tracking
│   │   └── [P1] Vectors: position cache response format
│   ├── [P1 epic] Position Query + Subscribe
│   │   ├── [P1] Python: /sensors/location GET (Observable)
│   │   ├── [P1] Rust: position query client types
│   │   ├── [P1] Zephyr: /sensors/location Observable notifications
│   │   └── [P1] Vectors: position observe notification sequences
│   ├── [P2 epic] Position Privacy
│   │   ├── [P2] Python: privacy modes (public/group/private/off)
│   │   ├── [P2] Python: /config/privacy resource
│   │   ├── [P2] Rust: privacy config types
│   │   ├── [P2] Zephyr: privacy mode enforcement
│   │   ├── [P2] Zephyr: group beacon encryption (OSCORE)
│   │   ├── [P2] Zephyr: private mode whitelist (/config/privacy/allowed)
│   │   └── [P2] Vectors: privacy mode enforcement scenarios
│   └── [P1] Cross-validate: position SenML parity across impls
│
├── [P1 epic] 18.3 Waypoints
│   ├── [P1 epic] Waypoint CRUD
│   │   ├── [P1] Python: /waypoints GET (list) + POST (create)
│   │   ├── [P1] Python: /waypoints/{id} GET/PUT/DELETE
│   │   ├── [P1] Rust: waypoint domain types + CBOR codec
│   │   ├── [P1] Zephyr: /waypoints resource + storage
│   │   ├── [P1] Zephyr: /waypoints/{id} detail resource
│   │   └── [P1] Vectors: waypoint CBOR encoding (all fields)
│   ├── [P1 epic] Waypoint Sharing
│   │   ├── [P1] Python: unicast waypoint POST to peer
│   │   ├── [P1] Rust: waypoint sharing client
│   │   ├── [P1] Zephyr: receive shared waypoint
│   │   └── [P1] Vectors: waypoint sharing protocol
│   ├── [P2 epic] Routes
│   │   ├── [P2] Python: /routes GET/POST + /routes/{id}
│   │   ├── [P2] Rust: route domain types
│   │   ├── [P2] Zephyr: /routes resource
│   │   └── [P2] Vectors: route CBOR encoding
│   └── [P1] Cross-validate: waypoint encoding parity
│
├── [P1 epic] 18.4 Emergency / SOS
│   ├── [P1 epic] SOS Core
│   │   ├── [P1] Python: /sos GET/PUT/DELETE (Observable) [DONE]
│   │   ├── [P1] Rust: SOS domain types + CBOR codec
│   │   ├── [P1] Zephyr: /sos resource with state machine
│   │   ├── [P1] Zephyr: SOS alert format encoding
│   │   └── [P1] Vectors: SOS CBOR encoding (type/node/ts/lat/lon/msg/seq)
│   ├── [P1 epic] SOS Authentication
│   │   ├── [P1] Python: origin Schnorr48 signature generation
│   │   ├── [P1] Python: SOS signature verification (per spec §18.4.1)
│   │   ├── [P1] Rust: SOS signature types
│   │   ├── [P1] Zephyr: origin signature generation
│   │   ├── [P1] Zephyr: receiver signature verification
│   │   ├── [P1] Zephyr: reject unsigned/invalid SOS
│   │   └── [P1] Vectors: SOS signature test vectors (domain string, canonical CBOR)
│   ├── [P1 epic] SOS Rate Limiting
│   │   ├── [P1] Python: per-source rate limit (10min cooldown, 3/hour max)
│   │   ├── [P1] Rust: rate limit tracking types
│   │   ├── [P1] Zephyr: rate limit enforcement (monotonic uptime)
│   │   ├── [P1] Zephyr: burst allowance (2)
│   │   └── [P1] Vectors: rate limit enforcement scenarios
│   ├── [P1 epic] SOS Relay + Flooding
│   │   ├── [P1] Python: SOS re-broadcast (TTL-limited, once per SOS ID)
│   │   ├── [P1] Zephyr: SOS relay with link signature replacement
│   │   ├── [P1] Zephyr: serial replay window per verified origin
│   │   └── [P1] Vectors: SOS relay chain test cases
│   ├── [P2 epic] SOS Hardening
│   │   ├── [P2] Python: soft blacklist (reputation tracking)
│   │   ├── [P2] Zephyr: reputation scoring + threshold
│   │   ├── [P2] Zephyr: operator override (clear rate limit, manual blacklist)
│   │   └── [P2] Vectors: reputation/blacklist scenarios
│   ├── [P1 epic] SOS Network Behavior
│   │   ├── [P1] Python: priority routing (SOS packets first)
│   │   ├── [P1] Python: beacon boost (30s interval during SOS)
│   │   ├── [P1] Zephyr: TX queue priority for SOS
│   │   ├── [P1] Zephyr: 4-hour SOS timeout
│   │   └── [P1] Vectors: SOS network behavior test cases
│   ├── [P2 epic] SOS Log + History
│   │   ├── [P2] Python: /sos/log GET
│   │   ├── [P2] Rust: SOS log types
│   │   ├── [P2] Zephyr: /sos/log resource
│   │   └── [P2] Vectors: SOS log encoding
│   └── [P1] Cross-validate: SOS signature/rate-limit parity
│
├── [P1 epic] 18.5 Presence and Status
│   ├── [P1 epic] Presence Core
│   │   ├── [P1] Python: /presence GET/PUT (Observable) [DONE]
│   │   ├── [P1] Rust: presence domain types + CBOR codec
│   │   ├── [P1] Zephyr: /presence resource with state
│   │   └── [P1] Vectors: presence CBOR encoding (status/activity/msg/battery/ts)
│   ├── [P1 epic] Presence Cache
│   │   ├── [P1] Python: /presence/cache GET (all known nodes)
│   │   ├── [P1] Rust: presence cache types
│   │   ├── [P1] Zephyr: /presence/cache with age_s tracking
│   │   └── [P1] Vectors: presence cache response format
│   ├── [P2 epic] Automatic Status
│   │   ├── [P2] Python: auto-update from GPS (moving/stationary)
│   │   ├── [P2] Python: away after 30min inactivity
│   │   ├── [P2] Zephyr: automatic presence transitions
│   │   └── [P2] Vectors: auto-status transition test cases
│   └── [P1] Cross-validate: presence encoding parity
│
├── [P2 epic] 18.6 Check-In / Roll Call
│   ├── [P2 epic] Check-In
│   │   ├── [P2] Python: /checkin POST (node -> leader)
│   │   ├── [P2] Rust: check-in domain types
│   │   ├── [P2] Zephyr: /checkin resource
│   │   └── [P2] Vectors: check-in CBOR encoding
│   ├── [P2 epic] Roll Call
│   │   ├── [P2] Python: /rollcall POST (leader initiates)
│   │   ├── [P2] Python: /rollcall/{id} GET (status tracking)
│   │   ├── [P2] Rust: roll call types (responded/missing)
│   │   ├── [P2] Zephyr: /rollcall resource
│   │   ├── [P2] Zephyr: /rollcall/{id} with timeout tracking
│   │   └── [P2] Vectors: roll call protocol sequences
│   ├── [P2 epic] Scheduled Check-Ins
│   │   ├── [P2] Python: /config/checkin PUT (interval, target, include_location)
│   │   ├── [P2] Zephyr: scheduled check-in timer
│   │   ├── [P2] Zephyr: missed check-in alert trigger
│   │   └── [P2] Vectors: scheduled check-in scenarios
│   └── [P2] Cross-validate: check-in/rollcall parity
│
├── [P2 epic] 18.7 Range Testing
│   ├── [P2 epic] Basic Ping
│   │   ├── [P2] Python: ICMPv6 Echo via /diag
│   │   ├── [P2] Zephyr: ICMPv6 Echo support
│   │   └── [P2] Vectors: ping round-trip
│   ├── [P2 epic] Extended Range Test
│   │   ├── [P2] Python: /diag/rangetest POST (seq, payload_len, count)
│   │   ├── [P2] Python: SenML response (rssi/snr/sf/freq)
│   │   ├── [P2] Rust: range test types
│   │   ├── [P2] Zephyr: /diag/rangetest resource
│   │   ├── [P2] Zephyr: radio telemetry in response
│   │   └── [P2] Vectors: range test SenML encoding
│   ├── [P2 epic] Continuous Range Test
│   │   ├── [P2] Python: /diag/rangetest Observable (interval_ms)
│   │   ├── [P2] Zephyr: periodic range test notifications
│   │   └── [P2] Vectors: continuous test sequences
│   ├── [P2 epic] Trace Route
│   │   ├── [P2] Python: /diag/traceroute GET (hops array)
│   │   ├── [P2] Rust: traceroute types
│   │   ├── [P2] Zephyr: /diag/traceroute from RPL source routing
│   │   └── [P2] Vectors: traceroute response encoding
│   └── [P2] Cross-validate: range test telemetry parity
│
├── [P2 epic] 18.8 Groups and Channels
│   ├── [P2 epic] Group Core
│   │   ├── [P2] Python: /groups GET/POST (create group)
│   │   ├── [P2] Python: /groups/{id} GET/PUT/DELETE
│   │   ├── [P2] Rust: group domain types (id/name/mcast/owner/admins/members)
│   │   ├── [P2] Zephyr: /groups resource + storage
│   │   └── [P2] Vectors: group CBOR encoding
│   ├── [P2 epic] Group Membership Protocol
│   │   ├── [P2] Python: /groups/invite POST (invitation with signature)
│   │   ├── [P2] Python: /groups/remove POST (removal with signature)
│   │   ├── [P2] Python: signature validation for inviter/remover
│   │   ├── [P2] Rust: invitation/removal types
│   │   ├── [P2] Zephyr: invitation handling
│   │   ├── [P2] Zephyr: removal handling
│   │   └── [P2] Vectors: membership protocol sequences
│   ├── [P2 epic] Group Key Management
│   │   ├── [P2] Python: /groups/{id}/key POST (request join key)
│   │   ├── [P2] Python: key distribution via pairwise OSCORE
│   │   ├── [P2] Zephyr: Group OSCORE key storage
│   │   ├── [P2] Zephyr: key epoch tracking
│   │   └── [P2] Vectors: key distribution test cases
│   ├── [P2 epic] Group Rekeying
│   │   ├── [P2] Python: rekey on member removal
│   │   ├── [P2] Python: key_epoch increment + grace period
│   │   ├── [P2] Zephyr: rekeying state machine
│   │   └── [P2] Vectors: rekeying protocol sequences
│   ├── [P2 epic] Group Multicast Addressing
│   │   ├── [P2] Python: ff13::GGGG:GGGG address derivation (SHA-256 of id)
│   │   ├── [P2] Python: collision resolution
│   │   ├── [P2] Zephyr: multicast address calculation
│   │   ├── [P2] Zephyr: gateway blocks realm-local to Yggdrasil
│   │   └── [P2] Vectors: multicast address derivation
│   ├── [P2 epic] Group Messaging + Position
│   │   ├── [P2] Python: POST to [group-mcast]/msg/inbox
│   │   ├── [P2] Python: PUT to [group-mcast]/pos
│   │   ├── [P2] Zephyr: group multicast receive
│   │   └── [P2] Vectors: group messaging scenarios
│   └── [P2] Cross-validate: group membership/key parity
│
├── [P1 epic] Integration
│   ├── [P1] Python: CoAP resource site integration [DONE]
│   ├── [P1] Rust: lichen-client library integration
│   ├── [P1] Zephyr: lichen_coap service integration [DONE]
│   ├── [P2] Memory budget verification (Zephyr - constrained)
│   └── [P2] Observable resource notification flood protection
│
└── [P2 epic] Edge Cases / Hardening
    ├── [P2] Malformed CBOR payload handling (all resources)
    ├── [P2] Missing required fields rejection
    ├── [P2] Oversized message handling (4.13 response)
    ├── [P2] Observable resource cleanup on client disconnect
    ├── [P2] Content-Format negotiation (CBOR vs SenML+CBOR)
    └── [P2] Fuzz vectors: malformed application messages
```
```

**Bead count:** ~76 P1 + ~71 P2 = ~147 total

**Notes:** Many Python basics are DONE (messaging, presence, SOS, location). Rust has domain types for msg/pos/status but not SOS/waypoints/groups. Zephyr has messaging/status/location but missing SOS/presence/waypoints/groups/range-testing. No application-layer test vectors exist yet (only lower-layer vectors). SOS authentication (Schnorr48 origin signature) is a significant P1 effort requiring careful cross-validation. Group OSCORE (RFC 9594) is complex and may be deferred to P2. Store-and-forward is OPTIONAL per spec.

### Chapter Expansion Summary

| Chapter | P1 | P2 | Total |
|---------|----|----|-------|
| 02 Physical and Link Layer | 55 | 27 | 82 |
| 02a Coordinated Capacity Profile (CCP) | 28 | 106 | 134 |
| 03 Adaptation Layer (SCHC) | 63 | 28 | 91 |
| 04 Network Layer (IPv6) | 47 | 48 | 95 |
| 05 Routing | 108 | 36 | 144 |
| 06 Security | 71 | 36 | 107 |
| 07 Transport and Application | 78 | 42 | 120 |
| 09 Packets and Timing | 72 | 31 | 103 |
| 11 Local Client Interface (LCI) | 92 | 35 | 127 |
| 12 Applications | 76 | 71 | 147 |
| **All Chapters** | **690** | **460** | **1150** |


### Chapter 03: Adaptation Layer (SCHC)

**Scope:** SCHC compression rules 1-6, fragmentation/reassembly, context matching, rule ID encoding

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

**Bead count:** ~63 P1 + ~28 P2 = ~91 total

**Notes:** Python uses OpenSCHC patterns. Rust partial (missing some headers/context). Zephyr partial (missing fragmentation). Existing beads: project-LICHEN-hwx9 (fragmentation), project-LICHEN-vsiw (rules 5-6), project-LICHEN-qopb (Rust gaps), project-LICHEN-bcds (Zephyr gaps).
