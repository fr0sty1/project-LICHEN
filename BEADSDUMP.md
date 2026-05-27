# LICHEN Beads Issue Dump

Exported: 2026-05-27T06:43:02Z

## Summary

- **Open:** 34
- **In Progress:** 0
- **Closed:** 14
- **Total:** 48

## P0 Critical

### ○ [lora-ipv6-mesh-sw3] Validate STM32WL memory budget

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:27Z
- **Blocked by:** lora-ipv6-mesh-ijj

**Description:**

Build minimal Zephyr+IPv6+CoAP on nucleo_wl55jc. Run west build -t ram_report and rom_report. Target: <50KB RAM, <220KB flash. If exceeded, evaluate RIOT OS fallback. This is a go/no-go gate for Zephyr on STM32WL.

---

### ○ [lora-ipv6-mesh-cek] Build wireless channel simulator

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:45Z

**Description:**

Python module simulating LoRa radio propagation. Features: (1) Distance-based path loss model, (2) SF/BW impact on range and data rate, (3) Packet collision detection (simultaneous TX), (4) Configurable packet loss/BER, (5) Propagation delay, (6) Duty cycle tracking per node, (7) SNR/RSSI calculation. Should support multiple nodes in a topology.

---

### ✓ [lora-ipv6-mesh-ruc] Spec: Define truncated Ed25519 algorithm

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:04Z
- **Closed:** 2026-05-27T05:23:20Z

**Description:**

The spec says 'we use a deterministic scheme where the second half is derived from the first' for truncated Ed25519 signatures but provides no concrete algorithm. This is non-standard cryptography with no security analysis. Need to either: (1) specify exact derivation algorithm with security proof, or (2) switch to standard ECDSA approach mentioned in 8.4. Violates 'no hand-rolled crypto' principle.

**Resolution:**

Resolved: Use Schnorr (e₁₂₈, s) variant - 48 bytes, well-known construction, 128-bit security. Added relay-mutable vs signed field separation and signature caching. Updated spec/06-security.md.

---

### ✓ [lora-ipv6-mesh-0tt] Spec: Define time synchronization mechanism

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:05Z
- **Closed:** 2026-05-27T05:29:09Z

**Description:**

Time sync is listed as 'open question' but is critical for: replay protection (SeqNum wrapping), SenML timestamps, message TTL expiration, scheduled check-ins, OSCORE sequence numbers. Options mentioned: NTP over CoAP, GPS, DIO piggyback. Need to pick one and specify protocol.

**Resolution:**

Resolved: Hierarchical time sources (GPS > gpsd > NTS > Roughtime > mesh peer > none). Stratum propagated via DIO Time Option. Constrained nodes gracefully degrade to monotonic counters. Updated spec/09-packets-timing.md.

---

### ✓ [lora-ipv6-mesh-2w4] Spec: Design 6LoWPAN over LoRa adaptation layer

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:06Z
- **Closed:** 2026-05-27T05:32:11Z

**Description:**

Listed as 'open question' but foundational. LoRa is not 802.15.4 — Zephyr's 6LoWPAN assumes 802.15.4 MAC semantics (ACKs, CSMA-CA timing, frame formats). Need concrete adaptation layer design covering: frame format mapping, ACK handling, timing parameters, integration with SCHC.

**Resolution:**

Resolved: Use SCHC (RFC 8724) instead of 6LoWPAN IPHC. No 802.15.4 anywhere. Stack: IPv6 → SCHC → LICHEN Link Layer → LoRa PHY. Zephyr requires custom L2. Updated spec/03-adaptation.md.

---

## P1 High

### ○ [lora-ipv6-mesh-s80] Spec: Add SOS authentication and rate limiting

- **Type:** bug
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:09Z

**Description:**

Emergency/SOS section specifies 're-broadcast once (TTL-limited)' but no authentication. Attack vector: flood network with fake SOS messages causing DoS. Need: (1) require Ed25519 signature on SOS, (2) specify rate limiting (e.g., 1 SOS per node per hour), (3) define reputation/blacklist for SOS abusers.

---

### ○ [lora-ipv6-mesh-3t6] Spec: Address 16-bit sequence number wrapping

- **Type:** bug
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:11Z

**Description:**

16-bit SeqNum with 32-entry window is weak. High-traffic nodes wrap in ~65K packets. After wrap, delayed replays become possible. Need: (1) specify behavior on wrap, (2) add epoch counter or timestamp component, (3) define state recovery after reboot. Consider 32-bit SeqNum or hybrid approach.

---

### ○ [lora-ipv6-mesh-7xg] Phase 0: Python Prototype + Simulation

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:46Z

**Description:**

Build Python prototype with simulated wireless to validate protocol design before embedded implementation. Exit criteria: multi-node simulation runs, SCHC compression validated, RPL DODAG forms, CoAP messaging works end-to-end over simulated LoRa links.

---

### ○ [lora-ipv6-mesh-71u] Phase 1: Physical & Link Layer

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:49Z
- **Blocked by:** lora-ipv6-mesh-7xg

**Description:**

Transmit and receive authenticated frames over LoRa. Exit criteria: two nodes exchange authenticated frames, replay attack blocked, test vectors for link layer.

---

### ○ [lora-ipv6-mesh-68r] Phase 2: SCHC Compression

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:50Z
- **Blocked by:** lora-ipv6-mesh-71u

**Description:**

RFC 8724 SCHC for IPv6/UDP/CoAP compression. Exit criteria: all rules implemented and tested, fragmentation working, Rust and C produce identical output.

---

### ○ [lora-ipv6-mesh-7ry] Phase 3: IPv6 and 6LoWPAN

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:51Z
- **Blocked by:** lora-ipv6-mesh-68r

**Description:**

Full IPv6 with layered addressing. Exit criteria: nodes can ping (link-local), ULA addresses work, isolated mesh self-organizes.

---

### ○ [lora-ipv6-mesh-d5c] Phase 4: RPL Routing

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:53Z
- **Blocked by:** lora-ipv6-mesh-7ry

**Description:**

Mesh formation with MRHOF objective function. Exit criteria: 5-node mesh forms DODAG, upward and downward routing work, parent switching on link failure.

---

### ○ [lora-ipv6-mesh-42x] Create Rust workspace with no_std crates

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:24Z
- **Blocked by:** lora-ipv6-mesh-ijj

**Description:**

Set up rust/ directory with Cargo.toml workspace. Create stub crates: lichen-core, lichen-link, lichen-schc, lichen-coap, lichen-senml, lichen-apps, lichen-node, lichen-gateway, lichen-sim. All core crates should be no_std by default.

---

### ○ [lora-ipv6-mesh-ihv] Set up Zephyr west workspace

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:26Z
- **Blocked by:** lora-ipv6-mesh-ijj

**Description:**

Create zephyr/ directory with west.yml manifest. Set up CMakeLists.txt, Kconfig. Create board overlays for heltec_lora32_v3, rak4631, tbeam_supreme, nucleo_wl55jc. Verify west build succeeds for each board.

---

### ○ [lora-ipv6-mesh-p4w] Implement Radio abstraction trait

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:59Z

**Description:**

Create Radio trait with: configure(), transmit(), receive(), cad(), rssi(), snr(). Implement for sx126x, sx127x, and simulated backends. Per spec section 3.

---

### ○ [lora-ipv6-mesh-fw4] Implement link layer frame format

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:11:00Z

**Description:**

Per spec section 4: Length(1B) + LLSec(1B) + SeqNum(2B) + DstAddr(2-8B) + Payload + MIC(4-8B). Implement encoding/decoding in both Rust and C. Create test vectors.

---

### ○ [lora-ipv6-mesh-9nj] Implement replay protection

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:11:02Z

**Description:**

16-bit sequence number with 32-entry sliding window per sender. Track per-sender SeqNum state. Reject if SeqNum <= last_seen (accounting for window).

---

### ○ [lora-ipv6-mesh-ijj] Python prototype validates protocol design

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:11Z
- **Blocked by:** lora-ipv6-mesh-1a0 lora-ipv6-mesh-fxi

**Description:**

Gate for moving to embedded implementation. Python prototype must demonstrate: SCHC compression works, RPL DODAG forms in simulation, CoAP messaging works end-to-end, test vectors generated for Rust/C.

---

### ○ [lora-ipv6-mesh-ux9] Implement simulated radio interface

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:47Z
- **Blocked by:** lora-ipv6-mesh-cek

**Description:**

Python Radio class matching the trait from spec. Methods: configure(), transmit(), receive(), cad(), rssi(), snr(). Backed by wireless channel simulator. Async/event-driven design.

---

### ○ [lora-ipv6-mesh-tz8] Implement link layer in Python

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:49Z
- **Blocked by:** lora-ipv6-mesh-ux9

**Description:**

Python implementation of spec section 4: frame format (Length+LLSec+SeqNum+DstAddr+Payload+Sig), Ed25519 signatures (use PyNaCl), replay protection with sliding window. Generate test vectors.

---

### ○ [lora-ipv6-mesh-5d7] Implement SCHC compression in Python

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:50Z
- **Blocked by:** lora-ipv6-mesh-tz8

**Description:**

Python implementation of RFC 8724 SCHC. Implement rules 0-4 from spec Appendix A. Compression and decompression. ACK-on-Error fragmentation. Generate test vectors for each rule.

---

### ○ [lora-ipv6-mesh-zev] Implement minimal IPv6/6LoWPAN in Python

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:53Z
- **Blocked by:** lora-ipv6-mesh-5d7

**Description:**

Python IPv6 packet construction/parsing. 6LoWPAN IPHC compression. Address handling: link-local, ULA, IID derivation from EUI-64. ICMPv6 echo. Integrate with SCHC layer.

---

### ○ [lora-ipv6-mesh-eja] Implement RPL routing in Python

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:55Z
- **Blocked by:** lora-ipv6-mesh-zev

**Description:**

Python implementation of RFC 6550 RPL. DIO/DIS/DAO/DAO-ACK messages. Trickle timer. MRHOF objective function with ETX. DODAG formation. Non-storing mode with source routing. Test with 5+ node topology.

---

### ○ [lora-ipv6-mesh-1a0] Integrate aiocoap for CoAP

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:56Z
- **Blocked by:** lora-ipv6-mesh-eja

**Description:**

Use aiocoap library for CoAP client/server. Integrate with LICHEN stack (SCHC compression, link layer). Implement basic resources: /.well-known/core, /status. Test request/response over simulated multi-hop mesh.

---

### ○ [lora-ipv6-mesh-fxi] Build simulation harness

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:58Z

**Description:**

Python simulation runner. Features: (1) Topology definition (node positions, links), (2) Event-driven simulation loop, (3) Packet capture/logging, (4) Metrics collection (latency, delivery rate, collisions), (5) Visualization of DODAG formation. Support for reproducible runs (seeded RNG).

---

### ○ [lora-ipv6-mesh-chh] Create Python project structure

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:14:59Z

**Description:**

Set up python/ directory with: pyproject.toml, src/lichen/, tests/, uv or poetry for deps. Dependencies: pynacl, aiocoap, asyncio. Type hints throughout. pytest for testing.

---

### ✓ [lora-ipv6-mesh-s3b] Spec: Define OSCORE key derivation from Ed25519

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:08Z
- **Closed:** 2026-05-27T05:45:57Z

**Description:**

TOFU trust model binds Ed25519 pubkeys to nodes, but OSCORE requires symmetric master secrets. How are OSCORE contexts derived from Ed25519 keypairs? Options: ECDH-style key agreement, HKDF from shared secret, pre-shared context. Must specify concrete algorithm for trust model to work end-to-end.

**Resolution:**

Added EDHOC (RFC 9528) for OSCORE key derivation in spec/06-security.md section 8.8

---

## P2 Medium

### ○ [lora-ipv6-mesh-o9l] Spec: Define OTA firmware update mechanism

- **Type:** feature
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:14Z

**Description:**

No firmware update mechanism specified. Critical for IoT security — devices need patches. Consider: CoAP block-wise transfer for images, SUIT manifest (RFC 9019), secure boot verification, rollback protection. This is essential for production deployment.

---

### ○ [lora-ipv6-mesh-1ru] Phase 5: Security Layer

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:54Z
- **Blocked by:** lora-ipv6-mesh-d5c

**Description:**

TOFU trust model, OSCORE encryption. Exit criteria: TOFU key exchange works, OSCORE-protected CoAP works, key pinning with change detection.

---

### ○ [lora-ipv6-mesh-gb3] Phase 6: Local Client Interface

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:56Z
- **Blocked by:** lora-ipv6-mesh-1ru

**Description:**

IPv6+CoAP interface for phone apps and local clients. Exit criteria: SLIP framing works over serial, BLE UART works, CoAP resources implemented, client can address mesh nodes through local node.

---

### ○ [lora-ipv6-mesh-bi0] Phase 7: SenML Sensors

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:57Z
- **Blocked by:** lora-ipv6-mesh-gb3

**Description:**

RFC 8428 SenML for all sensor data. Exit criteria: all sensor profiles implemented, observable resources work, position beaconing works.

---

### ○ [lora-ipv6-mesh-nre] Phase 8: Applications

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:09:59Z
- **Blocked by:** lora-ipv6-mesh-bi0

**Description:**

Tactical radio features: messaging, position sharing, waypoints, SOS, presence, check-in, range testing, groups. Exit criteria: all P0 applications working, SOS priority handling works, group messaging works.

---

### ○ [lora-ipv6-mesh-45t] Phase 9: Border Router

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:00Z
- **Blocked by:** lora-ipv6-mesh-nre

**Description:**

Full 6LBR connecting mesh to internet. Exit criteria: internet host can ping mesh node, mesh node can reach internet, Resource Directory operational.

---

### ○ [lora-ipv6-mesh-9dq] Define shared constants

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:28Z

**Description:**

Create shared header/module with: frequencies per region, sync word 0x34, CoAP ports (5683, 5684), MQTT-SN port (10883), SCHC rule IDs, RPL parameters. Must be usable from both Rust and C.

---

### ○ [lora-ipv6-mesh-d94] Set up GitHub Actions CI

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:30Z

**Description:**

Create .github/workflows/ with: Rust build/test/clippy/fmt, Zephyr build for all target boards, test vector validation. CI should run on push and PR.

---

### ○ [lora-ipv6-mesh-ajr] Create test vector framework

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:31Z

**Description:**

Set up test/vectors/ with JSON schema for test vectors. Create initial vectors for: link layer frames, SCHC compression. Both Rust and C implementations must validate against these vectors.

---

### ○ [lora-ipv6-mesh-mok] Write draft-lichen-link-01.md

- **Type:** task
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:33Z

**Description:**

IETF-style Internet-Draft for link layer. Cover: frame format, LLSec byte, addressing modes, sequence numbers, Ed25519 truncated signatures. Use RFC 2119 keywords.

---

### ✓ [lora-ipv6-mesh-z0h] Spec: Add SCHC rule versioning

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:12Z
- **Closed:** 2026-05-27T05:52:31Z

**Description:**

SCHC rules are pre-provisioned with no versioning scheme. Problems: (1) no fallback when rules mismatch, (2) firmware updates could silently break interop, (3) no error detection for rule mismatch. Need: rule version field in packets, negotiation/fallback mechanism, or minimum version advertisement in DIO.

**Resolution:**

Added section 5.7: DIO advertises rule version, Rule 255 reserved for uncompressed fallback. spec/03-adaptation.md

---

### ✓ [lora-ipv6-mesh-6yu] Spec: Define group membership protocol

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:15Z
- **Closed:** 2026-05-27T05:59:44Z

**Description:**

Groups extensively documented for messaging/encryption but no join/leave protocol. Missing: membership synchronization, authorization model, key distribution mechanism (currently 'out-of-band'). Need concrete protocol for group CRUD operations and member management.

**Resolution:**

Added section 18.8.2: roles (owner/admin/member), invitations, key distribution via pairwise OSCORE, leave/remove, rekeying on removal. spec/12-apps.md

---

### ✓ [lora-ipv6-mesh-1zq] Spec: Resolve RPL secure mode contradiction

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:17Z
- **Closed:** 2026-05-27T05:49:06Z

**Description:**

Design principle: 'No pre-shared network keys'. Section 8.7: 'Recommended: Preinstalled mode with network-wide key'. These contradict. Either: (1) drop RPL secure mode recommendation, (2) use Authenticated mode with per-node keys, (3) clarify that control plane PSK is acceptable while data plane is per-peer.

**Resolution:**

Resolved: link-layer sigs are baseline, RPL PSK is optional defense-in-depth. Updated spec/06-security.md section 8.9.

---

### ✓ [lora-ipv6-mesh-8nc] Spec: Add congestion control for CoAP

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:18Z
- **Closed:** 2026-05-27T05:57:55Z

**Description:**

No congestion control specified. CoAP CON retries over duty-cycle-limited links can cause: cascading retry storms, EU 868MHz duty cycle violations, network collapse under load. Need: adaptive retry backoff, duty cycle awareness, load shedding policy.

**Resolution:**

Added CoAP params for LoRa (15s ACK_TIMEOUT, 2 retries), duty cycle tracking with congestion levels, 5.03 load shedding, priority queue. spec/07-transport-app.md section 10.1.1-10.1.2

---

### ✓ [lora-ipv6-mesh-syf] Spec: Define short address collision handling

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:20Z
- **Closed:** 2026-05-27T05:50:52Z

**Description:**

Short address assignment says 'Hash lower 16 bits, check for collision' but no collision detection mechanism for lossy mesh. DAD over LoRa is unreliable. Race conditions when multiple nodes join. Need: concrete DAD protocol with timeouts, collision resolution, coordinator-assisted fallback.

**Resolution:**

Added section 4.5: coordinator assigns when present, hash+DAD when isolated, signature mismatch detects collisions. spec/02-physical-link.md

---

### ✓ [lora-ipv6-mesh-4y6] Spec: Harden isolated mesh root election

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:22Z
- **Closed:** 2026-05-27T05:55:54Z

**Description:**

'Lowest EUI-64 wins' is deterministic but exploitable. Attacker can manufacture nodes with low EUI-64. No mechanism to demote misbehaving roots. No re-election on root failure. Consider: randomized election with proof-of-work, reputation system, election timeout, demotion protocol.

**Resolution:**

Added root failure detection (3×Imax timeout), re-election protocol, and demotion voting (>50% threshold). spec/04-network.md

---

### ✓ [lora-ipv6-mesh-67q] Spec: Add store-and-forward limits and back-pressure

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:23Z
- **Closed:** 2026-05-27T05:54:06Z

**Description:**

Store-and-forward has 'implementation-defined' limits — no interop guarantees. Attack: exhaust node storage with messages to offline targets. Need: mandatory minimum/maximum limits, back-pressure signaling (e.g., 5.03 Service Unavailable), memory reservation policy.

**Resolution:**

Added storage limits (8-64 msgs, 1-16KB), FIFO+fairness eviction, 5.03 back-pressure. spec/12-apps.md section 18.1.4

---

## P3 Low

### ○ [lora-ipv6-mesh-b8g] Phase 10: Tooling & Polish

- **Type:** epic
- **Status:** open
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T05:10:01Z
- **Blocked by:** lora-ipv6-mesh-45t

**Description:**

lichen-craft CLI, Wireshark dissector, network simulator, web dashboard. Exit criteria: all tools functional, documentation complete, example applications working.

---

### ✓ [lora-ipv6-mesh-ee7] Spec: Define CoAP block-wise vs SCHC fragmentation interaction

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:26Z
- **Closed:** 2026-05-27T06:02:56Z

**Description:**

Both CoAP block-wise (RFC 7959) and SCHC (RFC 8724) fragment large payloads. Interaction unspecified: which layer fragments first? How do reassembly failures propagate? What's the overhead when both active? Need clear layering rules and failure handling.

**Resolution:**

CoAP block-wise NOT RECOMMENDED. SCHC handles all fragmentation. Large transfers use app-level chunking. spec/07-transport-app.md section 10.3

---

### ✓ [lora-ipv6-mesh-b5f] Spec: Address link-layer metadata exposure

- **Type:** feature
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:27Z
- **Closed:** 2026-05-27T04:56:46Z

**Description:**

Spec acknowledges 'Metadata visible: Link-layer headers unencrypted' but doesn't mitigate. Enables: traffic analysis, node tracking via IID/EUI-64, network topology discovery by passive adversaries. Consider: IID rotation, traffic padding, dummy messages for cover traffic.

**Resolution:**

Not a concern per threat model: auth-only, not concealment. Running in the clear is intentional.

---

### ✓ [lora-ipv6-mesh-v62] Spec: Complete position privacy model

- **Type:** bug
- **Status:** closed
- **Owner:** me@mark.atwood.name
- **Created:** 2026-05-27T04:55:29Z
- **Closed:** 2026-05-27T06:04:10Z

**Description:**

'group' privacy mode says 'query requires auth' but no mechanism defined. Beacons still reveal presence to passive eavesdroppers. Group membership undefined. Need: auth protocol for position queries, beacon encryption option, group membership definition.

**Resolution:**

Added query auth (OSCORE required), group beacon encryption, private mode whitelist, documented presence vs location limitation. spec/12-apps.md section 18.2.4

---
