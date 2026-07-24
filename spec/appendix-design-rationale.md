<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix: Design Rationale and Inspirations

This appendix documents the conceptual thinking behind LICHEN's design,
including inspirations from real tactical radio systems and how hardware
constraints shape protocol choices.

## 1. Inspirations from Tactical MANET Radios

LICHEN's routing algorithms draw from techniques proven in military tactical
radios. These systems solve similar problems--multi-hop mesh networking in
contested RF environments--but with vastly different resource budgets.

### 1.1. ANW2 (Adaptive Networking Wideband Waveform)

The first deployed tactical MANET in US military service, running on AN/PRC-154
Rifleman Radio and AN/PRC-155 Manpack. Key concepts:

- **Mobile ad-hoc networking** with automatic route discovery
- **No central coordination** required for mesh formation
- **Designed for dismounted infantry** in complex terrain

LICHEN borrows: The fundamental assumption that nodes join and leave
unpredictably, and routing must adapt without manual configuration.

### 1.2. L3Harris TSM-X (Tactical Scalable MANET)

Runs on AN/PRC-163, the current production tactical radio. Features:

- **250+ node flat networks** demonstrated
- **Geographic routing** using GPS coordinates
- **Automatic network healing** when nodes drop

LICHEN's GPSR implementation (Section 9.7) directly parallels TSM-X's approach:
nodes advertise coordinates in announce messages, and forwarding decisions use
geographic proximity to destination.

### 1.3. Silvus StreamCaster with MN-MIMO

Commercial MANET radio used by SOF and allied militaries:

- **Multi-node MIMO** where nodes cooperate at the physical layer
- **Congestion-aware path selection** based on link quality and queue depth
- **100+ node networks** demonstrated

LICHEN's backpressure routing (Section 11.4) is a constrained version of this:
nodes advertise queue depth, and senders route around congested paths. Without
the bandwidth for continuous link probing, LICHEN piggybacks congestion metrics
on announce messages.

### 1.4. Persistent Systems MPU5 with Wave Relay

Commercial but heavily used by DoD/SOCOM:

- **320-node flat network** demonstrated
- **Store-and-forward** for intermittent connectivity
- **Opportunistic routing** with coordinated multi-forwarder schemes

LICHEN's DTN store-and-forward (Section 9.8) and opportunistic forwarding
(Section 9.9) parallel Wave Relay's approach. Both handle network partitions
by buffering packets and use coordinated forwarding where multiple nodes hear
a packet but suppress retransmission based on priority ranking.

## 2. The Constraint Gap

These tactical radios solve problems with resources LICHEN doesn't have:

| Resource | Tactical Radio | LICHEN |
|----------|----------------|--------|
| CPU | ARM Cortex-A / x86 @ GHz | ESP32 @ 240 MHz (or less) |
| RAM | Gigabytes | Kilobytes to low megabytes |
| Bandwidth | 1-10+ Mbps | 0.3-5 kbps |
| Power | Vehicle/battery pack | Coin cell to small LiPo |
| Cost | $10,000-$50,000/node | $20-$50/node |

What this means in practice:

**Tactical radios can afford:**
- Full routing tables for every known node
- Aggressive link probing (continuous beacons, SNR measurement)
- Redundant transmissions "just in case"
- Complex cryptographic operations without power concerns
- Retransmit-until-success strategies

**LICHEN cannot afford any of that.** Every byte costs battery. Every
transmission blocks the shared channel. Routing state must fit in kilobytes.
Crypto must be fast enough to not drain a coin cell.

## 3. Constraint-Driven Design

The constraints force cleaner design. Every LICHEN protocol choice traces to a
resource limit:

### 3.1. 48-Byte Schnorr Signatures (Section 6)

Not elegant by choice--necessary because a 256-byte RSA signature won't fit in a
LoRa frame alongside actual payload. Schnorr with a 192-bit curve gives 48
bytes: small enough to include in every packet, secure enough for authentication.

### 3.2. SCHC Instead of 6LoWPAN (Section 3)

6LoWPAN assumes 127-byte IEEE 802.15.4 frames. LoRa frames are smaller and
airtime is precious. SCHC compresses IPv6+UDP headers to 6-15 bytes instead of
6LoWPAN's 20-40 bytes. Every saved byte is real airtime returned.

### 3.3. Announce-Based Routing (Section 5, 9)

Tactical radios probe links actively. LICHEN can't--probing consumes the channel.
Instead, nodes broadcast periodic announces that double as:

- Presence indication (neighbor discovery)
- Routing metric advertisement (hop count, coordinates, congestion)
- Application data carrier (position, DTN pending IIDs)

One packet, multiple purposes. No dedicated control plane.

### 3.4. Opportunistic Forwarding with Timed Suppression (Section 9.9)

Wave Relay can afford to elect forwarders with explicit coordination messages.
LICHEN uses implicit coordination: all candidate forwarders hear the same
packet, each waits a time proportional to their rank (based on distance to
destination), and hearing a better-ranked node forward suppresses transmission.
No coordination overhead--just timing discipline.

### 3.5. Minimal Routing State (Section 5)

TSM-X can keep full routing tables. LICHEN keeps:

- Neighbor table: who's in range (from recent announces)
- Gradient cache: best next-hop toward known destinations
- DTN buffer: small set of store-and-forward packets

Everything else is derived on-demand from overheard traffic. If memory is
exhausted, oldest entries evict. The network degrades gracefully rather than
crashing.

## 4. Design Philosophy

The recurring theme: **tactical radios solve problems with bandwidth; LICHEN
solves them with protocol design.**

When a TSM-X node needs to find a route, it floods discovery packets. When
LICHEN needs a route, it checks the gradient cache built from overheard
announces--zero discovery latency, zero additional transmissions.

When Wave Relay wants reliable delivery, it retransmits aggressively with
link-layer ACKs. LICHEN assumes unreliable delivery and pushes reliability
to applications (CoAP CON messages) where it belongs.

When StreamCaster measures link quality, it sends probe packets. LICHEN infers
link quality from successful packet reception--if you heard the announce, the
link works.

This isn't elegance for its own sake. It's survival. A protocol that wastes
airtime on a LoRa network kills the network. A protocol that exceeds memory
crashes. A protocol that drains batteries makes nodes disappear.

The constraints aren't limitations to work around--they're the design parameters.

## 5. What's Different from Consumer Mesh

Meshtastic and similar consumer protocols prove LoRa mesh works. But they make
different tradeoffs:

| Aspect | Consumer Mesh | LICHEN |
|--------|---------------|--------|
| Addressing | Proprietary node IDs | Real IPv6 |
| Routing | Flooding or simple hop count | GPSR + backpressure + DTN |
| Security | Optional encryption | Mandatory per-packet signatures |
| Interop | Custom app required | Standard CoAP/MQTT-SN |
| Scale | Tens of nodes | Designed for hundreds |

LICHEN isn't "better" in absolute terms--it's designed for different use cases:
autonomous sensor networks, infrastructure-independent communication, and
integration with standard IP tooling. Consumer mesh prioritizes simplicity and
phone compatibility.

## 6. Intentional Simplifications

The implementation deliberately omits advanced features from the tactical radio
playbook. These features add significant complexity to handle edge cases that
rarely occur in practice.

### 6.1. GPSR: Greedy Only, No Perimeter Mode

Full GPSR includes "perimeter mode" (face routing) for escaping local minima--
situations where no neighbor is closer to the destination than the current node.
This requires planarizing the network graph and traversing faces, which means:

- Maintaining planar subgraph state at every node
- Complex right-hand rule traversal logic
- Additional message types for mode switching

**Why omitted:** Local minima are rare in real deployments. When they occur,
LOADng reactive discovery finds a path. The complexity of perimeter mode isn't
justified for an edge case that has a working fallback.

### 6.2. Backpressure: Data Collection Only

Full backpressure routing automatically selects less-congested paths. LICHEN
collects congestion data (queue depths in announces) but doesn't auto-route
around congestion. Applications can use the data if they want.

**Why omitted:** Automatic backpressure routing requires:

- Continuous queue depth updates (more airtime)
- Hysteresis to avoid route flapping
- Complex interaction with other routing tiers

For LoRa's bandwidth, the cure is worse than the disease. If a path is
congested, the network is probably overloaded anyway. Applications that care
can implement their own logic using the exposed queue depth data.

### 6.3. Opportunistic: Ranked Candidates, No Correlation Tracking

Full ExOR-style opportunistic routing tracks which packets each forwarder has
received (via batch maps) to avoid duplicate transmissions. LICHEN uses simpler
ranked-candidate selection with timed suppression.

**Why omitted:** Correlation tracking requires:

- Batch acknowledgment maps in every packet
- Per-forwarder packet reception state
- Complex duplicate suppression logic

The timed suppression approach wastes some airtime on duplicates but requires
no coordination state. At LoRa data rates, the overhead of batch maps would
exceed the savings from perfect duplicate suppression.

### 6.4. The Pattern

Each omission follows the same logic: **the full version handles edge cases
that have simpler fallbacks, at a complexity cost that exceeds the benefit.**

| Feature | Edge Case | Fallback | Complexity Saved |
|---------|-----------|----------|------------------|
| GPSR perimeter | Local minima | LOADng discovery | Graph planarization |
| Auto backpressure | Congested paths | App-layer logic | Route flap hysteresis |
| ExOR correlation | Duplicate packets | Timed suppression | Batch map state |

This is deliberate. A protocol that handles every edge case optimally is a
protocol too complex to implement correctly on a microcontroller. LICHEN
handles common cases well and degrades gracefully on edge cases.

### 6.5. No MAC or Address Randomization

Consumer devices randomize MAC addresses to frustrate passive tracking.
LICHEN does not, and will not. Unlike 6.1-6.3, this is not a complexity
trade-off — the feature is counterproductive here:

- **It breaks the mesh.** Root election, short-address assignment, replay
  windows, and signature caching all key on stable EUI-64 identity.
  Rotating addresses means election instability, constant re-DAD, and
  table churn on a link budget measured in bytes per second.
- **It provides nothing.** Every LICHEN frame is signed by a long-term
  public key. An observer tracks the key, not the address. Randomizing
  the address under a stable signing key is privacy theater.
- **It barely works where it came from.** Wi-Fi MAC randomization
  protects unassociated probe requests only; the moment a station
  associates, its MAC is stable for the session and the AP tracks it
  regardless. LICHEN nodes are permanently "associated" to the mesh, so
  even the narrow Wi-Fi benefit has no analog.

Privacy effort goes where it can actually work: position privacy (omit
coords from announces, Section 5; `/config/privacy` access control,
Section 12 Apps) and payload confidentiality via OSCORE (Section 6).
See Security Considerations 15.5 for the normative statement.

## 7. Physical Layer Parameter Choices

The LoRa PHY parameters are chosen as a middle-ground compromise:

### 7.1. Spreading Factor: SF10

| SF | Sensitivity | Airtime (50B) | Range | Use Case |
|----|-------------|---------------|-------|----------|
| SF7 | -123 dBm | ~30ms | Short | High-density urban |
| SF10 | -132 dBm | ~250ms | Medium | General purpose |
| SF12 | -137 dBm | ~1s | Long | Rural/wilderness |

**Why SF10:**

- **Not SF7-8:** LICHEN targets mesh networking over distance, not adjacent-room
  communication. Urban deployments need wall penetration. SF10 provides ~9dB
  more link budget than SF7--the difference between "works indoors" and "doesn't."

- **Not SF11-12:** Airtime matters for battery and duty cycle. SF10→SF12 doubles
  airtime for only ~5dB more range--diminishing returns. A node sending 100
  packets/day at SF10 uses half the airtime of SF12, extending battery life
  proportionally.

- **SF10 is the middle:** Good range for multi-hop mesh without excessive airtime.
  Most links that fail at SF10 would need a relay node anyway.

### 7.2. Bandwidth: 125 kHz

| BW | Data Rate | Sensitivity | Crystal Tolerance |
|----|-----------|-------------|-------------------|
| 62.5 kHz | Slowest | Best | Tight |
| 125 kHz | Medium | Good | Relaxed |
| 250 kHz | Fast | Worse | Relaxed |
| 500 kHz | Fastest | Worst | Relaxed |

**Why 125 kHz:**

- **More robust than 250 kHz:** ~3dB better sensitivity. In marginal conditions,
  this is the difference between packet reception and loss.

- **Tolerates cheaper crystals:** Wider bandwidth means less sensitivity to
  frequency offset from temperature drift or cheap oscillators. Enables use of
  low-cost modules.

- **Not 62.5 kHz:** Requires tighter frequency accuracy than cheap modules provide.
  The sensitivity gain doesn't justify the hardware cost increase.

### 7.3. Coding Rate: CR 4/5

| CR | Overhead | Error Correction |
|----|----------|------------------|
| 4/5 | 25% | Minimal |
| 4/6 | 50% | Low |
| 4/7 | 75% | Medium |
| 4/8 | 100% | High |

**Why 4/5:**

- **Minimal overhead:** LoRa's chirp modulation already provides good noise
  immunity. FEC provides diminishing returns on top of that.

- **Airtime matters:** Higher CR means longer packets. The extra robustness
  rarely saves packets that wouldn't have been saved by retransmission.

- **ADR can adjust:** If a specific link needs more robustness, ADR can increase
  CR for that link. Default to minimal overhead.

### 7.4. Sync Word: 0x34

| Sync Word | Used By |
|-----------|---------|
| 0x12 | LoRaWAN private networks |
| 0x34 | LoRaWAN public networks / LICHEN |
| 0x2B | Meshtastic |

**Why 0x34:**

- **Not 0x2B (Meshtastic):** In areas with Meshtastic traffic, LICHEN nodes
  would receive every Meshtastic packet, wasting CPU and battery filtering them.
  The sync word check happens in radio hardware--different sync word means zero
  processing cost for foreign packets.

- **Using 0x34 (LoRaWAN public):** Chosen arbitrarily from unused space. Could
  be any value except 0x12 and 0x2B. LoRaWAN public networks are rare; collision
  risk is low.

- **Alternative:** A LICHEN-specific sync word (e.g., 0x4C for 'L') would provide
  complete isolation. 0x34 was chosen for historical reasons and works fine.

### 7.5. Comparison with Meshtastic

| Parameter | LICHEN | Meshtastic "Long Fast" |
|-----------|--------|------------------------|
| SF | 10 | 11 |
| BW | 125 kHz | 250 kHz |
| CR | 4/5 | 4/5 |
| Sync | 0x34 | 0x2B |
| Data Rate | ~980 bps | ~6.8 kbps |

Different design goals:

- **Meshtastic optimizes for throughput:** Higher BW, slightly higher SF for range
- **LICHEN optimizes for link budget:** Lower BW for sensitivity, lower SF for
  airtime efficiency

The PHY parameters are incompatible--LICHEN and Meshtastic devices cannot hear
each other even on the same frequency. This is intentional; mixing protocols
on shared PHY would create interference without interoperability.

### 7.6. CCP-16: Load Balancing (TDMA + Adaptive SF + Multi-Channel + Density-Aware)

Single channel creates contention hotspot. CCP-16 coordinates capacity. All impls (Python sim/schc, Rust rpl/gateway, Zephyr lichen/subsys/lichen) MUST match test/vectors/ccp16.json exactly.

**TDMA Slots (Zephyr scheduler, Rust sim)**
- Root includes epoch and `num_slots` (default 8) in extended RPL config option (see draft-lichen-rpl-lora).
- Slot ID = hash_32(eui64 XOR epoch) % num_slots using lichen_hash_32 FNV-1a32 (consistent per CCP-15.8.3 and project-LICHEN-eirg; matches Rust lichen-core::lichen_hash_32, Python _hash_32, C impl). samples/lora_ping::packet_hash uses crc32_ieee for telemetry only. Cross-ref spec/02a-coordinated-capacity.md.
- Slot duration = max_airtime(current_SF) + 100ms guard. Node uses lichen_link_set_slot() in subsys.
- TX suppressed outside slot (tdma_tx_allowed()).

Normative pseudocode and thresholds are now in 02a-coordinated-capacity:2a.7 (with pure IETF-style definitions for adaptive_sf_select, select_channel, now(); EMA alpha=1/4, per-neighbor state, DIO signaling). SF10 is the REQUIRED baseline for moderate density per section 7.1; density-aware overrides and CH0 fallback apply only on explicit thresholds (density >8 triggers specific SF and control channel rules). Implementations MUST match test/vectors/ccp16.json and ccp_load_balancing.json exactly. No dead code; all paths exercised by vectors.

**Fixed-Point no_std Example (Q16.16 for EMA):** For embedded `no_std` (Zephyr C/Rust lichen-core), avoid f32. Use saturating Q16.16 arithmetic matching rf_health.rs:170,251:

```rust
const EMA_ALPHA_SHIFT: u32 = 2;  // alpha = 1/4
const FP_SCALE: u32 = 1 << 16;

fn ema_update_fp(avg_fp: i32, sample_fp: i32) -> i32 {
    let diff = sample_fp.saturating_sub(avg_fp);
    avg_fp.saturating_add(diff >> EMA_ALPHA_SHIFT)
}

// Usage (SNR scaled <<16):
let snr_fp = (snr as i32) << 16;
nbr.ema_snr_fp = ema_update_fp(nbr.ema_snr_fp, snr_fp);
let snr_ema = (nbr.ema_snr_fp + (1<<15)) >> 16;  // round to int
```

This produces identical results to the floating-point pseudocode for the test vectors while fitting constrained MCUs. See lichen-core/src/rf_health.rs:13-20 for full impl (saturating ops, constants matching DENSITY_* and SNR_* thresholds).

**Multi-Channel + Density Balancing**
- CH0 always for control (DIOs, all listen). Data channels via hash or root-assigned (RPL DAO-ACK carries channel_map).
- Nodes report neighbor_count (u8), channel_util (percent*2.55) in DIO option.
- Root (Rust gateway/rpl) runs central optimizer: minimize collisions using density map.
- Python sim/schc: models multi-channel propagation, TDMA collisions, validates <5% loss at 50 nodes/km2.
- Renode/west tests for Zephyr node behavior. Cargo tests for Rust rpl logic. Pytest for sim interop.

**Kconfig**
- CONFIG_LICHEN_CCP16=y
- CONFIG_LICHEN_TDMA_SLOTS=8
- CONFIG_LICHEN_ADAPTIVE_SF=y

**Interop & Tests**
- All platforms load test/vectors/ccp16.json.
- pytest in python/tests/sim/test_ccp16.py
- cargo test in rust/rpl, rust/gateway
- west build -b native_sim && west build -t run for Zephyr
- Renode scenarios for multi-node density test.
- No dead code; all paths exercised by vectors.

Integrates with existing SCHC (add channel to rule ID), RPL (new option type), link layer (new ctx fields). Auth via existing Schnorr/Ed25519. PHY spec now complete.

## 8. Summary

LICHEN applies concepts proven in tactical MANETs to the constrained world of
LoRa:

- **Geographic routing** (from TSM-X) adapted to announce-based coordinate
  distribution
- **Congestion-aware forwarding** (from StreamCaster) adapted to piggyback
  metrics
- **Store-and-forward** (from Wave Relay) adapted to kilobyte buffers
- **Opportunistic coordination** (from Wave Relay) adapted to implicit timing

The difference is resource budget. Tactical radios have compute, memory, and
bandwidth to spare. LICHEN has none of that luxury--so the protocol must be
correspondingly smarter about what it spends.

### Frequency Agility Channel Selection

**Rejected alternative (pure random):** Pure random channel selection was considered but rejected because it prevents reliable rendezvous prediction between nodes (receiver cannot compute which channel the sender will use). Hash_32(SFN, EUI) provides deterministic, reproducible selection that enables synchronized hopping and rendezvous announcements while still providing statistical interference avoidance. See CCP-12 and CCP-15 pseudocode in 02a-coordinated-capacity.md.

**now() and clamp():** Defined in 02a-coordinated-capacity:2a.3.1 as monotonic unsigned 32-bit SFN counter (with modular arithmetic for wraparound) and numeric limiter respectively. Density vs SF10 baseline updated per pure pseudocode; thresholds fixed for interoperability (normative).

---
[Index](README.md) | [Architecture](01-architecture.md)

