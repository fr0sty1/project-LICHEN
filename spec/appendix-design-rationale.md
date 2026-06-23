<!-- Part of LICHEN Protocol Specification -->

# Appendix: Design Rationale and Inspirations

This appendix documents the conceptual thinking behind LICHEN's design,
including inspirations from real tactical radio systems and how hardware
constraints shape protocol choices.

## 1. Inspirations from Tactical MANET Radios

LICHEN's routing algorithms draw from techniques proven in military tactical
radios. These systems solve similar problems—multi-hop mesh networking in
contested RF environments—but with vastly different resource budgets.

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

Not elegant by choice—necessary because a 256-byte RSA signature won't fit in a
LoRa frame alongside actual payload. Schnorr with a 192-bit curve gives 48
bytes: small enough to include in every packet, secure enough for authentication.

### 3.2. SCHC Instead of 6LoWPAN (Section 3)

6LoWPAN assumes 127-byte IEEE 802.15.4 frames. LoRa frames are smaller and
airtime is precious. SCHC compresses IPv6+UDP headers to 6-15 bytes instead of
6LoWPAN's 20-40 bytes. Every saved byte is real airtime returned.

### 3.3. Announce-Based Routing (Section 5, 9)

Tactical radios probe links actively. LICHEN can't—probing consumes the channel.
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
No coordination overhead—just timing discipline.

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
announces—zero discovery latency, zero additional transmissions.

When Wave Relay wants reliable delivery, it retransmits aggressively with
link-layer ACKs. LICHEN assumes unreliable delivery and pushes reliability
to applications (CoAP CON messages) where it belongs.

When StreamCaster measures link quality, it sends probe packets. LICHEN infers
link quality from successful packet reception—if you heard the announce, the
link works.

This isn't elegance for its own sake. It's survival. A protocol that wastes
airtime on a LoRa network kills the network. A protocol that exceeds memory
crashes. A protocol that drains batteries makes nodes disappear.

The constraints aren't limitations to work around—they're the design parameters.

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

LICHEN isn't "better" in absolute terms—it's designed for different use cases:
autonomous sensor networks, infrastructure-independent communication, and
integration with standard IP tooling. Consumer mesh prioritizes simplicity and
phone compatibility.

## 6. Intentional Simplifications

The implementation deliberately omits advanced features from the tactical radio
playbook. These features add significant complexity to handle edge cases that
rarely occur in practice.

### 6.1. GPSR: Greedy Only, No Perimeter Mode

Full GPSR includes "perimeter mode" (face routing) for escaping local minima—
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

## 7. Summary

LICHEN applies concepts proven in tactical MANETs to the constrained world of
LoRa:

- **Geographic routing** (from TSM-X) adapted to announce-based coordinate
  distribution
- **Congestion-aware forwarding** (from StreamCaster) adapted to piggyback
  metrics
- **Store-and-forward** (from Wave Relay) adapted to kilobyte buffers
- **Opportunistic coordination** (from Wave Relay) adapted to implicit timing

The difference is resource budget. Tactical radios have compute, memory, and
bandwidth to spare. LICHEN has none of that luxury—so the protocol must be
correspondingly smarter about what it spends.

---

[Index](README.md) | [Architecture](01-architecture.md)
