<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Routing

## 7. Routing Overview

### 7.1. Three-Tier Architecture

LICHEN uses a three-tier routing architecture optimized for different traffic patterns:

| Tier | Protocol | Traffic Type | Mechanism |
|------|----------|--------------|-----------|
| 1 | **RPL** | Border router ↔ mesh | Proactive DODAG tree |
| 2 | **Announce** | Peer-to-peer (active nodes) | Proactive gradient |
| 3 | **LOADng** | Peer-to-peer (fallback) | Reactive discovery |

**Rationale:**

- **RPL** excels at tree-shaped traffic (sensor → gateway → cloud). Most IoT traffic fits this pattern.

- **Announce routing** provides instant peer-to-peer paths for active mesh participants. Nodes that announce are immediately reachable via gradient following. No discovery latency.

- **LOADng** handles edge cases: new nodes, nodes that missed announces, or rarely-contacted destinations. Reactive discovery when gradient doesn't exist.

### 7.2. Routing Decision

```
def route_packet(dst):
    if is_off_mesh(dst):
        # External destination (GUA not in mesh, or unknown)
        return forward_to_rpl_parent()

    gradient = gradient_table.lookup(dst)
    if gradient and not gradient.expired:
        # Known peer - follow gradient
        return forward_to(gradient.next_hop)

    else:
        # Unknown peer - reactive discovery
        loadng_discover(dst)
        return queue_pending(dst, packet)
```

**Address classification:**

| Address Type | Classification | Routing |
|--------------|----------------|---------|
| Link-local (fe80::/10) | Direct neighbor | Send to neighbor |
| ULA (fd00::/8) in mesh prefix | Mesh peer (Ed25519 per 06-security) | Gradient or LOADng |
| GUA in mesh prefix | Mesh peer | Gradient or LOADng |
| Other GUA | Off-mesh | RPL to border router |
| Unknown | Off-mesh | RPL to border router |

### 7.3. Conformance Requirements

Keywords per RFC 2119. Device classes:

| Class | Example | RAM | Description |
|-------|---------|-----|-------------|
| **Constrained** | STM32WL | ≤64 KB | Battery-powered sensors/actuators |
| **Router** | ESP32, RPi | ≥256 KB | Powered relay nodes |
| **Border Router** | RPi, server | ≥1 MB | Internet gateway |

**Core Protocol (All Devices):**

| Feature | Constrained | Router | BR |
|---------|-------------|--------|-----|
| RPL join (DIO/DIS/DAO) | MUST | MUST | MUST |
| Announce send | MUST | MUST | MUST |
| Announce receive + gradient install | MUST | MUST | MUST |
| Announce relay | SHOULD | MUST | MUST |
| LOADng originate (RREQ/RREP) | MUST | MUST | MUST |
| LOADng relay | SHOULD | MUST | MUST |
| Gradient table (§11) | MUST | MUST | MUST |

**Extended Features (Routers Only):**

| Feature | Constrained | Router | BR |
|---------|-------------|--------|-----|
| Geographic coords in announce (§9.7) | MAY | MAY | MAY |
| GPSR fallback (§9.7) | -- | MAY | MAY |
| Backpressure tracking (§11.4) | -- | MAY | SHOULD |
| Store-and-forward / DTN (§9.8) | -- | MAY | SHOULD |
| Opportunistic forwarding (§9.9) | -- | MAY | MAY |

**Notes:**

- "--" means feature not applicable (insufficient resources).
- Constrained nodes MAY set DTN S-flag but do not buffer.
- Constrained nodes use unicast forwarding only (no opportunistic).
- All MAY features are independently optional; implement any subset.

---

## 8. RPL (Border Router Traffic)

### 8.1. Purpose

RPL (RFC 6550) handles traffic to and from border routers:
- **Upward:** Mesh nodes → Border router → Internet
- **Downward:** Internet → Border router → Mesh nodes (source routed)

RPL is NOT used for peer-to-peer mesh traffic (see Sections 9-10).

### 8.2. DODAG Topology

```
                    [Border Router]
                    (DODAG Root)
                         |
              +----------+----------+
              |                     |
          [Router 1]            [Router 2]
              |                     |
        +-----+-----+         +-----+-----+
        |           |         |           |
    [Node A]    [Node B]  [Node C]    [Node D]
```

### 8.3. Configuration

| Parameter | Value |
|-----------|-------|
| Mode | Non-storing (MOP=1) |
| Objective Function | MRHOF with ETX |
| Trickle Imin | 4 sec |
| Trickle Imax | 17 min |

See Appendix B for full RPL configuration.

### 8.4. Control Messages

| Message | Purpose |
|---------|---------|
| DIO | DODAG advertisement (downward flood) |
| DIS | Solicit DIO (join request) |
| DAO | Route advertisement to root |
| DAO-ACK | Confirm DAO receipt |

### 8.5. Downward Routing

Non-storing mode: root inserts Source Routing Header (6LoRH) for downward packets.

---

## 9. Announce Routing (Peer-to-Peer Primary)

### 9.1. Purpose

Announce routing provides zero-latency peer-to-peer paths for active mesh participants. Nodes periodically broadcast signed announcements; other nodes build gradients toward announcers.

**Key insight:** Most peer-to-peer traffic is between nodes that are actively participating in the mesh. These nodes announce regularly. No discovery needed.

### 9.2. Announce Message

Nodes broadcast announces periodically inside the L2 routing/control namespace.
The authenticated link payload is `0x15 || announce`, where `0x15` is the L2
routing/control dispatch byte and the announce bytes begin with Type `0x01`.
Receivers MUST NOT treat an unwrapped link payload beginning with `0x01` as an
announce because SCHC global CoAP also uses rule ID `0x01`.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0x15 (L2) | Type=0x01 | rx_channel (0-7) | Hop Cnt | Seq Num (BE) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator IID (8 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Public Key (32 bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Optional: App Data (variable)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fixed announce payload: 93 bytes (type through signature end). rx_channel reuses
the former Flags byte (per CCP-9 for da2q rendezvous). Signature covers
IID || pubkey || seq || rx_channel || app_data (prevents tampering with
rendezvous channel).

**Fields:**
- **Type:** 0x01 = announce
- **rx_channel:** 0-7 (control/data channel for next RX; signed); old Flags position
- **Hop Count:** Incremented at each relay (max 15)
- **Seq Num:** Monotonic u16 BE, detects duplicates/freshness
- **Originator IID:** 8-byte Interface Identifier of announcer
- **Public Key:** Ed25519 public key (32 bytes)
- **Signature:** Schnorr48 (48 bytes) over signed_data (see CCP-9)
- **App Data:** Optional (coords, name, capabilities, congestion metrics)

### 9.3. Announce Processing

**On receive announce:**

```
def process_announce(announce, from_neighbor):
    # Verify signature
    if not verify_schnorr(announce.pubkey, announce.signature, announce.signed_data):
        drop("invalid signature")
        return

    # Check for duplicate/old
    existing = gradient_table.get(announce.originator)
    if existing and existing.seq_num >= announce.seq_num:
        drop("stale announce")
        return

    # Install/update gradient
    gradient_table.update(
        destination=announce.originator,
        next_hop=from_neighbor,
        hop_count=announce.hop_count,
        seq_num=announce.seq_num,
        source="announce",
        expires=now() + GRADIENT_TIMEOUT
    )

    # Forward if hop count allows
    if announce.hop_count < MAX_ANNOUNCE_HOPS:
        announce.hop_count += 1
        broadcast(announce)
```

### 9.4. Announce Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| ANNOUNCE_INTERVAL | 300 sec | Time between announces |
| MAX_ANNOUNCE_HOPS | 15 | Maximum propagation |
| GRADIENT_TIMEOUT | 600 sec | 2× announce interval |
| ANNOUNCE_JITTER | 0-30 sec | Random delay to prevent collision |

### 9.5. Bandwidth Budget

For a 20-node mesh:
- 20 nodes × 92 bytes × 12 announces/hr = 22 KB/hr
- At SF10/125kHz: ~15 seconds airtime/hr network-wide
- ~0.04% of 1% duty cycle

Acceptable overhead for instant peer-to-peer routing.

### 9.6. Security

Announces are self-authenticating:
1. Signature proves sender holds private key for pubkey
2. TOFU binding associates pubkey with IID
3. Cannot forge announce for another node's address

First announce from a new node establishes TOFU binding.

### 9.7. Geographic Fallback (GPSR)

When gradient is missing and LOADng times out, nodes with GPS can fall back to geographic routing.

**Coordinates in App Data:**

```
App Data (coords present):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x01 |             LatE7 (4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         LonE7 (4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type 0x01:** Geographic coordinates present
- **LatE7/LonE7:** Signed 32-bit fixed-point, 1e-7 degree resolution
  - Range: latitude MUST be within ±90°, longitude MUST be within ±180°
  - Encoding: `(degrees * 10000000)` as a signed 32-bit integer in network byte order
  - Rationale: e7 coordinates cover the full geographic range and match the
    firmware/HAL and Meshtastic position representation.

**GradientEntry Extension:**

Nodes store coords from announces:
```
coords: (lat, lon) | None  # from app_data if present
```

The coordinates are peer-owned routing metadata. A receiver MUST NOT treat
coordinates from another node's announce as the receiver's own physical
location by default. Border routers and gateways MAY expose a derived
`NETWORK` location only when an explicit local policy enables approximate
mesh-derived location fallback. Such a derived location MUST preserve
provenance (`source_class=NETWORK`, source name such as `mesh-announce`), MUST
be withdrawn or marked stale when the underlying announce expires, and MUST NOT
upgrade the peer's fix source to local GNSS, manual/static, or local-client
location. It MUST NOT outrank a fresh local position provider such as onboard
GNSS, external GNSS, manual/static configuration, or a local-client position.
The derived location is an approximation useful for diagnostics and coarse mesh
context, not a privacy-neutral replacement for this node's own position
provider.

Type `0x01` coordinate app data carries no Unix fix timestamp. Firmware
build/provision epoch floors apply only if another network source submits a
wall-clock or fix timestamp to the shared time provider; they do not make
coordinate-only announce metadata fresh or trustworthy by themselves.

**GPSR Forwarding:**

```
def gpsr_forward(dst_coords, packet):
    # Find neighbor closest to destination
    best = None
    best_dist = my_distance_to(dst_coords)  # greedy progress required

    for neighbor in neighbor_table:
        if neighbor.coords is None:
            continue
        d = distance(neighbor.coords, dst_coords)
        if d < best_dist:
            best_dist = d
            best = neighbor

    if best:
        forward_to(best)
    else:
        # Local minimum - perimeter mode or drop
        drop("gpsr: no progress")  # ponytail: perimeter mode if needed later
```

**When GPSR is attempted:**
1. No gradient for destination
2. LOADng RREQ timed out (RREQ_RETRIES exhausted)
3. Destination coords known (from previous announce or out-of-band)
4. At least one neighbor has coords

**Privacy:**

Coords reveal physical location. Nodes MAY omit coords from announces if privacy is required. GPSR fallback unavailable for such nodes.

Relays and border routers that store announce coordinates MUST apply the same
freshness and provenance rules when presenting them outside the routing table.
Publishing another peer's coordinates as local status without explicit
approximate-location policy is forbidden, even when the announce signature and
TOFU binding are valid.

### 9.8. Store-and-Forward (DTN)

Border routers MAY buffer messages for unreachable destinations, delivering when a path appears.

**When used:**
- Destination has no gradient and LOADng fails
- Message has store-and-forward flag set
- Router has buffer space

**Message Header Extension:**

```
DTN Flags (1 byte in IPv6 hop-by-hop options):
+-+-+-+-+-+-+-+-+
|S|   Reserved  |
+-+-+-+-+-+-+-+-+
S = Store-and-forward requested
```

**Absolute TTL:**

Store-and-forward messages carry absolute expiry (Unix timestamp, 4 bytes)
instead of hop limit. Expired messages are dropped silently. Expiry
comparison requires valid wall-clock time from the firmware time provider
(see `docs/firmware-time-provider.md`). Nodes without valid wall-clock time
MUST NOT drop messages based on expiry timestamp alone; they SHOULD forward
or store messages and let downstream nodes with valid time enforce expiry.

```
App Data (DTN expiry):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x03 | Expiry (4 bytes, UTC)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Storage Policy:**

| Parameter | Value |
|-----------|-------|
| Max buffer | 64 KB per router |
| Eviction | Oldest-first when full |
| Default TTL | 24 hours |
| Max TTL | 7 days |

**Handoff via Announce:**

Routers with buffered messages advertise pending destinations:

```
App Data (pending destinations):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x04 | Count | IID₁ (8B) | IID₂ (8B) ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

When a node sees its IID in a pending list, it sends a pull request to retrieve buffered messages.

**Scope:**

Border routers and powered routers only. Constrained nodes set the S flag but do not buffer--they forward or drop.

<!-- ponytail: spray-and-wait if single-copy delivery too slow -->

### 9.9. Opportunistic Forwarding (Optional)

Routers MAY use coordinated broadcast forwarding to exploit LoRa's broadcast nature in lossy conditions.

**Concept:**

Instead of unicast to one next-hop, broadcast once. Multiple receivers hear it; the best one forwards, others suppress.

**Forwarder List:**

Sender includes ranked forwarder candidates (by hop count to destination):

```
Opportunistic Header (after IPv6 header):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=OPP | Count | IID₁ (8B) | IID₂ (8B) | ...     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Count:** Number of candidate forwarders (1-4)
- **IIDₙ:** Candidates ranked best-first (lowest hop count to destination)

**Timed Suppression:**

Each candidate waits before forwarding:

```
def opportunistic_forward(packet, my_rank):
    wait_time = my_rank * SLOT_TIME  # rank 0 = immediate
    wait(wait_time)

    if heard_forward_from_better_rank:
        suppress()  # higher-priority node handled it
    else:
        forward(packet)
```

| Parameter | Value |
|-----------|-------|
| SLOT_TIME | 100 ms |
| MAX_CANDIDATES | 4 |

**When Used:**

Sender chooses opportunistic mode when:
- Multiple neighbors have gradient to destination
- Link quality is poor (high packet loss observed)

**Scope:**

Routers only. Constrained nodes use standard unicast forwarding--timing coordination adds code complexity.

<!-- ponytail: no ACK-based batch, add if throughput matters -->

---

## 10. LOADng (Peer-to-Peer Fallback)

### 10.1. Purpose

LOADng provides reactive route discovery when no gradient exists:
- New nodes not yet heard announcing
- Nodes that stopped announcing (sleeping, failed)
- First contact before any announce received

### 10.2. When LOADng is Used

```
if gradient_table.lookup(dst) returns None or expired:
    initiate LOADng discovery
```

### 10.3. Route Request (RREQ)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREQ | Flags     | Hop Limit   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREQ is flooded. Each node:
1. If I am destination → send RREP
2. If I have gradient to destination → send RREP (intermediate reply)
3. If seen before (originator + seq) → drop
4. Otherwise → record reverse gradient, decrement hop limit, rebroadcast

### 10.4. Route Reply (RREP)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREP | Flags     | Hop Count   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREP follows reverse path. Each hop installs forward gradient.

### 10.5. Gradient Unification

RREP installs the same gradient entry as announces:

```
gradient_table.update(
    destination=rrep.destination,
    next_hop=from_neighbor,
    hop_count=rrep.hop_count,
    source="rrep",  # different source, same table
    expires=now() + GRADIENT_TIMEOUT
)
```

Once discovered, the destination is in gradient table. Future traffic uses gradient, not LOADng.

### 10.6. Route Error (RERR)

When link fails, send RERR toward affected sources. Recipients invalidate gradient entries through broken link.

### 10.7. Parameters

| Parameter | Value |
|-----------|-------|
| RREQ_WAIT_TIME | 5 sec |
| RREQ_RETRIES | 3 |
| INITIAL_HOP_LIMIT | 4 (expanding ring) |
| MAX_HOP_LIMIT | 15 |

See Appendix B2 for full LOADng configuration.

---

## 11. Gradient Table

### 11.1. Unified Structure

All routing methods populate a single gradient table:

```
GradientEntry:
    destination: IID or IPv6Address
    next_hop: link-local address of neighbor
    hop_count: distance in hops
    seq_num: for freshness comparison
    source: "announce" | "rrep" | "data" | "rpl"
    expires: timestamp
    coords: (lat, lon) | None  # from announce app_data (§9.7)
```

### 11.2. Passive Learning

Forwarding nodes can learn gradients from data traffic:

```
on_forward_packet(packet, from_neighbor):
    # I just received a packet FROM this source
    # Therefore, to REACH this source, send to from_neighbor
    gradient_table.update(
        destination=packet.source,
        next_hop=from_neighbor,
        source="data",
        expires=now() + DATA_GRADIENT_TIMEOUT
    )
```

DATA_GRADIENT_TIMEOUT is shorter (60 sec) since it's opportunistic.

### 11.3. Entry Priority

When multiple sources provide gradient for same destination:

| Source | Priority | Rationale |
|--------|----------|-----------|
| announce | High | Explicitly advertised, fresh |
| rrep | High | Explicitly discovered |
| data | Low | Opportunistic, may be stale |

Higher priority entry replaces lower. Same priority: prefer lower hop count, then lower congestion (§11.4).

### 11.4. Backpressure (Optional)

Routers MAY track neighbor congestion to spread load across alternate paths.

**Neighbor Queue Depth:**

```
NeighborEntry (extended):
    queue_depth: uint8  # packets queued toward this neighbor
```

Incremented when packet enqueued, decremented on TX complete or drop.

**Congestion in Announces:**

Routers MAY include queue depth in app_data:

```
App Data (congestion):
+-+-+-+-+-+-+-+-+
| Type=0x02 | Q |
+-+-+-+-+-+-+-+-+
```

- **Type 0x02:** Congestion indicator
- **Q:** Current outbound queue depth (0-255)

**Path Selection:**

When multiple next-hops have equal hop count:

```
def select_next_hop(candidates):
    # Prefer least-congested path. See Section 2a.2 of draft-lichen-tdma
    # for TDMA channel selection + now() SFN wrap semantics (unsigned modular arithmetic).
    return min(candidates, key=lambda n: n.queue_depth)
```

**Scope:**

Border routers and powered routers only. Constrained nodes (≤64KB RAM) skip backpressure tracking--the memory cost exceeds the benefit at low traffic volumes.

<!-- ponytail: no per-flow fairness, add if starvation observed -->

---

## 12. Summary

```
                         ┌─────────────────┐
                         │  Border Router  │
                         │   (Internet)    │
                         └────────┬────────┘
                                  │
                            RPL (DODAG)
                          upward/downward
                                  │
┌─────────────────────────────────┴─────────────────────────────────┐
│                                                                    │
│    Node A ◄──────── Gradient ────────► Node B                     │
│       │            (from announces)        │                       │
│       │                                    │                       │
│    Node C ◄─── LOADng (if no gradient) ──► Node D                 │
│                                                                    │
│                      Mesh Interior                                 │
└────────────────────────────────────────────────────────────────────┘
```

| Traffic | Primary | Fallback |
|---------|---------|----------|
| To/from internet | RPL | -- |
| Peer (active node) | Announce gradient | LOADng |
| Peer (unknown node) | LOADng | RPL via root (inefficient) |
| Broadcast | Hop-limited flood | -- |

The three-tier approach optimizes for each traffic pattern while providing fallbacks for edge cases.

---

[← Previous: Network Layer](04-network.md) | [Index](README.md) | [Next: Security →](06-security.md)
