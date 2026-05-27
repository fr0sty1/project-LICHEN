<!-- Part of LICHEN Protocol Specification -->

# Routing

## 7. Routing (RPL)

### 7.1. Overview

RPL (Routing Protocol for Low-Power and Lossy Networks, RFC 6550) builds
a DODAG (Destination-Oriented Directed Acyclic Graph) rooted at a border
router or coordinator.

### 7.2. Topology

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

### 7.3. Control Messages

| Message | ICMPv6 Code | Direction | Purpose |
|---------|-------------|-----------|---------|
| DIO | 0x9B, 0x01 | Downward | DODAG Information Object |
| DIS | 0x9B, 0x00 | Upward | DODAG Information Solicitation |
| DAO | 0x9B, 0x02 | Upward | Destination Advertisement Object |
| DAO-ACK | 0x9B, 0x03 | Downward | DAO acknowledgment |

### 7.4. DIO (DODAG Information Object)

Broadcast by routers to advertise DODAG membership:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   RPLInstanceID   |    Version    |            Rank           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|G|0|MOP|Prf|           DTSN            |     Flags     | Res   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          DODAGID                              +
|                       (128 bits)                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Options                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 7.5. Objective Function

**OF0 (RFC 6552):** Minimize hop count
**MRHOF (RFC 6719):** Minimize ETX (expected transmissions)

Recommended: **MRHOF with ETX** for LoRa, as link quality varies significantly.

### 7.6. Rank Calculation

```
Rank(N) = Rank(Parent) + RankIncrease
RankIncrease = (ETX * MinHopRankIncrease) / 128
```

Default MinHopRankIncrease: 256

### 7.7. Trickle Timer

DIO transmissions follow Trickle algorithm (RFC 6206):

| Parameter | Value | Description |
|-----------|-------|-------------|
| Imin | 2^12 ms (~4 sec) | Minimum interval |
| Imax | 2^20 ms (~17 min) | Maximum interval |
| k | 10 | Redundancy constant |

### 7.8. Downward Routes (Non-Storing Mode)

For point-to-point traffic, root inserts source route via **6LoRH** (RFC 8138):

```
+--------+--------+--------+--------+
| 6LoRH  | Hop 1  | Hop 2  | Hop 3  |
+--------+--------+--------+--------+
   1B      2B       2B       2B
```

Compressed addresses (16-bit short addresses) minimize overhead.

### 7.9. Loop Avoidance

- Rank must strictly increase toward leaves
- Data-path validation via RPL Packet Information (RPI)
- Inconsistency detection triggers local repair

---

[← Previous: Network Layer](04-network.md) | [Index](README.md) | [Next: Security →](06-security.md)
