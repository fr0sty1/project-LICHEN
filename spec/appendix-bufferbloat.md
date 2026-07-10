<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Appendix: Bufferbloat Avoidance in LICHEN

## The Problem

Bufferbloat occurs when network buffers are sized for throughput rather than
latency. Large buffers absorb bursts without dropping packets, but the cost
is queueing delay — packets wait in line while the buffer drains through a
slower link.

In high-speed networks, this manifests as seconds of latency on DSL/cable
links. In LICHEN's LoRa mesh, the problem is more severe:

| LoRa SF | Data Rate | 100-byte Packet | 10-Packet Queue |
|---------|-----------|-----------------|-----------------|
| SF7     | 5.5 kbps  | 150 ms          | 1.5 s           |
| SF10    | 980 bps   | 800 ms          | 8 s             |
| SF12    | 250 bps   | 3.2 s           | 32 s            |

A queue that looks small in bytes represents enormous latency in time.

### LoRa-Specific Factors

**Duty cycle limits**: EU 868 MHz band limits transmissions to 1% duty cycle.
After a 1-second transmission, the node must wait 99 seconds before the next.
Queued packets experience not just transmission time but regulatory wait time.

**Half-duplex radio**: A node cannot transmit while receiving. Channel access
requires carrier sense and backoff, adding variable delay before transmission
even begins.

**Multi-hop mesh**: Each hop adds queuing delay. A 3-hop path through
congested relays can accumulate tens of seconds of latency.

**No TCP**: LICHEN uses UDP/CoAP, not TCP. There is no slow-start or
congestion window to automatically throttle senders. Without explicit
backpressure, senders have no visibility into mesh congestion.

## Design Principles

LICHEN applies Dave Täht's bufferbloat insights to low-power mesh:

### 1. Small, Bounded Queues

Every queue has an explicit, small bound. When full, new packets are rejected
with an error (backpressure) rather than silently queued.

```
TX queue:        4 packets max
Forwarding:      2 packets per source max
BLE GATT:        8 messages max (returns QueueFull)
```

These numbers are small because bytes are cheap but time is expensive.

### 2. Time-Based Expiry

Packets have deadlines. A position report from 30 seconds ago is worthless;
transmitting it wastes airtime and battery. Queued packets older than their
deadline are silently dropped.

```
Routing control:   5 s deadline (RPL DIO/DAO)
ACK/NACK:          10 s deadline
Application data:  configurable, default 60 s
```

### 3. Priority Queuing

Not all packets are equal:

| Priority | Traffic Type              |
|----------|---------------------------|
| 0 (high) | Routing control (DIO/DAO) |
| 1        | Link-layer ACKs           |
| 2        | Urgent app messages       |
| 3 (low)  | Bulk data                 |

Higher-priority packets preempt lower-priority ones. A node struggling to
maintain routes will not waste airtime on stale bulk transfers.

### 4. Explicit Backpressure

When a queue is full, the sender gets an error:
- `ENOBUFS` / `QueueFull` for immediate sends
- Negative acknowledgment for mesh-forwarded packets

Senders must handle this — typically by backing off and retrying later, or
by dropping the packet and notifying the application.

### 5. No Silent Drops

Tail-drop (silently discarding packets when full) hides congestion. LICHEN
prefers explicit signals:
- Return error to local sender
- NACK to mesh source (if routable)
- Log queue-full events for diagnostics

## Implementation Guidelines

### TX Queue

The radio TX queue holds packets waiting for channel access:

```c
#define TX_QUEUE_SIZE 4

struct tx_queue_entry {
    uint8_t data[MAX_PACKET_SIZE];
    uint16_t len;
    uint32_t deadline_ms;
    uint8_t priority;
};

int tx_queue_push(const uint8_t *data, uint16_t len, uint8_t priority) {
    // Check deadline of oldest packet, drop if expired
    // If full and new packet is higher priority, preempt lowest
    // If full and same/lower priority, return -ENOBUFS
}
```

### Forwarding Buffer

Relay nodes buffer packets for forwarding. Per-source limits prevent one
chatty node from monopolizing relay capacity:

```c
#define MAX_FORWARDING_SOURCES 8
#define MAX_PACKETS_PER_SOURCE 2

// If source has MAX_PACKETS_PER_SOURCE queued, send NACK upstream
// Total forwarding buffer: 16 packets max
```

### Measuring Queue Latency

Track time-in-queue, not just queue depth:

```c
struct queue_stats {
    uint32_t packets_queued;
    uint32_t packets_dropped_deadline;
    uint32_t packets_dropped_full;
    uint32_t max_latency_ms;      // Worst-case queue time
    uint32_t avg_latency_ms;      // Smoothed average
};
```

Expose via `/status/queues` CoAP resource for diagnostics.

## Why Not CoDel/CAKE?

CoDel (Controlled Delay) and CAKE (Common Applications Kept Enhanced) are
Dave Täht's solutions for TCP bufferbloat. They work by:
1. Measuring sojourn time (how long packets wait in queue)
2. Dropping packets when sojourn time exceeds a target (~5ms)
3. Using ECN or drop signals to trigger TCP congestion response

LICHEN doesn't use CoDel because:
- **No TCP**: CoDel signals congestion to TCP, which backs off. LICHEN uses
  UDP/CoAP without built-in congestion control.
- **Latency target mismatch**: CoDel targets 5ms sojourn time. LoRa packet
  transmission alone takes 100ms–3s. A 5ms target makes no sense.
- **Different goal**: CoDel optimizes throughput vs latency tradeoff. In
  LoRa, throughput is already minimal; the goal is bounded worst-case delay.

Instead, LICHEN uses simpler mechanisms: small bounds, deadlines, priorities,
and explicit backpressure. These achieve the same goal (controlled latency)
with mechanisms appropriate to low-rate mesh networks.

## Testing

Bufferbloat avoidance must be tested under congestion:

1. **Queue-full handling**: Sender gets `ENOBUFS` when queue full
2. **Deadline expiry**: Old packets dropped before transmission
3. **Priority preemption**: High-priority packets bypass queue
4. **Multi-hop latency**: End-to-end delay bounded under load
5. **Fairness**: No single source monopolizes forwarding capacity

## Further Reading

- [Bufferbloat.net](https://www.bufferbloat.net/) — Dave Täht's project
- [CoDel RFC 8289](https://datatracker.ietf.org/doc/html/rfc8289)
- [CAKE paper](https://arxiv.org/abs/1804.07617)
- Gettys & Nichols, "Bufferbloat: Dark Buffers in the Internet" (2012)

---

[Index](README.md) | [Acknowledgments](99-acknowledgments.md)
