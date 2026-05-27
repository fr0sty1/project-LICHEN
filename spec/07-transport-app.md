<!-- Part of LICHEN Protocol Specification -->

# Transport and Application Layers

## 9. Transport Layer

### 9.1. UDP

Standard UDP (RFC 768), compressed via SCHC.

**Ports:**
| Port | Protocol |
|------|----------|
| 5683 | CoAP (unencrypted) |
| 5684 | CoAPS (DTLS) |
| 10883 | MQTT-SN |

### 9.2. No TCP

TCP is NOT recommended for LoRa mesh due to:
- High overhead (20-byte header minimum)
- Poor performance over lossy links
- Congestion control incompatible with duty cycles

Use CoAP (with Observe) or MQTT-SN for reliable messaging.

---

## 10. Application Layer

### 10.1. CoAP (RFC 7252)

Constrained Application Protocol - REST-like for constrained devices.

**Message Format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver| T |  TKL  |      Code     |          Message ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Token (if any, TKL bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Methods:**
| Code | Method |
|------|--------|
| 0.01 | GET |
| 0.02 | POST |
| 0.03 | PUT |
| 0.04 | DELETE |

#### 10.1.1. CoAP Parameters for LoRa

RFC 7252 defaults are tuned for low-latency networks. LoRa mesh requires
adjusted parameters to avoid retry storms and duty cycle violations.

**Transmission Parameters:**

| Parameter | RFC 7252 Default | LICHEN Value | Rationale |
|-----------|------------------|--------------|-----------|
| ACK_TIMEOUT | 2 s | 15 s | Multi-hop RTT can exceed 10s |
| ACK_RANDOM_FACTOR | 1.5 | 2.0 | More jitter reduces collision |
| MAX_RETRANSMIT | 4 | 2 | Fewer retries, fail faster |
| NSTART | 1 | 1 | Keep 1 outstanding CON |
| LEISURE | 5 s | 15 s | Multicast response spread |
| PROBING_RATE | 1 B/s | 0.1 B/s | Respect duty cycle |

With LICHEN values: retries at 15-30s, 30-60s, give up at ~90s.

**Prefer NON Messages:**

For most telemetry and notifications, use NON (non-confirmable):
- No retry overhead
- Application handles reliability if needed (e.g., delivery receipts)
- Suitable for periodic sensor readings, position beacons

Use CON only when delivery confirmation is critical:
- Configuration changes
- Firmware update blocks
- SOS acknowledgments

#### 10.1.2. Duty Cycle Awareness

Nodes MUST track duty cycle usage and throttle transmissions accordingly.

**Duty Cycle Tracking:**

```
Per-channel state:
  last_tx_end: <timestamp>
  tx_time_window: <rolling 1-hour sum of airtime>
  duty_limit: <region-specific, e.g., 0.01 for EU 868 sub-band>
```

**Congestion Levels:**

| Level | Duty Used | Action |
|-------|-----------|--------|
| Normal | <50% of limit | Transmit normally |
| Elevated | 50-80% | Delay non-urgent traffic, increase backoff |
| Critical | 80-95% | Only SOS/routing, shed application traffic |
| Exhausted | >95% | Stop TX until window rolls over |

**Load Shedding:**

When congested, respond to new requests with:

```
5.03 Service Unavailable
Max-Age: <seconds until duty cycle recovers>
Content-Format: application/cbor
{
  "reason": "duty_cycle",
  "retry_after": 120,
  "level": "critical"
}
```

Senders receiving 5.03 MUST back off for the indicated duration.

**Priority Queue:**

TX queue ordered by priority:

| Priority | Traffic Type |
|----------|--------------|
| 0 (highest) | SOS, emergency |
| 1 | RPL control (DIO, DAO) |
| 2 | CoAP CON (awaiting ACK) |
| 3 | CoAP NON, telemetry |
| 4 (lowest) | Bulk transfer, firmware |

During congestion, low-priority traffic is dropped first.

**Neighbor Congestion Signaling:**

Nodes MAY advertise congestion state in RPL DIO (option TBD):

```
+--------+--------+--------+
| Type   | Length | Level  |
+--------+--------+--------+
   1B       1B       1B (0-3)
```

Senders SHOULD avoid routing through congested neighbors when alternatives
exist.

### 10.2. CoAP Observe (RFC 7641)

Subscribe to resource changes:

```
GET /.well-known/core?rt=temperature
Observe: 0

<-- 2.05 Content
    Observe: 1
    {temperature: 23.5}

<-- 2.05 Content (notification)
    Observe: 2
    {temperature: 24.0}
```

### 10.3. Fragmentation: SCHC Only

**CoAP Block-wise (RFC 7959) is NOT RECOMMENDED for LICHEN.**

SCHC fragmentation (RFC 8724) handles all packet fragmentation at the
adaptation layer. Using CoAP block-wise creates redundant fragmentation
with worse performance characteristics for LoRa.

**Why SCHC fragmentation is preferred:**

| Aspect | CoAP Block-wise | SCHC Fragmentation |
|--------|-----------------|-------------------|
| Designed for | Reliable networks | LPWAN (LoRa) |
| ACK overhead | Per-block ACK required | ACK-on-Error (sparse) |
| Recovery | Application must retry | L2 handles retransmission |
| State | Both endpoints track | Receiver reassembles |

**SCHC fragmentation capacity:**

```
FCN: 6 bits → 63 fragments per window
Fragment size: ~200 bytes (L2 MTU)
Max payload: 63 × 200 = ~12 KB per SCHC transaction
```

Most LICHEN traffic (telemetry, messages, config) is <1 KB and requires
no fragmentation. SCHC handles the rare larger payloads transparently.

**Large Transfers (Firmware, Bulk Data):**

For payloads exceeding SCHC capacity (~12 KB), use application-level
chunking instead of CoAP block-wise:

```
Application Chunking Protocol:
1. Sender: POST /firmware/upload {chunk: 0, total: 50, data: <12KB>}
2. Receiver: 2.04 Changed {received: 0}
3. Sender: POST /firmware/upload {chunk: 1, total: 50, data: <12KB>}
4. ... repeat ...
5. Receiver: 2.01 Created {status: "complete", hash: "..."}
```

Each chunk fits in one SCHC transaction. Application tracks progress,
handles retries at chunk granularity. Simpler than CoAP block-wise,
better suited to LoRa's constraints.

**If Block-wise is Required:**

Legacy devices or specific use cases MAY use CoAP block-wise, but:
- Block size MUST be ≤64 bytes (fits in L2 MTU after compression)
- Expect degraded performance vs SCHC-only approach
- Double fragmentation (CoAP + SCHC) wastes overhead

### 10.4. MQTT-SN (OASIS Standard)

MQTT for Sensor Networks - UDP-based MQTT variant.

**Key Differences from MQTT:**
- Topic IDs instead of strings (2 bytes vs. variable)
- QoS -1 (fire and forget, no connection)
- Gateway-assisted topic registration

**Message Types:**
| Type | Code | Description |
|------|------|-------------|
| CONNECT | 0x04 | Client connect |
| CONNACK | 0x05 | Connect acknowledgment |
| REGISTER | 0x0A | Register topic alias |
| REGACK | 0x0B | Registration acknowledgment |
| PUBLISH | 0x0C | Publish message |
| PUBACK | 0x0D | Publish acknowledgment |
| SUBSCRIBE | 0x12 | Subscribe to topic |
| SUBACK | 0x13 | Subscribe acknowledgment |

### 10.5. MQTT-SN over LoRa Mesh

**Architecture:**
```
[Sensor Node] --LoRa--> [MQTT-SN Gateway] --IP--> [MQTT Broker]
                              |
                        [Border Router]
```

Gateway at border router translates MQTT-SN <-> MQTT 3.1.1/5.0.

### 10.6. Resource Directory (RFC 9176)

Border router runs CoAP Resource Directory for discovery:

```
# Registration
POST coap://[border-router]/rd?ep=sensor-42
</temperature>;rt="sensor";if="core.s"

# Lookup
GET coap://[border-router]/rd-lookup/res?rt=sensor
```

---

[← Previous: Security](06-security.md) | [Index](README.md) | [Next: Node Types →](08-nodes.md)
