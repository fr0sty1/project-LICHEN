<!-- Part of LICHEN Protocol Specification -->

# Packets and Timing

## 13. Packet Formats

### 13.1. Complete Packet Example

**Scenario:** Leaf node sends CoAP temperature reading to border router.

**Application payload (CoAP):**
```
Ver=1, T=NON, TKL=1, Code=2.05 (Content)
Token: 0x42
Options: Content-Format=60 (CBOR)
Payload: {temperature: 23.5} -> A1 6B 74656D7065726174757265 F9 4BC0
         (17 bytes)
```

**After OSCORE:** (if enabled)
```
OSCORE option + encrypted payload + tag
(adds ~10 bytes)
```

**After SCHC compression (Rule 0):**
```
Rule ID: 0x00 (1 byte)
Residue: SrcPort[3:0], DstPort[3:0] (1 byte)
Compressed CoAP header: 0x42 0x45 (2 bytes)
Payload: (17 bytes)
Total: 21 bytes
```

**With 6LoWPAN dispatch:**
```
SCHC dispatch: 0x14 (1 byte)
SCHC packet: (21 bytes)
Total: 22 bytes
```

**Link-layer frame:**
```
Length: 38 (1 byte)
LLSec: 0x20 (signature, no encryption, short addr) (1 byte)
SeqNum: 0x0042 (2 bytes)
DstAddr: 0x0001 (border router short) (2 bytes)
Payload: (22 bytes)
Signature: (32 bytes, truncated Ed25519)
Total: 60 bytes
```

**LoRa PHY:**
```
Preamble: 8 symbols
Header: 3 bytes (implicit mode)
Payload: 60 bytes
CRC: 2 bytes
```

### 13.2. Packet Size Summary

| Layer | This Protocol | Meshtastic | MeshCore |
|-------|---------------|------------|----------|
| App payload | 17 | 17 | 17 |
| Security (E2E) | 10 | 0* | 2 |
| Transport + Network | 2 | 16 | - |
| Routing overhead | 0-6 | 0-7 | 0-64 |
| Link security | 35 | 0 | 4 |
| **Total** | **64-70** | **33-40** | **23-87** |

*Meshtastic AES-CTR has no auth overhead; this is a weakness.

### 13.3. RPL DIO Packet

```
Link-layer:
  [Len] [LLSec] [SeqNum] [DstAddr=ff02::1a] [Payload] [Sig]

IPv6 (compressed):
  [SCHC Rule 2] [HopLimit] [Multicast flag]

ICMPv6:
  Type=155, Code=1 (DIO)

DIO payload:
  [RPLInstanceID] [Version] [Rank] [Flags] [DODAGID]

Options:
  [DODAG Configuration] [Prefix Information]
```

---

## 14. Timing and Duty Cycle

### 14.1. Trickle Timer (DIO)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Imin | 4 seconds | Allow network stabilization |
| Imax | 17 minutes | Reduce steady-state overhead |
| k | 10 | Suppress redundant DIOs |

### 14.2. DAO Timing

| Event | Delay |
|-------|-------|
| Initial DAO | Random 0-2 seconds after joining |
| DAO retry | 4, 8, 16 seconds (exponential backoff) |
| DAO refresh | 30 minutes (soft state lifetime / 2) |

### 14.3. Data Traffic

| Traffic Type | Recommended Interval |
|--------------|---------------------|
| Periodic telemetry | 5-60 minutes |
| Event-driven | As needed |
| Heartbeat/keepalive | 30 minutes |

### 14.4. Duty Cycle Compliance

**EU 868 MHz (10% duty cycle):**

At SF9/125kHz, airtime per 60-byte packet ~ 200ms.

Max packets per hour: `3600s * 0.1 / 0.2s = 1800 packets`

Per node, accounting for routing: ~100-300 packets/hour comfortable.

### 14.5. CSMA/CA Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CAD timeout | 3 symbols | Channel activity detection |
| Backoff unit | 10 ms | Slot time |
| Backoff max | 5 | CW = 2^backoff - 1 |
| Retry limit | 3 | Before reporting failure |

---

[← Previous: Node Types](08-nodes.md) | [Index](README.md) | [Next: Implementation →](10-implementation.md)
