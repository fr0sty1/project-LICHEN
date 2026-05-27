<!-- Part of LICHEN Protocol Specification -->

# Physical and Link Layers

## 3. Physical Layer

### 3.1. Modulation

LoRa Chirp Spread Spectrum (CSS) as implemented by Semtech SX126x and SX127x.

### 3.2. Recommended Parameters

| Parameter | Symbol | Default | Notes |
|-----------|--------|---------|-------|
| Frequency | FREQ | Regional | See 3.3 |
| Bandwidth | BW | 125 kHz | Balance of range/throughput |
| Spreading Factor | SF | 9 | Adjustable per-link |
| Coding Rate | CR | 4/5 | Minimal FEC overhead |
| Preamble | - | 8 symbols | Standard LoRa |
| Sync Word | SYNC | 0x34 | Distinct from Meshtastic (0x2B) |
| CRC | - | Enabled | Hardware CRC |

### 3.3. Frequency Bands

| Region | Band | Default Channel | Channels |
|--------|------|-----------------|----------|
| US/CA | 915 MHz ISM | 903.9 MHz | 64 (200 kHz spacing) |
| EU | 868 MHz | 868.1 MHz | 3 (duty cycle limited) |
| AU/NZ | 915 MHz | 916.8 MHz | 64 |

### 3.4. Adaptive Data Rate (ADR)

Nodes SHOULD implement ADR to optimize SF/TX power based on link quality:

1. Track SNR of received packets from each neighbor
2. If SNR > threshold + margin: decrease SF (faster)
3. If SNR < threshold: increase SF (more robust)
4. Propagate via RPL DIO options

---

## 4. Link Layer

### 4.1. Frame Format

```
+--------+--------+--------+----------+---------+--------+
| Length | LLSec  | SeqNum | Dst Addr | Payload | MIC    |
+--------+--------+--------+----------+---------+--------+
   1B       1B       2B       2-8B      var      4-8B
```

| Field | Size | Description |
|-------|------|-------------|
| Length | 1 byte | Total frame length (excl. Length field) |
| LLSec | 1 byte | Link-layer security flags |
| SeqNum | 2 bytes | Sequence number (replay protection) |
| Dst Addr | 2-8 bytes | Compressed destination address |
| Payload | Variable | 6LoWPAN/SCHC compressed packet |
| MIC | 4-8 bytes | Message Integrity Code |

### 4.2. Link-Layer Security (LLSec) Byte

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| E | S |  MIC Len  | Addr Mode |
+---+---+---+---+---+---+---+---+
```

| Field | Bits | Values |
|-------|------|--------|
| Addr Mode | 0-1 | 0=none, 1=16-bit, 2=64-bit, 3=elided |
| MIC Length | 2-4 | 0=32-bit, 1=64-bit, 2=reserved |
| Signature | 5 | 1=Ed25519 signature present |
| Encrypted | 6 | 1=payload encrypted (AES-CCM) |
| Reserved | 7 | Must be 0 |

### 4.3. Addressing Modes

| Mode | Size | Description |
|------|------|-------------|
| None (0) | 0B | Broadcast |
| Short (1) | 2B | 16-bit short address (assigned by coordinator) |
| Extended (2) | 8B | EUI-64 derived from hardware |
| Elided (3) | 0B | Derived from IPv6 destination |

### 4.4. Sequence Number

16-bit counter per sender, incremented for each transmission.
Used for:
- Duplicate detection (discard if seen recently)
- Replay protection (reject if SeqNum <= last_seen)

Receivers maintain per-sender SeqNum state, with 32-entry window for
out-of-order tolerance.

---

[← Previous: Architecture](01-architecture.md) | [Index](README.md) | [Next: Adaptation Layer →](03-adaptation.md)
