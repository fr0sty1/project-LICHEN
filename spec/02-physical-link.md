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
+--------+--------+-------+--------+----------+---------+--------+
| Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload | MIC    |
+--------+--------+-------+--------+----------+---------+--------+
   1B       1B       1B      2B       2-8B      var      4-8B
```

| Field | Size | Description |
|-------|------|-------------|
| Length | 1 byte | Total frame length (excl. Length field) |
| LLSec | 1 byte | Link-layer security flags |
| Epoch | 1 byte | Epoch counter (see 4.4) |
| SeqNum | 2 bytes | Sequence number (replay protection) |
| Dst Addr | 2-8 bytes | Compressed destination address |
| Payload | Variable | SCHC compressed packet |
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

### 4.4. Epoch and Sequence Number

Replay protection uses a 24-bit logical counter: 8-bit epoch + 16-bit seqnum.

**Epoch (8 bits):**

The epoch counter increments on:
1. **SeqNum wrap:** When SeqNum rolls over from 0xFFFF to 0x0000
2. **Reboot:** Epoch MUST increment on every power cycle or reset
3. **Manual reset:** Operator-initiated counter reset

Epoch MUST be persisted to non-volatile storage. Implementations SHOULD:
- Write epoch to flash on every increment
- Use wear-leveling or multiple slots to extend flash lifetime
- On read failure, assume epoch = last_known + 1

**Sequence Number (16 bits):**

Per-sender counter, incremented for each transmission.

**Receiver State:**

Receivers maintain per-sender state:
```
Sender State Entry:
  IID: <sender IID>
  LastEpoch: <8 bits>
  LastSeqNum: <16 bits>
  Window: <32-bit bitmap for out-of-order tolerance>
```

**Acceptance Rules:**

| Received | Action |
|----------|--------|
| Epoch > LastEpoch | Accept, update state |
| Epoch == LastEpoch, SeqNum > LastSeqNum | Accept, update state |
| Epoch == LastEpoch, SeqNum in window | Accept if not seen, mark seen |
| Epoch < LastEpoch | Reject (replay) |
| Epoch == LastEpoch, SeqNum ≤ window floor | Reject (replay) |

**Wrap Behavior:**

At ~1 packet/second, 16-bit seqnum wraps every ~18 hours. The epoch
increment ensures the 24-bit logical counter advances monotonically.
At maximum traffic (10 pkt/sec), epoch wraps in ~7.5 years—acceptable.

**Reboot Resilience:**

On reboot, the node increments epoch and starts seqnum at 0. Receivers
see epoch advance and accept packets immediately. No time sync required.

### 4.5. Short Address Assignment

Short addresses (16-bit) save 6 bytes per packet compared to EUI-64.
Assignment uses a hybrid approach depending on network topology.

**When Coordinator is Present (Border Router or DODAG Root):**

The coordinator assigns short addresses authoritatively:

1. Node joins mesh, sends DAO with EUI-64
2. Coordinator allocates unused 16-bit address
3. Coordinator responds with assigned address in DAO-ACK
4. Node begins using short address

Coordinator maintains address table:
```
Short Address Table:
  0x0001: EUI-64=00:11:22:33:44:55:66:77, PubKey=<32B>
  0x0002: EUI-64=00:11:22:33:44:55:66:88, PubKey=<32B>
  ...
```

Address 0x0000 is reserved (broadcast). Range 0xFFF0-0xFFFF reserved for future use.

**When No Coordinator (Isolated Mesh):**

Nodes self-assign using hash-based allocation with DAD:

1. **Compute candidate:** `short_addr = CRC16(EUI-64) | 0x0001` (ensure non-zero)
2. **DAD probe:** Broadcast 3 DAD requests with random jitter (0-500ms between)
   ```
   DAD Request:
     Type: DAD_PROBE
     Candidate: <16-bit address>
     EUI-64: <requester's EUI-64>
     PubKey: <requester's public key>
   ```
3. **Wait:** Listen for 2 seconds for conflicts
4. **Conflict response:** Node holding address replies with DAD_CONFLICT
   ```
   DAD Conflict:
     Type: DAD_CONFLICT
     Address: <contested address>
     EUI-64: <holder's EUI-64>
     PubKey: <holder's public key>
   ```
5. **Resolution:**
   - If conflict received: increment candidate, retry from step 2
   - If no conflict after 3 probes: claim address
   - After 5 failed attempts: fall back to EUI-64 only

**Collision Detection (Safety Net):**

Even with DAD, collisions may occur (simultaneous join, partitioned mesh).
Receivers detect collisions via signature mismatch:

1. Receive frame from short address 0x0042
2. Verify signature against stored public key for 0x0042
3. If signature invalid but well-formed: possible collision
4. Check if different public key would verify → collision confirmed

**Collision Resolution:**

When collision detected:

| Scenario | Action |
|----------|--------|
| Node detects own address collision | Abandon short address, use EUI-64, re-run DAD |
| Receiver detects collision | Log warning, track both keys temporarily |
| Coordinator present | Coordinator arbitrates, reassigns one node |

**Transition to Coordinator:**

When a border router joins an isolated mesh:

1. BR announces coordinator capability in DIO
2. Nodes with self-assigned addresses re-register with coordinator
3. Coordinator confirms or reassigns addresses
4. Mesh transitions to coordinator-managed mode

---

[← Previous: Architecture](01-architecture.md) | [Index](README.md) | [Next: Adaptation Layer →](03-adaptation.md)
