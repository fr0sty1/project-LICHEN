<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

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
| Spreading Factor | SF | 10 | Adjustable per-link (see Appendix: Design Rationale §7) |
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

### 3.5. SFN Delta for Coordinated Capacity

Coordinated transmissions on a single frequency (SFN) improve capacity and reliability by having multiple nodes transmit identical frames with deliberate timing deltas. Receivers combine signals constructively if deltas fall within the cyclic prefix/symbol guard.

**SFN Delta Example (SF10, BW=125 kHz, symbol time ≈ 8.19 ms):**

| Transmitter | Dist to RX (km) | Prop. Delay (µs) | Applied Delta (symbols) | Effective Alignment |
|-------------|-----------------|------------------|-------------------------|---------------------|
| A (lead)    | 2               | 6.7              | +0.8                    | Within guard        |
| B (ref)     | 5               | 16.7             | 0.0                     | Reference           |
| C (follow)  | 12              | 40.0             | -1.2                    | Boundary case       |

Boundary example: When delta exceeds 0.25 symbols, destructive interference occurs unless SF increased or separate slot used (see 14.8 TDMA). Deltas computed from known positions or RSSI-derived ranging. MUST synchronize via shared time source (GNSS/DIO).

See CCP-12 synchronized hopping in [02a-coordinated-capacity.md](02a-coordinated-capacity.md) for full multi-channel coordination via SFN/GPS, hash_32 channel selection, and rendezvous announcements in beacons/DIOs.

---

## 4. Link Layer

### 4.1. Frame Format

```
+--------+--------+-------+--------+----------+---------+--------+
| Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload | MIC    |
+--------+--------+-------+--------+----------+---------+--------+
   1B       1B       1B      2B       0/2/8B    var      0/48B
```

| Field | Size | Description |
|-------|------|-------------|
| Length | 1 byte | Total frame length (excl. Length field) |
| LLSec | 1 byte | Link-layer security flags |
| Epoch | 1 byte | Epoch counter (see 4.4) |
| SeqNum | 2 bytes | Sequence number (replay protection) |
| Dst Addr | 0/2/8 bytes | Destination address; 0 bytes for broadcast or elided mode |
| Payload | Variable | Authenticated inner payload (dispatch byte + body) |
| MIC | 0 or 48 bytes | No bytes when unsigned; full Schnorr-48 signature when signed |

The first byte of the authenticated inner payload is a dispatch value:

| Dispatch | Body |
|----------|------|
| `0x14` | SCHC packet: SCHC rule ID followed by residue/tail |
| `0x15` | LICHEN routing/control message: message type followed by message body |

Receivers MUST NOT infer the payload namespace from the first body byte. This
is required because SCHC rule `0x01` is global CoAP and LICHEN routing
announce type `0x01` would otherwise collide. The dispatch byte is covered by
the link signature and MIC because it is part of the frame payload.

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
| MIC Length | 2-4 | 0 or 1=compatibility selector; 2-7=reserved |
| Signature | 5 | 1=48-byte Schnorr signature present; 0=no MIC |
| Encrypted | 6 | 1=encrypted frame unsupported; receivers MUST reject |
| Reserved | 7 | Must be 0 |

### 4.3. Addressing Modes

| Mode | Size | Description |
|------|------|-------------|
| None (0) | 0B | Broadcast |
| Short (1) | 2B | 16-bit short address (assigned by coordinator) |
| Extended (2) | 8B | EUI-64 derived from hardware |
| Elided (3) | 0B | Destination derived from context |

### 4.4. Epoch and Sequence Number

Replay protection uses a 24-bit logical counter: 8-bit epoch + 16-bit seqnum.

**Epoch (8 bits):**

The epoch counter increments on:
1. **SeqNum wrap:** When SeqNum rolls over from 0xFFFF to 0x0000
2. **Reboot:** Epoch MUST advance on every power cycle or reset
3. **Manual reset:** Operator-initiated counter reset

**Epoch Initialization:**

When no persisted epoch is available (cold boot without flash, or flash read
failure), implementations MUST initialize epoch to a random value uniformly
distributed in [128, 255]. This ensures the 24-bit counter starts in the upper
half of the counter space (8M-16M), so half-space arithmetic treats it as
"ahead" of any counter value peers may have cached in the lower half.

> **Security Note:** Some platforms (notably ESP32) have weak hardware RNG output
> before the radio subsystem initializes. On such platforms without epoch
> persistence, an attacker who knows boot timing may predict the epoch.
> Implementations on affected platforms SHOULD either persist epoch to flash or
> defer random initialization until after radio subsystem init.

Epoch persistence is RECOMMENDED but not required. Implementations that persist
epoch SHOULD:
- Write epoch to flash on every increment
- Use wear-leveling or multiple slots to extend flash lifetime
- On read failure, fall back to random initialization as above

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
At maximum traffic (10 pkt/sec), epoch wraps in ~7.5 years--acceptable.

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
