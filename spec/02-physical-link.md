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

| Region | Band | Baseline CH0 |
|--------|------|--------------|
| US/CA | 902-928 MHz ISM | 903.9 MHz |
| EU | 863-870 MHz SRD | 868.1 MHz |
| AU/NZ | 915-928 MHz | 916.8 MHz |

CH0 is the mandatory interoperability and fallback channel. Additional
channels are defined by versioned, locally provisioned regional plans; their
legal use depends on bandwidth, power, duty-cycle or dwell-time accounting,
listen-before-talk requirements, and equipment authorization. LoRaWAN channel
counts and uplink/downlink roles MUST NOT be assumed to apply unchanged to a
symmetric LICHEN mesh. See the
[Coordinated Capacity Profile](02a-coordinated-capacity.md).

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
+--------+--------+-------+--------+----------+----------+---------+--------+
| Length | LLSec  | Epoch | SeqNum | Dst Addr | SenderID | Payload | MIC    |
+--------+--------+-------+--------+----------+----------+---------+--------+
   1B       1B       1B      2B       0/2/8B    0/2/10B     var      0/48B
```

| Field | Size | Description |
|-------|------|-------------|
| Length | 1 byte | Total frame length (excl. Length field) |
| LLSec | 1 byte | Link-layer security flags |
| Epoch | 1 byte | Epoch counter (see 4.4) |
| SeqNum | 2 bytes | Sequence number (replay protection) |
| Dst Addr | 0/2/8 bytes | Destination address; 0 bytes for broadcast or elided mode |
| SenderID | 0, 2, or 10 bytes | Immediate sender short address, or `0xffff` + key-derived IID; present when Signature=1 |
| Payload | Variable | Authenticated inner payload (dispatch byte + body) |
| MIC | 0 or 48 bytes | No bytes when unsigned; full Schnorr-48 signature when signed |

The first byte of the authenticated inner payload is a dispatch value:

| Dispatch | Body |
|----------|------|
| `0x14` | SCHC packet: SCHC rule ID followed by residue/tail |
| `0x15` | LICHEN routing/control message: message type followed by message body |

Receivers MUST NOT infer the payload namespace from the first body byte. This
is required because SCHC rule `0x01` is native-address CoAP and LICHEN routing
announce type `0x01` would otherwise collide. The dispatch byte is covered by
the link signature and MIC because it is part of the frame payload.

For signed frames, `SenderID` is a 16-bit short address when the sender has an
unambiguous authenticated short-address binding. Otherwise it is the reserved
value `0xffff` followed by the sender's key-derived 64-bit IID. Receivers use
that binding to select the immediate sender key, verify the binding, and then
verify the MIC. Relays replace `SenderID`, epoch, sequence number, and
destination and sign the outgoing frame with their own key. Unsigned frames
omit `SenderID`.

Routing/control message type `0x02` is provisionally allocated to the optional
Coordinated Capacity Profile. Unknown routing/control message types and
unsupported versions MUST be ignored by protocol logic and MUST NOT be
delivered as application payload.

### 4.2. Link-Layer Security (LLSec) Byte

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| I | E | S | MIC Len | Addr Mode |
+---+---+---+---+---+---+---+---+
```

| Field | Bits | Values |
|-------|------|--------|
| Addr Mode | 0-1 | 0=none, 1=16-bit, 2=64-bit, 3=elided |
| MIC Length | 2-4 | 0 or 1=compatibility selector; 2-7=reserved |
| Signature | 5 | 1=48-byte Schnorr signature present; 0=no MIC |
| Encrypted | 6 | 1=encrypted frame unsupported; receivers MUST reject |
| Sender ID | 7 | 1=SenderID present; version 2 requires this to equal Signature |

Version 2 receivers MUST reject frames where Sender ID and Signature differ.
This makes the sender-bearing signed format self-identifying; legacy signed
frames with bit 7 clear are not valid version 2 frames.

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

Epoch persistence is REQUIRED while a long-term key remains active. A node that
cannot recover its epoch MUST NOT transmit signed frames under that key until
it restores the counter through secure provisioning or generates a new
identity. Implementations SHOULD:
- Write epoch to flash on every increment
- Use wear-leveling or multiple slots to extend flash lifetime
- Treat read failure as a fail-closed key-state error

**Sequence Number (16 bits):**

Per-sender counter, incremented for each transmission.

**Receiver State:**

Receivers maintain per-sender state:
```
Sender State Entry:
  IID: <sender IID>
  LastEpoch: <8 bits>
  LastSeqNum: <16 bits>
  Window: <at least 64 bits for out-of-order tolerance>
```

This receive state MUST persist for as long as the sender's trust binding. If
it is lost, the receiver MUST discard the binding and re-establish trust before
accepting another frame from that sender.

**Acceptance Rules:**

| Received | Action |
|----------|--------|
| `serial_newer(received, highest)` | Accept, advance window |
| Received counter in current window | Accept if unseen, mark seen |
| Received counter older than window | Reject |
| Serial delta exactly `0x800000` | Reject as ambiguous |

**Wrap Behavior:**

At ~1 packet/second, 16-bit seqnum wraps every ~18 hours. The epoch
increment ensures the 24-bit logical counter advances monotonically.
At 10 packets/second, the complete 24-bit counter wraps in about 19.4 days and
the half-space is about 9.7 days. Wrap is safe while receivers observe progress
within a half-space. A peer that may have missed `2^23` transmissions MUST
re-establish replay state through an authenticated exchange before accepting
new traffic.

Counters use 24-bit serial arithmetic. Let `C = (Epoch << 16) | SeqNum` and
`delta = (received - highest) mod 2^24`. `received` is newer exactly when
`0 < delta < 2^23`; a delta of `2^23` is ambiguous and rejected. This rule
handles epoch wrap without ordinary integer comparisons.

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

1. **Compute candidate:** `short_addr = (CRC16(EUI-64) mod 0xffef) + 1`,
   producing the interoperable range `0x0001`-`0xffef`
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
   - If conflict received: set `candidate = (candidate mod 0xffef) + 1` and
     retry from step 2
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

[← Previous: Architecture](01-architecture.md) | [Index](README.md) | [Next: Coordinated Capacity Profile →](02a-coordinated-capacity.md)
