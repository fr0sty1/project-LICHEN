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
| Spreading Factor | SF | 10 | Adjustable per-link (see Appendix: Design Rationale §7); see 3.5 for orthogonal channel assignment |
| Coding Rate | CR | 4/5 | Minimal FEC overhead |
| Preamble | - | 8 symbols | Standard LoRa |
| Sync Word | SYNC | 0x34 | Distinct from Meshtastic (0x2B) |
| CRC | - | Enabled | Hardware CRC |

### 3.3. Frequency Bands and Multi-Channel Coordination

Control channel (CH0): Announces, DIO, DIS, DAO. Beacons (if TDMA). All nodes MUST listen on CH0 when idle. Data channels (CH1-N): Application traffic only. Node selects channel per-packet or per-flow.

Coordination uses hash-based: data_ch = 1 + (hash(src_iid ^ dst_iid) mod (N_CHANNELS - 1)). Or rendezvous via announced RX_CHANNEL in Announce. Gateway-assigned in DIO for load balancing.

Regional parameters: EU868: 8 channels (868.1-868.5, 867.1-867.9); US915: 64 uplink + 8 downlink. Channel list in regional config.

**Backwards Compatibility**

No flag day required.

- Old nodes: Stay on CH0 (current single-channel behavior)
- New nodes: Use CH0 for control, data channels for application traffic
- Mixed network: CH0 carries ALL traffic types for old nodes

CH0 MUST remain the control channel AND fallback data channel. Old nodes never leave CH0, so all traffic TO old nodes MUST be on CH0. New nodes MUST listen on CH0 for routing (announces, DIO). New nodes MAY use data channels for traffic between new nodes only. Gateway MUST receive on all channels (or round-robin scan).

Channel selection logic: if dst is old_node or dst.rx_channel unknown: use CH0 else: use dst.rx_channel (from announce) or hash-based.

Degradation: Traffic to/from old nodes uses CH0 only. New-to-new traffic uses data channels. Capacity scales with fraction of new nodes.

### 3.5. Spreading Factor Assignment for Orthogonal Channels

Different LoRa spreading factors are quasi-orthogonal. SF7 and SF12 transmissions can overlap without collision. This is effectively 6 parallel channels on the same frequency. Works on ALL hardware.

Assignment: Gateway-assigned in DIO or join response for load balancing. Hash-based node_sf = SF7 + (hash(iid) mod 6). Topology-aware: core nodes SF7, edge SF12.

Nodes without an assigned SF MUST use SF10. Implementations MUST support gateway-assigned SF via DIO option (Method 2). SF10 MUST remain the default and common ground for backwards compatibility.

| Src SF | Dst SF | Path |
|--------|--------|------|
| 10 | 10 | Direct |
| 7 | 10 | Via gateway (MUST) or SF10 fallback (MAY) |
| 7 | 9 | Via gateway |

Gateways MUST receive on all SFs. Cross-SF traffic adds one hop. Independent oracle: test/vectors/sf-assignment.json verified against OpenSSL and reference Python impl.

### 3.4. Adaptive Spreading Factor

Nodes SHOULD implement adaptive SF based on link quality. Track per-neighbor (SNR, packet success rate). SNR > 10dB above sensitivity: decrease SF. SNR < 5dB above sensitivity: increase SF. Hysteresis: require N consecutive samples before changing.

Thresholds (SF10 baseline):

| SF | Sensitivity | Upgrade threshold | Downgrade threshold |
|----|-------------|-------------------|---------------------|
| SF7 | -123 dBm | -- | SNR < 0 dB |
| SF8 | -126 dBm | SNR > 10 dB | SNR < 0 dB |
| SF9 | -129 dBm | SNR > 10 dB | SNR < 0 dB |
| SF10 | -132 dBm | SNR > 10 dB | SNR < 0 dB |
| SF11 | -134 dBm | SNR > 10 dB | SNR < 0 dB |
| SF12 | -137 dBm | SNR > 10 dB | -- |

Signaling: Announce includes current TX_SF (1 byte). Absence means SF10.

**Backwards Compatibility**

No flag day required.

- Old nodes: Use SF10 for all traffic (current behavior)
- New nodes: Adapt SF per-neighbor based on SNR
- Mixed network: SF10 is common ground, always works

SF10 MUST remain the default and fallback SF. New nodes MUST use SF10 when communicating with old nodes (no SF field in their announces). New nodes MUST accept traffic on any SF (RX is already multi-SF capable via CAD). Announce MAY include TX_SF field; absence means SF10.

Adaptation logic: if dst.tx_sf is known (from announce): use adapted SF based on SNR to that neighbor else: use SF10 (safe default, works with old nodes).

Degradation: Old nodes always use SF10 (no adaptation). New nodes adapt when talking to new nodes. New-to-old: SF10. Benefit scales with fraction of new nodes.

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
