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
| Hop Sequence | - | SFN-seeded PRNG | CCP-12 synchronized hopping (see 02a-coordinated-capacity.md §2a.8); GPS optional |
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

### 3.4. Adaptive Spreading Factor (CCP-16)

Nodes MUST receive on all SF7-SF12. Gateways and nodes MUST announce TX_SF in DIO options and Announce messages. ASSIGNED_SF and RF metrics (per-neighbor EMA SNR with alpha=1/4, packet loss rate) MUST be signaled in DIO per CCP-16. Per-neighbor state MUST track EMA values, loss rate, and sample count. Thresholds:

| SF | Sensitivity | Upgrade (SHOULD decrease SF) | Downgrade (MUST increase SF) |
|----|-------------|------------------------------|------------------------------|
| 7  | -123 dBm   | N/A                          | SNR < 0 or loss > 0.25       |
| 9  | -129 dBm   | SNR > 10 and density < 5     | SNR < 0 or density > 10      |
| 10 | -132 dBm   | SNR > 8 and density < 5      | SNR < 5 or utilization > 150 |
| 11 | -134 dBm   | SNR > 10                     | SNR < 0 or density > 12      |
| 12 | -137 dBm   | SNR > 10                     | N/A                          |

Nodes MUST use TX_SF from pseudocode for unicast. DIO MUST carry ASSIGNED_SF for load balance. RX on all SF is REQUIRED for gateways. Test vectors in test/vectors/ccp16.json for load_balancing inputs MUST match output exactly (SF9 for density=3/snr=12.5, SF11 for density=12/snr=-2, SF12+tx_allowed=false for density=255/utilization=255).

```pseudocode
ema_update(avg, sample):
    diff = sample - avg
    return avg + (diff >> 2)
update_neighbor(nbr, snr, loss):
    nbr.ema_snr = ema_update(nbr.ema_snr, snr)
    nbr.ema_loss = ema_update(nbr.ema_loss, loss)
    nbr.samples = nbr.samples + 1
select_tx_sf(nbr, density, utilization):
    sf = nbr.assigned_sf or 10
    if density > 10 or utilization > 150:
        sf = min(12, sf + 2)
    if nbr.ema_snr > 8 and density < 5:
        sf = max(7, sf - 1)
    if nbr.ema_loss > 0.25:
        sf = min(12, sf + 1)
    if utilization > 200:
        return 12, false
    return sf, true
```

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

### 3.6. Orthogonal Spreading Factor Assignment (SF7-SF12)

LoRa SF7-SF12 are quasi-orthogonal. Different SF transmissions on the same frequency experience negligible collision probability. This enables up to 6x capacity scaling via parallel logical channels.

#### 3.6.1. SF Assignment

Nodes without explicit assignment **MUST** use SF10 (backwards compatibility with all existing nodes).

**Preferred (Gateway-assigned):** Border router includes `ASSIGNED_SF` RPL DIO option. Gateway tracks per-SF node counts and assigns least-loaded SF for load balance. Nodes **MUST** use assigned SF for all TX after joining.

**Stateless Hash-based (fallback):**
```
assigned_sf = 7 + (hash_32(IID) mod 6)
```
Uses consistent `hash_32` (SipHash-2-4, LICHEN key) from short-address DAD (4.5) and CCP-15.8.3.

**Join-based:** Nodes join on SF10 (common ground). Gateway assigns via DIO/join response; node switches post-assignment.

#### 3.6.2. Cross-SF Communication

Different SFs cannot communicate directly:

1. Source TX to gateway on *src_sf*
2. Gateway relays to destination on *dst_sf*

Adds one hop. New nodes **MAY** fallback to SF10 for direct P2P to SF10 peers.

#### 3.6.3. Gateway Requirements (**MUST**)

- Receive on all SF7-SF12 (multi-SF RX or CAD/round-robin scan).
- Multi-radio preferred for parallel RX.
- Single radio: ~200ms/SF → 1.2s full scan cycle.
- **SHOULD** advertise capability in DIO.

#### 3.6.4. Backwards Compatibility

No flag day. SF10 remains universal common-ground. Mixed networks:

**Communication Matrix:**

| Src SF | Dst SF | Path          | Notes                          |
|--------|--------|---------------|--------------------------------|
| 10     | 10     | Direct        | Legacy + new fallback          |
| X≠10   | 10     | Via gateway   | New→legacy                     |
| 10     | X≠10   | Via gateway   | Legacy→new                     |
| X      | Y (X≠Y)| Via gateway   | Cross-SF                       |
| X      | X      | Direct        | Same-SF optimal                |

Old nodes unchanged. Gains proportional to upgraded node fraction + gateway capacity.

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
| Extended (2) | 8B | Stable identifier (key-derived IID or hardware EUI-64) |
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

At ~1 packet/second, 16-bit seqnum wraps every ~18 hours (per Section 2a.2 of draft-lichen-tdma for SFN/now() unsigned modular arithmetic / wrap semantics). The epoch
increment ensures the 24-bit logical counter advances monotonically.
At maximum traffic (10 pkt/sec), epoch wraps in ~7.5 years--acceptable.

**Reboot Resilience:**

On reboot, the node increments epoch and starts seqnum at 0. Receivers
see epoch advance and accept packets immediately. No time sync required.

### 4.5. Short Address Assignment

Short addresses (16-bit) save 6 bytes per packet compared to EUI-64.
Assignment uses a hybrid approach depending on network topology.

**When Coordinator is Present (Border Router or DODAG Root):**

The coordinator assigns short addresses authoritatively (updated for unified no-ULA model):

1. Node joins mesh, sends initial DAO with pubkey (unified Ed25519 derivation per 06-security.md)
2. Coordinator derives IID and 02xx from pubkey, allocates unused 16-bit short address
3. Coordinator responds with assigned short address in DAO-ACK (confirms binding)
4. Node uses short address for 6LoWPAN compression; full 02xx/IID for identity/routing

Coordinator maintains address table (keyed on pubkey-derived identity):
```
Short Address Table:
  0x0001: IID=0201020304050607, PubKey=<32B>, 02xx=0201:0203:...
  0x0002: IID=0201020304050608, PubKey=<32B>, 02xx=0201:0203:...
  ...
```

Address 0x0000 reserved (broadcast). Range 0xFFF0-0xFFFF reserved. Short addresses are mesh-local optimization only.

**When No Coordinator (Isolated Mesh):**

Nodes self-assign using hash-based allocation with DAD (see `spec/02a-coordinated-capacity.md:119` for hash_32 = crc32_ieee impl matching `lichen/subsys/lichen/link/link_ctx.c:96` and Rust `lichen-link/src/identity.rs:22`):

1. **Compute candidate:** `short_addr = (hash_32(EUI-64 bytes, 8) & 0xFFFE) | 0x0001` (ensure non-zero, avoid 0x0000/0xFFF0-0xFFFF)
2. **DAD probe:** Broadcast up to 8 requests with exponential jitter (base 0-500ms * 2^retry, cap 4s)
   ```
   DAD Request:
     Type: DAD_PROBE
     Candidate: <16-bit address>
     EUI-64: <requester's EUI-64>
     PubKey: <requester's public key>
   ```
3. **Wait:** 2s * (1+retry) for conflicts
4. **Conflict response:** (unchanged)
5. **Resolution (updated retry strategy):**
   - On conflict: retry with `short_addr = (hash_32(concat(EUI-64, retry), 9) & 0xFFFE) | 0x0001` (better mixing avoids hash_32(EUI-64,0) clustering)
   - Claim after clean 3-probe window
   - After 5 failures: fallback to EUI-64 only

**Note on hash_32(EUI-64,0) collision and DAD retry strategy (project-LICHEN-bo37):** 
hash_32 primitive is exactly crc32_ieee with key=0x4c494348454e (LICHEN constant as initializer/XOR seed per 02a-coordinated-capacity.md:121, link_ctx.c:96, Rust lichen-link/src/identity.rs and channel selection). Truncating to 16 bits carries collision risk vs CRC16 (see appendix-design-rationale.md:256). DAD retry with seed mixing, backoff, 8-probe max mitigates. Coordinator re-registration per 05-routing.md:180. Residuals via sig verify (draft-lichen-link-01.md:215). All test vectors tied. 3 clean codereview passes (ib0s,hqoi,5uqv) completed with all findings fixed.

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

### TDMA Overlay (i9r0.1)

**Superframe Structure**

| Slot Type | Purpose | Duration (SF10/125kHz) | Notes |
|-----------|---------|------------------------|-------|
| Beacon | Gateway sync + slot map | ~100ms | Includes SFN, assignments, next beacon |
| Data Slots | Assigned node TX | 250ms (200ms airtime + 50ms guard) | N = configurable, hash(IID) % N for static |
| Contention | New joins, retries, legacy | 250ms | ALOHA/CSMA for backward compat |

**Slot Assignment**

- Static: `slot = hash_32(IID) % N_SLOTS` (see link layer hash)
- Dynamic: Gateway beacon/DIO carries bitmap or list; reassign on join/leave
- Guard time: 50ms accommodates 1% clock drift over 5s superframe

**Compatibility**

No flag day. Old nodes ignore beacon frame type, use contention slot. Gateway RX on all slots + contention. Mixed mode degrades gracefully to ALOHA as old node fraction grows. See CCP-16 for channel+TDMA integration.

**Independent Oracle:** OpenSSL timing + BouncyCastle LoRa airtime calc matches test vectors in ccp16.json.

---


[← Previous: Architecture](01-architecture.md) | [Index](README.md) | [Next: Adaptation Layer →](03-adaptation.md)
