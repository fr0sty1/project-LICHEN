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
| Hop Sequence | - | SFN-seeded PRNG | CCP-12 synchronized hopping (see 02a-coordinated-capacity.md §2a.3 for channel agility and hash-based selection); GPS optional |
| CRC | - | Enabled | Hardware CRC |

### 3.3. Frequency Bands and Multi-Channel Coordination

**Channel Plan**

| Channel | Role | Traffic | Listen Requirement |
|---------|------|---------|--------------------|
| CH0 (control) | Routing, control | Announces, DIO, DIS, DAO, beacons (TDMA) | All nodes MUST listen when idle |
| CH1-N (data) | Application | App traffic only | Per-packet selection |

**Coordination Methods** (see CCP-9 in 02a-coordinated-capacity.md)

- Hash-based (stateless): `data_ch = 1 + (hash(src_iid ^ dst_iid) mod (N_CHANNELS - 1))`
- Rendezvous: Announce includes `rx_channel`; sender uses announced (TOFU pinning)
- Gateway-assigned: DIO carries channel for load balancing (MRHOF variant)

**Regional Parameters**

Channel list in regional config (not hardcoded):

- EU868: 8 channels (868.1-868.5, 867.1-867.9)
- US915: 64 uplink + 8 downlink

**Backwards Compatibility**

No flag day required. CH0 is universal fallback. Old nodes stay on CH0. New nodes listen on CH0 for routing + data channels for new-to-new. Gateway RX on all channels. Selection: CH0 if old/unknown else announced or hash. Degradation scales with new node fraction. Test vectors in test/vectors/ccp9*.json and ccp16*.json.

### 3.4. Spreading Factor Assignment for Orthogonal Channels

Different LoRa spreading factors are quasi-orthogonal. SF7 and SF12 transmissions can overlap without collision. This enables up to 6x capacity scaling via parallel logical channels on the same frequency. Works on ALL hardware.

**SF Assignment:**
- Preferred (Gateway-assigned): Border router includes `ASSIGNED_SF` RPL DIO option. Gateway tracks per-SF node counts and assigns least-loaded SF for load balance. Nodes **MUST** use assigned SF for all TX after joining.
- Stateless hash-based (fallback): `assigned_sf = 7 + (hash_32(IID) mod 6)`. Uses consistent `hash_32` (FNV-1a32 per project-LICHEN-eirg) from short-address DAD and CCP-15.8.3.
- Join-based: Nodes join on SF10 (common ground). Gateway assigns via DIO or join response; node switches post-assignment.
- Nodes without explicit assignment **MUST** use SF10 (backwards compatibility with all existing nodes).

| Src SF | Dst SF | Path          | Notes                          |
|--------|--------|---------------|--------------------------------|
| 10     | 10     | Direct        | Legacy + new fallback          |
| X≠10   | 10     | Via gateway   | New→legacy or legacy→new       |
| X      | Y (X≠Y)| Via gateway   | Cross-SF                       |
| X      | X      | Direct        | Same-SF optimal                |

Gateways **MUST** receive on all SF7-SF12 (multi-SF RX or CAD/round-robin scan). Multi-radio preferred for parallel RX. Single radio: ~200ms/SF → 1.2s full scan cycle. **SHOULD** advertise capability in DIO.

Cross-SF traffic adds one hop. New nodes **MAY** fallback to SF10 for direct P2P to SF10 peers.

Independent oracle: `test/vectors/sf-assignment.json` verified against OpenSSL and reference Python impl.

### 3.5. Adaptive Spreading Factor (CCP-16)

SF10 (or ASSIGNED_SF from gateway DIO) is the REQUIRED baseline per appendix-design-rationale.md:7.1 and 02a-coordinated-capacity.md:2a.3. Density-aware rules override this **only** on explicit thresholds (see adaptive_sf_select pseudocode there and table below); otherwise retain baseline. Nodes MUST receive on all SF7-SF12. Gateways and nodes MUST announce current TX_SF in DIO options and Announce messages (1-byte field; absence means SF10). ASSIGNED_SF and RF metrics (per-neighbor EMA SNR with alpha=1/4, packet loss rate) MUST be signaled in DIO per CCP-16. Per-neighbor state MUST track EMA values, loss rate, and sample count.

Thresholds:

| SF | Sensitivity | Upgrade (SHOULD decrease SF) | Downgrade (MUST increase SF) |
|----|-------------|------------------------------|------------------------------|
| 7  | -123 dBm   | N/A                          | SNR < 0 or loss > 0.25       |
| 9  | -129 dBm   | density < 5 AND snr_ema > 8 (low-density only) | SNR < 0 or density > 8       |
| 10 | -132 dBm   | **DEFAULT** (moderate density 5-20) | SNR < 0 or load_factor > 0.8 |
| 11 | -134 dBm   | N/A                          | density > 8 or snr_ema < 0 or load > 0.8 |
| 12 | -137 dBm   | N/A                          | density > 20 or snr_ema < -5 |

**Normative Pseudocode:**

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

Embedded note: no_std implementations SHOULD prefer Q16.16 fixed-point (see appendix-design-rationale.md:7.6 example and lichen-core::rf_health). Test vectors in `test/vectors/ccp16.json` (and ccp15.json, ccp_load_balancing.json) MUST match output exactly for load_balancing cases (SF9 for density=3/snr=12.5, SF11 for density=12/snr=-2, SF12+tx_allowed=false for density=255/utilization=255).

**Backwards Compatibility**

No flag day required. SF10 remains the universal common-ground.

- Old nodes: Use SF10 for all traffic (no adaptation).
- New nodes: Adapt per-neighbor for new-to-new; MUST fallback to SF10 for old nodes.
- Mixed network: All old-node traffic on SF10/CH0. Benefit scales with upgraded node fraction + gateway multi-SF RX capacity.

### 3.6. SFN Delta for Coordinated Capacity

Coordinated transmissions on a single frequency (SFN) improve capacity and reliability by having multiple nodes transmit identical frames with deliberate timing deltas. Receivers combine signals constructively if deltas fall within the cyclic prefix/symbol guard.

**SFN Delta Example (SF10, BW=125 kHz, symbol time ≈ 8.19 ms):**

| Transmitter | Dist to RX (km) | Prop. Delay (µs) | Applied Delta (symbols) | Effective Alignment |
|-------------|-----------------|------------------|-------------------------|---------------------|
| A (lead)    | 2               | 6.7              | +0.8                    | Within guard        |
| B (ref)     | 5               | 16.7             | 0.0                     | Reference           |
| C (follow)  | 12              | 40.0             | -1.2                    | Boundary case       |

Boundary example: When delta exceeds 0.25 symbols, destructive interference occurs unless SF increased or separate slot used (see 14.8 TDMA). Deltas computed from known positions or RSSI-derived ranging. MUST synchronize via shared time source (GNSS/DIO).

See CCP-12 synchronized hopping in [02a-coordinated-capacity.md](02a-coordinated-capacity.md) for full multi-channel coordination via SFN/GPS, hash_32 channel selection, and rendezvous announcements in beacons/DIOs.

### 3.7. LR-FHSS Optional Mode (SX1262 Only)

LR-FHSS provides superior collision resilience by frequency hopping each packet across many channels. Collisions corrupt only fragments rather than entire packets. Optional for SX1262 devices only.

**Advertisement and Negotiation:**
- Gateway sets `LR_FHSS_SUPPORTED` flag in DIO (MUST use a reserved bit).
- Nodes advertise `LR_FHSS_CAPABLE` flag in Announce (1 bit in app_data field).
- SX1262 nodes MAY select LR-FHSS for uplink if gateway advertises support.
- Gateway MUST implement dual-mode RX (standard LoRa + LR-FHSS on same frequency).
- Downlink always matches the mode of the node's most recent uplink.
- Node-to-node defaults to standard LoRa; LR-FHSS only if both peers capable and negotiated.

**Parameters:**
- Uses LoRaWAN LR-FHSS DR8-DR11.
- OCW: 137 kHz or 336 kHz.
- CR: 1/3 or 2/3.
- Hopping sequence per Semtech AN1200.62.

**Backward Compatibility:**
- SX127x nodes ignore flags, use standard LoRa exclusively.
- Mixed networks supported without disruption.
- No protocol flag day required.

**Tradeoffs:**
- ~2× airtime vs standard LoRa.
- 10×+ better performance in high-density collision scenarios via fragment FEC.

See child issue project-LICHEN-zd2d.2 for driver implementation.

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
| Length | 1 byte | Frame body length (excludes this field), 4-254 bytes |
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
the link signature in the MIC field because it is part of the frame payload.

### 4.2. Link-Layer Security (LLSec) Byte

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| R | E | S |  MIC Len  | Addr Mode |
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

Replay protection uses EPO and SeqNum as one finite 24-bit unsigned counter:
`counter = (EPO << 16) | SeqNum`, in the range 0x000000 through 0xFFFFFF.
Counter comparisons use ordinary unsigned integer ordering, not serial-number
arithmetic or modulo arithmetic.

**Epoch (8 bits):**

The epoch counter increments when SeqNum reaches 0xFFFF and another tuple is
needed. SeqNum then restarts at zero in the new epoch. EPO MUST NOT wrap from
0xFF to 0x00. After using `(EPO=0xFF, SeqNum=0xFFFF)`, the sender MUST rotate
its link key before transmitting another authenticated frame.

On reboot or manual reset, a sender MUST resume above its last used counter
under the current key. It MUST NOT reset or wrap either component under that
key.

**Epoch Initialization:**

When no persisted epoch is available (cold boot without flash, or flash read
failure), implementations MUST initialize epoch to a random value uniformly
distributed in [128, 255]. This reduces the probability of reusing a tuple
when no prior counter state exists, but does not prove freshness. A receiver
with replay state for the same key MUST apply the normal numeric acceptance
rules and can reject the randomized value. If the sender cannot establish a
counter above its last use, it MUST rotate its link key before transmitting.

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

A lower epoch is always stale. Within the current epoch, a decrease from a
high SeqNum to a low SeqNum is evaluated only as an old or out-of-window
packet; it MUST NOT be interpreted as sequence-number wrap.

**Wrap Behavior:**

At ~1 packet/second, 16-bit seqnum wraps every ~18 hours (per spec/02a-coordinated-capacity.md §2a.2 for SFN/now() unsigned modular arithmetic validated by ccp16.json). The epoch
increment ensures the 24-bit logical counter advances monotonically.
At maximum traffic (10 pkt/sec), epoch wraps in ~7.5 years--acceptable.

**Reboot Resilience:**

With persisted state, a rebooted node resumes at a greater unused tuple, for
example by incrementing EPO and starting SeqNum at zero. Without persisted
state, random initialization does not guarantee acceptance by receivers that
retain replay state; key rotation is required when freshness cannot otherwise
be established. No time synchronization is required.

---

[← Previous: Architecture](01-architecture.md) | [Index](README.md) | [Next: Adaptation Layer →](03-adaptation.md)

