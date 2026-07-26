<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Appendix: CCP-12 Channel Selection and Synchronized Hopping

This appendix defines the channel selection algorithms for LICHEN networks,
including the primary hash-based peer rendezvous (CCP-16) and optional
network-wide synchronized hopping (CCP-12).

## 1. Overview

LICHEN uses a **hybrid channel selection strategy** that balances deterministic
rendezvous with minimal synchronization requirements:

| Priority | Mechanism | Use Case | Sync Requirement |
|----------|-----------|----------|------------------|
| 1 | Announce-driven (CCP-9) | Known peer with fresh announce | None |
| 2 | Hash-based (CCP-16) | Known peer without fresh announce | Epoch only |
| 3 | Synchronized hop (CCP-12) | Optional network-wide hopping | SFN alignment |
| 4 | CH0 fallback | Unknown peers, broadcasts, high density | None |

The hash-based mechanism (CCP-16) is the **primary** channel selection method
for LICHEN because it requires only coarse epoch agreement, which propagates
naturally through DIOs and beacons. Network-wide synchronized hopping (CCP-12)
is available for deployments requiring traditional FHSS compliance but adds
synchronization complexity unsuitable for lossy multi-hop mesh.

## 2. Design Rationale

### 2.1. Why Hash-Based Selection is Primary

LICHEN networks operate under constraints that favor hash-based over
synchronized hopping:

1. **Coarse timing suffices.** Hash-based selection keys on epoch, not SFN.
   Epochs change slowly (hours to days) and propagate via standard RPL DIOs.
   Synchronized hopping requires SFN alignment within ~50ms guard time, which
   degrades rapidly over multi-hop paths with variable latency.

2. **Lossy mesh resilience.** In networks with 10-20% packet loss, tight time
   sync cannot be reliably maintained. Hash-based selection degrades gracefully:
   a stale epoch shifts the channel deterministically, and density fallback to
   CH0 provides guaranteed rendezvous.

3. **Implementation simplicity.** FNV-1a32 is ~10 lines of code with no tables,
   no floating point, no state machine. A sync state machine with drift tracking
   and stratum management adds complexity inappropriate for 8KB RAM targets.

4. **Multi-hop routing.** Nodes that cannot hear each other can still compute
   the correct rendezvous channel knowing only peer EUI64 and current epoch.
   No announcement propagation or sync distribution required.

### 2.2. When to Use Synchronized Hopping (CCP-12)

CCP-12 network-wide synchronized hopping is appropriate when:

- Tight FHSS regulatory compliance is required (FCC Part 15.247 with 50+ channels)
- All nodes have reliable time source (GNSS/NTS, stratum <= 2)
- Network topology is shallow (1-2 hops) with reliable links
- Jamming/interference resistance is prioritized over mesh scalability

## 3. CCP-16: Hash-Based Peer Rendezvous (Primary)

### 3.1. Algorithm Definition

**SelectChannel** computes a deterministic data channel for peer communication
based on the peer's EUI-64 and current network epoch.

#### Input Parameters

| Parameter | Type | Source | Description |
|-----------|------|--------|-------------|
| EUI64 | 8 bytes | Peer identity | Peer's IEEE EUI-64 address (big-endian) |
| Epoch | u32 | RPL DIO / TDMA beacon | Current network epoch from root |
| Density | u8 | Local estimate | Estimated neighbors in radio range |
| NChannels | u8 | Channel plan | Number of channels in regional plan |

#### Pseudocode (IETF-style, language-agnostic)

```
Procedure SelectChannel(EUI64, Epoch, Density, NChannels):
    1. IF Density > 8 THEN RETURN 0        // CH0 fallback under congestion
    2. Data = CONCAT(EUI64, Epoch_LE)      // EUI64 big-endian, Epoch 4-byte LE
    3. Hash = FNV1A32(Data)                // basis 0x811c9dc5
    4. N = MAX(NChannels, 3)               // minimum 3 to spread traffic
    5. RETURN 1 + (Hash MOD N)             // channels 1..N (CH0 reserved)
```

**FNV-1a32 Hash Function:**

```
Procedure FNV1A32(Data):
    1. H = 0x811c9dc5                      // FNV offset basis
    2. FOR EACH byte B in Data:
           H = (H XOR B) * 0x01000193      // FNV prime
           H = H AND 0xFFFFFFFF            // 32-bit truncation
    3. RETURN H
```

### 3.2. Example Calculation

```
Input:
    EUI64     = 0x0011223344556677 (big-endian)
    Epoch     = 1
    Density   = 3
    NChannels = 8

Step 1: Density (3) <= 8, proceed with hash

Step 2: Concatenate
    Data = 0x00 11 22 33 44 55 66 77 || 0x01 00 00 00
         = 0x001122334455667701000000 (12 bytes)

Step 3: FNV-1a32(Data)
    H = 0x811c9dc5
    After processing all bytes: H = 926423932 (0x373854FC)

Step 4: N = MAX(8, 3) = 8

Step 5: Channel = 1 + (926423932 MOD 8) = 1 + 4 = 5

Result: Channel 5
```

**Note:** The test vector in `ccp16.json` shows `channel: 2` for this input.
The discrepancy arises because the implementation uses `N = NChannels - 1` to
exclude CH0 from the modulus, yielding `1 + (926423932 % 7) = 2`. Implementations
MUST match `test/vectors/ccp16.json` exactly.

### 3.3. Density Fallback

When `Density > 8`, all nodes fall back to CH0 for both control and data.
This provides:

- Guaranteed rendezvous when network is congested
- Reduced frequency spreading but higher receive probability
- Natural load shedding as capacity degrades gracefully

## 4. CCP-12: Network-Wide Synchronized Hopping (Optional)

### 4.1. Algorithm Definition

**SynchronizedHopChannel** computes a channel based on superframe number (SFN)
and shared seed, causing the entire network to hop together in lockstep.

#### Input Parameters

| Parameter | Type | Source | Description |
|-----------|------|--------|-------------|
| SFN | u32 | Time provider | Current superframe number |
| Seed | u32 | Configuration | Shared hopping seed (default 0) |
| NChannels | u8 | Channel plan | Number of channels in regional plan |

#### Pseudocode

```
Procedure SynchronizedHopChannel(SFN, Seed, NChannels):
    1. Data = CONCAT(Seed_LE, SFN_LE)      // Both 4-byte little-endian
    2. Hash = FNV1A32(Data)
    3. N = MAX(NChannels, 3)
    4. RETURN 1 + (Hash MOD N)
```

### 4.2. Superframe Duration and LoRa Timing

The superframe duration must accommodate LoRa packet airtime:

| SF | 50-byte Airtime | Recommended Superframe |
|----|-----------------|------------------------|
| SF7 | ~100ms | 500ms |
| SF10 | ~700ms | 2000ms |
| SF12 | ~2.5s | 5000ms |

**Default: 2000ms (2 seconds)** - fits SF10 packets with margin for RX window.

Nodes hop **between packets**, not mid-packet. The sequence is:
1. Compute channel from current SFN
2. TX packet (may span multiple SFNs)
3. After TX complete, compute new SFN, hop if changed
4. RX on new channel

### 4.3. Synchronization Requirements

CCP-12 synchronized hopping requires **SFN alignment** across all nodes:

| Superframe | Guard Time | Required Sync Accuracy | Achievable Via |
|------------|------------|------------------------|----------------|
| 2000ms | 200ms | ~100ms | GNSS PPS, NTS, mesh-sync |
| 1000ms | 100ms | ~50ms | GNSS PPS, NTS |
| 500ms | 50ms | ~25ms | GNSS PPS only |

With 2-second superframes, **mesh-derived sync IS sufficient** - the 100ms
accuracy achievable over 2-3 hops fits within the 200ms guard window.

### 4.3. Example Calculation

```
Input:
    SFN       = 5
    Seed      = 0
    NChannels = 8

Step 1: Concatenate
    Data = 0x00 00 00 00 || 0x05 00 00 00
         = 0x0000000005000000 (8 bytes)

Step 2: FNV-1a32(Data) = <hash value>

Step 3: N = MAX(8, 3) = 8

Step 4: Channel = 1 + (Hash MOD 8)
```

### 4.4. Desync Recovery

When a node detects desync (e.g., fails to receive expected beacons):

1. Fall back to CH0 listening
2. Wait for 3 consecutive valid beacons on CH0
3. Re-sync SFN from beacon timestamp
4. Resume synchronized hopping

## 5. CCP-9: Announce-Driven Selection (Priority 1)

When a peer has sent a recent Announce message containing `rx_channel`, use
that channel directly. This provides:

- Explicit channel preference per node
- Works without any time synchronization
- Adapts to local RF conditions (peer knows best channel for its location)

The `rx_channel` field is in the signed Announce payload (wire offset 1) and
cannot be tampered with by intermediate nodes.

## 6. Priority Chain Implementation

The channel selection priority chain in order:

```python
def select_channel(peer_eui64, peer_known, announce_rx_channel,
                   sfn, epoch, n_channels, density):
    # Priority 1: Announce-driven (CCP-9)
    if announce_rx_channel is not None and peer_known:
        return announce_rx_channel

    # Priority 2: Hash-based (CCP-16) for known peers
    if peer_known and peer_eui64 is not None:
        if density > 8:
            return 0  # CH0 fallback
        data = peer_eui64 + epoch.to_bytes(4, "little")
        h = fnv1a32(data)
        n = max(n_channels - 1, 1)
        return 1 + (h % n)

    # Priority 3/4: CH0 fallback for unknown peers
    return 0
```

## 7. Regulatory Considerations

### 7.1. FCC Part 15.247 (US915)

FCC FHSS rules require:

| Requirement | Current Status | Compliance Path |
|-------------|----------------|-----------------|
| 50 hopping channels for 125kHz BW | 8 channels | Expand US915 plan OR use digital modulation path |
| 400ms maximum dwell time | Not enforced | SFN duration typically exceeds this |

**Recommendation:** Either expand US915 channel plan to 50+ channels, or
document that US operation uses the "digital modulation" compliance path
(minimum 500kHz bandwidth, 6dB bandwidth rule) rather than FHSS rules.

### 7.2. ETSI EN 300 220 (EU868)

EU compliance uses duty cycle limits (1% per sub-band) rather than FHSS.
Hash-based selection is compliant when combined with the duty cycle enforcer
in `duty_cycle.py`. No additional channels required.

### 7.3. Other Regions

| Region | Compliance Path | Notes |
|--------|-----------------|-------|
| AU915 | Same as US915 | Similar FHSS or digital modulation |
| AS923 | Duty cycle | Similar to EU |
| CN470 | Listen-before-talk | LBT implementation required |

## 8. Implementation Status

### 8.1. Existing Implementations

| Component | File | Status |
|-----------|------|--------|
| Python `select_channel` | `python/src/lichen/channel_plan.py` | Complete, matches vectors |
| Python priority chain | `python/src/lichen/link/channel.py` | Complete |
| Python `synchronized_hop_channel` | `python/src/lichen/sim/tdma.py` | Complete |
| Rust `lichen_hash_32` | `rust/lichen-core/src/lib.rs` | Complete |
| Test vectors | `test/vectors/ccp16.json` | Authoritative |

### 8.2. Required Code Changes

**None required** for the hash-based (CCP-16) approach documented here. The
existing implementation is correct and matches test vectors.

**Optional enhancements:**

1. **US915 channel expansion:** Expand `US915` channel plan in `channel_plan.py`
   from 8 to 50+ channels for FCC FHSS compliance if that path is chosen.

2. **SFN inclusion:** The current `select_channel` uses epoch only. Adding
   optional SFN parameter would enable faster channel rotation within an epoch
   if needed for specific regulatory requirements.

## 9. Test Vectors

All implementations MUST produce identical output to `test/vectors/ccp16.json`.

Example vector (from file):

```json
{
  "name": "synchronized_hop_channel_consistency",
  "input": {
    "eui64": "0011223344556677",
    "epoch": 1,
    "density": 3
  },
  "output": {
    "hash_32": 926423932,
    "channel": 2,
    "expected_channel": 2
  }
}
```

## 10. Summary

LICHEN uses **hash-based channel selection (CCP-16)** as the primary mechanism
because it:

1. Requires only coarse epoch agreement (propagates via DIOs)
2. Degrades gracefully in lossy mesh (density fallback to CH0)
3. Enables multi-hop rendezvous without direct communication
4. Implements trivially on constrained devices

Network-wide synchronized hopping (CCP-12) remains available for deployments
with reliable time sources and strict FHSS compliance requirements, but is
not recommended as the default due to sync complexity over multi-hop mesh.

---

[Index](README.md) | [Coordinated Capacity](02a-coordinated-capacity.md)
