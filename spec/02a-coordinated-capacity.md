<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Coordinated Capacity Protocol (CCP)

## Abstract

The Coordinated Capacity Protocol (CCP) defines mechanisms for coordinated capacity management in LICHEN LoRa meshes. This includes TDMA slot assignment, channel agility via select_channel with density-aware fallback, adaptive spreading factor selection via adaptive_sf_select (incorporating EMA-smoothed SNR and load_factor), time synchronization via now(), CH0 control channel rules, signed rx_channel for CCP-9 da2q rendezvous, density/load rules, capability signaling in DIOs, and desynchronization recovery.

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, and `l2_payload.json`:
- TDMA beacon byte layout, CDDL, SCHC rule 0x08, slot/hash, SFN wrap, join flows, epoch/num_slots per 2a.2
- vectors for CCP-16/14 slot, SF, channel, tx_allowed, Multi-RX, capacity metrics (independent oracle: FNV-1a + SX126x airtime + multi-channel sim).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Beacon Format, Slots, Hash Selection, and Join (SCHC 0x08, CDDL, byte layout)
4. 2a.3. Channel Agility (select_channel, now())
5. 2a.4. Time Synchronization
6. 2a.5. Desync Recovery State Machine
7. 2a.6. Regional Channel Plans and CH0 Rules
8. 2a.7. Adaptive Spreading Factor Selection (adaptive_sf_select)
9. CCP-12. Synchronized Channel Hopping (SelectChannel, hash_32, test vectors)
10. Implementation Status
11. References

## Overview

The LICHEN mesh coordinates capacity across multiple nodes sharing a finite set of radio channels and time slots. Without coordination, concurrent transmissions on the same channel cause repeated collisions, wasting energy and airtime. CCP integrates with the TDMA frame structure from [LICHEN Link Layer](02-physical-link.md) and the RPL DODAG from [spec/05-routing](05-routing.md).

CCP provides:
- **CCP-4:** Regional channel plans and CH0 fallback
- **CCP-9:** Rendezvous announcements for directed traffic
- **CCP-12:** Synchronized channel hopping via `SelectChannel`/`hash_32`
- **CCP-14:** TDMA slot assignment with SFN epoch scheduling
- **CCP-15:** Load-aware spreading factor selection
- **CCP-16:** Integrated capacity decisions (slot + SF + channel)

Signature verification (Ed25519/48-byte Schnorr) applies to link-layer frames per [spec/07-security](07-security.md). All CCP references in this document follow CCP-16, using Schnorr signatures (spec draft-lichen-schnorr-00, 48-byte). SCHC compression rules for CCP control payloads are defined in [spec/appendix-schc](appendix-schc.md).

The CCP operational state machine (IDLE, LISTENING, JOINING, JOINED, DENSE, DESYNC) is defined in [spec/02-physical-link.md §2.6](02-physical-link.md#26-link-layer-state-machine).

## 2a.1. TDMA Beacon Format, Slots, Hash Selection, and Channel Dwelling

A node selects a slot in the TDMA epoch using `hash_32(EUI64 || Epoch) mod num_slots`. The beacon format (SCHC Rule 0x08) carries: EUI64, SFN, epoch, num_slots, CH0, next_beacon_time, rx_channel for CCP-9 rendezvous, SF10 capability, and a 32-byte Schnorr signature truncated to 48 bytes (Ed25519 base, spec draft-lichen-schnorr-00). The CDDL for the beacon is:

```cddl
tdma-beacon = {
  eui64: bytes .size 8,
  sfn: uint32,
  epoch: uint32,
  num-slots: uint8,
  ch0: uint8,
  next-beacon-time: uint32,
  rx-channel: uint8,         ; CCP-9 rendezvous channel (0 = CH0)
  sf10-capable: bool,
  signature: bytes .size 48  ; Schnorr48
}
```

SFN (Slot Frame Number) is a free-running 32-bit counter that advances with each TDMA slot. The TDMA frame uses a fixed timebase: `slot_duration = max_airtime(current_SF) + 100 ms guard`. All nodes synchronize to a reference SFN as follows:

- **Absolute SFN** is obtained via GPS timestamp (PPS-based, RTC drift compensated).
- **Relative SFN** is obtained via beacon reception from a DODAG root: the beacon includes the root's current SFN; the receiving node computes its own SFN as `beacon_sfn + (elapsed_slots_since_beacon)`.
- **Beacon loss** triggers desync recovery state machine (see 2a.5).
- **Test vectors** in `ccp16.json` and `ccp_tdma.json` MUST cover SFN wrap around boundary (`0xFFFFFFFF → 0`) with correct unsigned modular arithmetic.

Beacons are transmitted on CH0 at a rate proportional to `RPL_DIO_INTERVAL` (Trickle-minimum). In DENSE state (≥20 nodes), beacon rate doubles to maintain synchronization stability.

A node MUST validate received beacons: verify the 48-byte Schnorr signature against the root's Ed25519 public key (TOFU on first contact, per spec/07-security §7.5), check SFN monotonic increase (with wrap-around handling), and drop beacons with stale epochs.

### Slot Assignment and Hash Selection (CCP-14)

Each node selects one transmission slot per epoch:

```
slot = hash_32(EUI64 || EPOCH_LE) mod num_slots
```

Where `EPOCH_LE` is the epoch counter as a 4-byte little-endian u32 and `hash_32` is FNV-1a32 (basis `0x811c9dc5`; see [hash_32 definition](#ccp-12-synchronized-channel-hopping-selectchannel-hash_32-test-vectors) and canonical vectors in `test/vectors/hash_32.json`).

**SF change across an epoch boundary:**
When a node's SF changes due to adaptive SF selection, the slot assignment remains tied to the epoch, not the SF. Slot duration always uses `max_airtime(SF=7)` for the guard calculation to prevent adjacent-slot overlap when higher SFs appear later.

### Channel Dwelling (CCP-12)

Between beacon receptions, a node dwells on one channel for the full inter-beacon interval. The channel is selected by `SelectChannel(EUI64, SFN, Density, NChannels)` (see [CCP-12 pseudocode](#ccp-12-synchronized-channel-hopping-selectchannel-hash_32-test-vectors)). Nodes with no pending TX and no directed RX expectation MAY enter low-power receive mode on CH0 only.

### SFN Wrap

When SFN wraps from `0xFFFFFFFF` to `0x00000000`, all hash-based selections (slot, channel) reset deterministically. The beacon carries the post-wrap SFN. Comparison operators for "elapsed since last beacon" MUST use unsigned modular arithmetic as defined in `Now()` (see [CCP-12 pseudocode](#ccp-12-synchronized-channel-hopping-selectchannel-hash_32-test-vectors)).

This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json and ccp_tdma.json MUST cover this and similar boundaries.

A node MUST only transmit in its assigned slot. Slot duration = max_airtime(current_SF) + 100 ms guard. The link layer MUST enforce via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link implementation). This integrates with TDMA and SCHC compressed control traffic on CH0.

## CCP-4. Regional Channel Plans

A regional channel plan MUST be provisioned locally. An over-the-air message MUST NOT expand the local plan, increase transmit power, or relax regulatory limits.

Each versioned plan contains:
- plan identifier and version;
- ordered channel entries, with CH0 at index zero;
- center frequency, bandwidth, spreading factors, coding rates, and maximum power allowed for each entry;
- regulatory accounting group for each channel;
- applicable duty-cycle, dwell-time, occupancy, and listen-before-talk rules;
- hardware-specific permitted channel mask.

CCP PHY profile ID `0x01` is fixed as LoRa bandwidth 125 kHz, SF10, coding rate 4/5, eight-symbol preamble, explicit header, payload CRC enabled, and low-data-rate optimization disabled. ADR MUST NOT change these parameters inside a schedule generation. See [CCP-12 pseudocode](#ccp-12-synchronized-channel-hopping-selectchannel-hash_32-test-vectors) for normative adaptive SF outside schedules. Future profile IDs require canonical airtime vectors and a new specification revision before use.

Remote capability and schedule messages MAY reduce the locally permitted intersection. Unknown plan identifiers or versions MUST cause CH0 fallback.

## 2a.3. Channel Agility and Adaptive SF

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00 and draft-lichen-rpl-lora-00). Announce messages carry rx_channel (CCP-9 per spec/05-routing.md:9.2) for rendezvous. Data channels selected via `SelectChannel()` or hash. All implementations MUST produce identical results to test vectors in `ccp16.json`, `ccp9*.json`, `ccp_load_balancing.json`.

### 2a.3.1. Pure Pseudocode Definitions (IETF-style, language agnostic)

Procedure Now():
   1. RETURN current SFN value.
   2. All subtractions, comparisons, and MOD operations MUST use unsigned 32-bit modular arithmetic (modulo 2^32) to handle wraparound correctly per test vectors.

Procedure SelectChannel(EUI64, Epoch, Density, NChannels):
   1. IF Density > 8 THEN RETURN 0
   2. Data = CONCAT(EUI64 as BE bytes, Epoch as LE u32 bytes)
   3. Hash = FNV1A32(Data)  // basis 0x811c9dc5; matches hash_32.json and ccp16.json vectors
   4. N = MAX(NChannels, 3)
   5. RETURN 1 + (Hash MOD N)

### 2a.7. Adaptive Spreading Factor Selection (per 8gac)

SF10 is the REQUIRED baseline for moderate density (5-20 nodes). Density-aware adaptation and per-neighbor EMA (alpha = 1/4) override only on explicit thresholds. Load_factor from gateway DIOs takes precedence. All paths MUST match ccp16.json and ccp_load_balancing.json exactly (independent oracle).

**Thresholds Table:**

| SF | Sensitivity | Upgrade Condition (SHOULD) | Downgrade Condition (MUST) |
|----|-------------|----------------------------|----------------------------|
| 7  | -123 dBm   | N/A                        | SNR < 0 OR loss > 0.25    |
| 9  | -129 dBm   | Density < 5 AND SNR_EMA > 8 | SNR < 0 OR Density > 8    |
| 10 | -132 dBm   | DEFAULT (moderate density) | SNR < 0 OR load_factor > 0.8 |
| 11 | -134 dBm   | N/A                        | Density > 8 OR SNR_EMA < 0 OR load > 0.8 |
| 12 | -137 dBm   | N/A                        | Density > 20 OR SNR_EMA < -5 |

Procedure AdaptiveSFSelect(AssignedSF, Neighbor, Density, Utilization, LoadFactor):
   1. SF = AssignedSF
   2. IF SF absent THEN SF = 10
   3. IF (Density > 10) OR (Utilization > 150) THEN SF = MIN(12, SF + 2)
   4. IF (Neighbor.EMA_SNR > 8) AND (Density < 5) THEN SF = MAX(7, SF - 1)
   5. IF (Neighbor.EMA_Loss > 0.25) OR (Utilization > 200) THEN
         SF = MIN(12, SF + 1)
         IF Utilization > 200 THEN RETURN (SF, false)  // tx not allowed
   6. RETURN (SF, true)

EMA_Update(Avg, Sample) = Avg + ((Sample - Avg) right-shift 2). Update per-neighbor state on every RX. Integrate with RPL DIO capability signaling. No dead code.

(The state machine from prior section remains; JOINED uses SelectChannel and AdaptiveSFSelect per schedule.)

## CCP-12. Synchronized Channel Hopping (SelectChannel, hash_32, test vectors)

CCP-12 defines the synchronized channel hopping mechanism that enables deterministic channel selection across all nodes in a LICHEN mesh. All nodes independently compute the same channel for a given (EUI64, Epoch, Density, NChannels) tuple, enabling rendezvous without explicit signaling.

### Algorithm

Channel selection uses the `SelectChannel` procedure defined in [2a.3.1](#231-pure-pseudocode-definitions-ietf-style-language-agnostic):

```
Channel = SelectChannel(EUI64, Epoch, Density, NChannels)
```

The core hash primitive is `lichen_hash_32` (FNV-1a32, basis `0x811c9dc5`, multiplier `0x01000193`, modulo `2^32`), defined in:

| Implementation | Location |
|----------------|----------|
| Canonical test vectors | `test/vectors/hash_32.json` |
| Rust | `rust/lichen-core/src/lib.rs` — `pub fn lichen_hash_32(data: &[u8]) -> u32` |
| Python | `python/src/lichen/sim/tdma.py` — `def hash_32(data: bytes) -> int` |
| Vector generator | `test/vectors/generate.py` — `def hash_32(data: bytes) -> int` |
| C (Zephyr) | `lichen/subsys/lichen/link/link_ctx.c` — `uint32_t lichen_hash_32(...)` |
| C declaration | `lichen/subsys/lichen/link/include/lichen/link.h` (line 332) |

### Cross-References

- **hash_32 test vectors**: `test/vectors/hash_32.json` — canonical FNV-1a32 outputs (empty input, "test", 32 zero bytes)
- **CCP-12 hop vectors**: `test/vectors/ccp16-hop.json` — synchronized hop vectors matching `SelectChannel` pseudocode (SFN=0, SFN=1, SFN wrap, density fallback, rendezvous)
- **CCP-16 integration**: `test/vectors/ccp16.json` — full integrated capacity decision vectors that exercise CCP-12 channel selection
- **TDMA slot selection**: `test/vectors/ccp_tdma.json` — TDMA slot vectors using `hash_32`
- **CCP-9 rendezvous**: `test/vectors/ccp9.json`, `test/vectors/ccp9_rendezvous.json` — rendezvous announcements referencing `synchronized_hop_channel(CCP-12)`
- **Load balancing**: `test/vectors/ccp_load_balancing.json` — load factor vectors using `hash_32`

### Implementation Requirements

1. All implementations MUST produce identical `SelectChannel` outputs for the test vectors in `test/vectors/ccp16-hop.json`.
2. All implementations MUST use the identical `lich_hash_32` (FNV-1a32) as defined in `test/vectors/hash_32.json`.
3. Density > 8 MUST return CH0 (channel index 0).
4. SFN wraparound MUST use unsigned modular arithmetic as defined in `Now()`.
5. Rendezvous announcements in beacons and DIOs MAY override the hash-selected channel with the announced `rx_channel` (CCP-9).

## Regional Channel Plans and CH0 Rules

- Python simulator, Rust gateway, Zephyr `lichen/subsys/lichen` validate against `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json`.
- Kconfig options for CCP16, TDMA_SLOTS, integration with RPL/SCHC/TDMA complete. SCHC Rule 0x08 for TDMA beacon implemented.
- Adaptive SF, desync FSM, channel plans, Multi-RX gateway support implemented and tested.
- All codereview passes closed. Capacity gains verified in simulation per independent oracles.

## References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

- `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json` (authoritative for TDMA beacon format, CDDL, byte layout, slot/hash, join flows, SFN wrap; MUST match exactly)

- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/drafts/draft-lichen-schc-lora-00.md`
- `spec/appendix-design-rationale.md`
- `spec/appendix-schc.md` (Rule 0x08=TDMA_BEACON)
- `lichen/subsys/ichen/link*` (for `lichen_link_set_slot()`, `tdma_tx_allowed()`)
- `docs/firmware-time-provider.md`
- `spec/drafts/draft-lichen-link-01.md` (L2 0x15 join frame)

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
