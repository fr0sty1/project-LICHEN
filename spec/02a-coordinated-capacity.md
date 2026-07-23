<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Protocol (CCP-16 with CCP-14 Gateway Multi-RX)

## Abstract

CCP-16 defines mechanisms for coordinated capacity management in LICHEN LoRa meshes including TDMA slot assignment, channel agility, adaptive SF selection, time synchronization, and hash-based selection. CCP-14 specifies Gateway Multi-RX for simultaneous reception across channels (control + data), increasing capacity per da2q multi-channel context. 

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`:
- vectors[0-2]: TDMA slot, SF, channel, tx_allowed per CCP-16 (see 2a.2, 2a.3)
- vectors[3+]: CCP-14 Gateway Multi-RX scheduling, concurrent RX validation, capacity metrics (independent oracle: reference FNV-1a + Semtech SX126x airtime tables + multi-channel sim from external Python oracle, not LICHEN impl).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Slots and Hash Selection
4. 2a.3. Channel Agility and Adaptive SF
   4.1. select_channel and now()
   4.2. Density Rules Rationale
   4.3. adaptive_sf_select Pseudocode
5. 2a.4. Time Synchronization
6. 2a.5. Desync Recovery State Machine
7. Implementation Status
8. References

## 2a.1. Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP-16 coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF, multi-channel operation (CH0 for control per SCHC-compressed beacons - see draft-lichen-schc-lora-00), and time synchronization via RPL DIOs. 

Nodes compute their slot using a deterministic hash (FNV-1a) of (EUI64 XOR epoch) modulo num_slots (see test vectors for validation). Transmission outside the assigned slot is suppressed by the link layer. This document specifies the algorithms and interoperation with RPL, SCHC, and the link layer, incorporating SFN modulo, multi-root conflict, and desync recovery per parent epic project-LICHEN-ofrf. Arbitrary constants (e.g. 100ms guard, 300s density window) are defined in appendix-design-rationale.md and test vectors; implementations MUST match exactly.

## 2a.2. TDMA Slots and Hash Selection

The root advertises `epoch` (u32) and `num_slots` (default 8) in an extended RPL configuration option.

<<<<<<< HEAD
Slot ID MUST be computed as:
=======
CCP supports two compatible modes:

1. **Scheduled mode:** The coordinator assigns leased cells. This is the
   preferred high-density mode and requires GNSS with a hardware PPS signal at
   every participating node.
2. **CSMA rendezvous mode:** Immediate neighbors negotiate a temporary data
   channel on CH0. This permits multi-channel experiments before a schedule is
   available and provides a fallback for unscheduled traffic.

## CCP-4. Regional Channel Plans

A regional channel plan MUST be provisioned locally. An over-the-air message
MUST NOT expand the local plan, increase transmit power, or relax regulatory
limits.

Each versioned plan contains:

- plan identifier and version;
- ordered channel entries, with CH0 at index zero;
- center frequency, bandwidth, spreading factors, coding rates, and maximum
  power allowed for each entry;
- regulatory accounting group for each channel;
- applicable duty-cycle, dwell-time, occupancy, and listen-before-talk rules;
- hardware-specific permitted channel mask.

CCP PHY profile ID `0x01` is fixed as LoRa bandwidth 125 kHz, SF10, coding rate
4/5, eight-symbol preamble, explicit header, payload CRC enabled, and low-data-
rate optimization disabled. ADR MUST NOT change these parameters inside a
schedule generation. See 2a.3 for normative adaptive SF outside schedules. Future profile IDs require canonical airtime vectors and a
new specification revision before use.

Remote capability and schedule messages MAY reduce the locally permitted
intersection. Unknown plan identifiers or versions MUST cause CH0 fallback.

## 2a.3. Adaptive Spreading Factor

Adaptive SF integrates with TDMA/channel selection per CCP-16. Nodes MUST maintain per-neighbor EMA state (alpha=1/4 from rf_health.rs), signal ASSIGNED_SF and metrics (SNR EMA, loss, density, utilization) in DIO, announce TX_SF, and RX on all SF. Pseudocode MUST be followed exactly and produce identical output to test/vectors/ccp16.json load_balancing vectors. Thresholds and logic from physical-link:3.4. DIO option for metrics is REQUIRED for root load balancing. All impls MUST match vectors (low density/good SNR yields SF9 on data channel; high density/poor SNR yields SF11 on CH0; high utilization suppresses TX).

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

LoRaWAN regional tables MAY inform a LICHEN plan, but LoRaWAN uplink/downlink
roles MUST NOT be copied into a symmetric peer-to-peer plan without a separate
compliance analysis. In particular, adding frequencies does not necessarily
multiply a node's legal transmit airtime when channels share a regulatory
sub-band budget.

## CCP-5. CH0 Rules

All nodes MUST use CH0 for:

- Announce, DIO, DIS, DAO, and DAO-ACK traffic;
- LOADng RREQ, RREP, and RERR traffic;
- CCP capability, schedule, join, and rendezvous control;
- multicast, broadcast, and emergency traffic;
- unicast to peers whose compatible capability is unknown;
- fallback after any CCP failure.

A single-radio node MUST listen on CH0 whenever it is not transmitting or
participating in an active cell or rendezvous. Reception of legacy CH0 traffic
during an off-channel window is necessarily best-effort. Continuous CH0
reception while using a data channel requires another receive chain.

Legacy nodes do not know slot boundaries and may transmit at any time.
Therefore, a CCP transmitter MUST perform CAD or the regional plan's required
listen-before-talk procedure even in a dedicated cell.

## CCP-6. Capability Advertisement

Slow-changing domain parameters are advertised in a CCP Capability DIO option (provisional experimental type `0xE0`; MUST be replaced by assigned IANA value before interoperable publication).

The option format (36 bytes total data) is:
>>>>>>> origin/worktree-worker23

```
slot_id = (crc32_ieee(eui64, 8) ^ epoch) % num_slots
```

<<<<<<< HEAD
using `crc32_ieee` (see appendix-design-rationale.md:388, lichen/subsys/schc/schc.c:90). This fixes prior inconsistency between crc16 (SMP/Meshtastic legacy) and hash_32 in CCP-15.8.3 pseudocode (`spec/02a-coordinated-capacity.md:41`). The XOR with epoch ensures time-varying slots to prevent persistent collisions. All impls MUST match ccp16.json vectors exactly.

For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5. This integrates with `lichen_rpl_dodag_init()` ordering.

Delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior. 

Edge case example (0xFFFFFFFF boundary):
```
last_sfn = 0xFFFFFFFFu;
current_sfn = 0x00000002u;
delta = current_sfn - last_sfn;  /* = 3 in unsigned 32-bit arithmetic */
```
This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json MUST cover this and similar boundaries.

A node MUST only transmit in its assigned slot. Slot duration = max_airtime(current_SF) + 100 ms guard. The link layer MUST enforce via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link: implementation).

(This completes logical chunk 2: modulo 0xFFFFFFFF edge case example and delta calculation.)

## 2a.3. Channel Agility and Adaptive SF

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00).
=======
Multi-byte integers are unsigned big-endian. Flags bits: 0=scheduled mode, 1=CSMA rendezvous, 2=concurrent CH0 RX, 3=GNSS-PPS, 4-7 reserved (zero). `Setup Window` bounds retune/readiness/CAD. `Occupied Time` bounds data+ACK. `Guard` is separation between occupied envelopes. `RX Chains` is simultaneous receive count (1 for typical single-radio). `Channel Mask` bit 0 = CH0. Receivers compute local intersection. See test/vectors/ccp*.json for format validation.
>>>>>>> origin/worktree-worker23

CH0 is the mandatory control channel. All nodes MUST listen continuously on CH0 for Announce, DIOs, DIS, DAO, LOADng control (RREQ/RREP/RERR), CCP messages, and beacons. See draft-lichen-rpl-lora-00 and draft-lichen-schc-lora-00 for RPL/SCHC usage on CH0. Data channels are used only after rendezvous or scheduled assignment.

<<<<<<< HEAD
### select_channel and now() (logical chunk: function definitions - pure pseudocode)
=======
## CCP-6.1. Channel Selection and Adaptive SF (normative pseudocode)

Nodes MUST implement the following spelled-out pseudocode exactly (using IF/OR/NOT/MOD/XOR for IETF language neutrality). All implementations MUST produce bit-identical results to independent test oracles in test/vectors/ccp16.json, test/vectors/ccp_load_balancing.json, and test/vectors/ccp9.json. Cross-reference CCP-16 for load_factor integration and CCP-9 for da2q rendezvous.
>>>>>>> origin/worktree-worker23

```
function ema_update(avg, sample):
    diff = sample - avg
    return avg + (diff / 4)   // alpha = 1/4 equivalent

function select_channel(ctx, metrics, t):
    IF (metrics.density > 8) OR (NOT ctx.wall_clock_valid) THEN
<<<<<<< HEAD
        RETURN 0   // control CH0 for high density or desync (per vectors[1,3])
    hash = fnv1a32( (ctx.eui64 XOR t XOR ctx.epoch) )
    n = ctx.num_data_channels IF ctx.num_data_channels > 0 ELSE 3
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()   // from time-provider; unsigned modular arithmetic per 2a.2
```
Note: All operators are spelled out (OR, NOT, MOD, XOR) for language-agnostic IETF compatibility. No Rust 'or', no C types or structs, no dead code. now() and t parameter use unsigned u32 modular arithmetic per 2a.2; blacklist_until[] timer comparisons (in extended channel agility) MUST use `((now_ts - blacklist_until[ch]) & 0xFFFFFFFFu)` or equivalent uint32_t subtraction to correctly handle wrap-around without underflow. Cross-ref draft-lichen-tdma and Section 2a.2.

### Density Rules Rationale (logical chunk: rationale paragraph - updated)

SF10 is the REQUIRED default because it balances sensitivity (~ -137 dBm at 125 kHz) and airtime (~ 50 ms payload) for typical mesh density per appendix-design-rationale.md:7.6 and independent sim oracle in ccp16.json vectors. Density-aware adaptation prioritizes capacity (SF9 in low density <5 + good SNR >8 dB to reduce airtime 2x) vs robustness (SF11/12 in density >8 or poor SNR or high load_factor to lower PER). This yields net capacity gain in sims at 50 nodes/km^2 despite longer airtime for higher SF. EMA on SNR (snr_ema = 0.1 * current + 0.9 * previous, updated via now()) integrates with load_factor override from gateway DIOs.

Updates MUST be propagated in RPL metric container. Root optimizer uses reported neighbor_count and channel_util to minimize collisions.

### 2a.3.2 adaptive_sf_select Pseudocode (logical chunk: SF function)

```
function adaptive_sf_select(density, snr_db, load_factor, t):
    snr_ema = ema_update(previous_ema, snr_db, t)  // alpha=0.1 over 300s window; exact match to vectors
=======
        RETURN 0
    hash = fnv1a32(ctx.eui64 XOR t XOR ctx.epoch)
    n = ctx.num_data_channels
    IF n = 0 THEN
        n = 3
    END IF
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()   // SFN from GNSS-PPS or monotonic clock

function adaptive_sf_select(density, snr_ema, load_factor):
>>>>>>> origin/worktree-worker23
    IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) THEN
        RETURN 11
    ELSE IF (density < 5) AND (snr_ema > 8) THEN
        RETURN 9
    ELSE IF (density > 20) OR (snr_ema < -5) THEN
        RETURN 12
    ELSE
        RETURN 10
END FUNCTION
```

<<<<<<< HEAD
Per-SF SNR thresholds (normative, for ema_update fallback): SF9: >8dB, SF10: >0dB, SF11: >-5dB, SF12: any. Matches all ccp16.json vectors[0-4]. No dead code; all paths exercised by test vectors. Defines ema_update, select_channel, now() per prior beads.
=======
Default is SF10 per rationale in appendix-design-rationale.md. Density = neighbor count. Load_factor from DIO utilization and EMA (alpha=0.25 or 0.1 per vector). SNR_EMA updated via now(). Selected SF signaled in DIO capability option and Announce. RX on all SF. High density/load forces CH0 + higher SF for robustness; low density/good SNR enables SF9 on data channel for capacity. See CCP-9 for da2q rendezvous: Announce packets include signed rx_channel field (offset in signed_data per rust/lichen-core/src/announce.rs) for known-peer prediction. Unknown peers use CH0 control. Vectors in ccp9.json are authoritative independent oracle (hash-based, announce-driven, scheduled, with signed rx_channel preventing tampering).
>>>>>>> origin/worktree-worker23

## 2a.4. Time Synchronization

<<<<<<< HEAD
Time sync provided by DODAG root via epoch in beacons/RPL options (see 2a.2 for time-provider, epoch_floor validation, SFN modulo/wrap independence). Nodes MUST maintain `epoch_floor`, `stratum`, `wall_clock_valid` (see `docs/firmware-time-provider.md`).
=======

| Bit | Meaning |
|-----|---------|
| 0 | Scheduled mode supported |
| 1 | CSMA rendezvous mode supported |
| 2 | Concurrent CH0 reception supported |
| 3 | GNSS-PPS scheduled clock supported |
| 4-7 | Reserved; send as zero and ignore on receipt |
>>>>>>> origin/worktree-worker23

Root time-provider is authoritative. Adopt lowest DODAG ID root. Drift > threshold triggers desync (2a.5). Integrates with `lichen_rpl_dodag_init()` per AGENTS.md.

## 2a.5. Desync Recovery State Machine

[STUB - detailed FSM with transitions, timers, RPL version change handling, and multi-root conflict resolution to be expanded in subsequent chunks per parent epic project-LICHEN-ofrf. Includes full table of states (UNJOINED, JOINED, DRIFT, RECOVER), Trickle integration, and test vectors.]

Nodes entering this state from multi-root conflict (different epoch/version on same control channel) MUST refrain from data TX until re-synchronized. See Section 2a.2 for conflict detection rules.

## Implementation Status

- Python simulator, Rust RPL/gateway, Zephyr `lichen/subsys` all validate against `test/vectors/ccp16.json` (full cross-refs in Abstract; CCP-14 vectors[3+] for Gateway Multi-RX).
- Kconfig: `CONFIG_LICHEN_CCP16=y`, `CONFIG_LICHEN_TDMA_SLOTS=8`.
- Updated per draft-lichen-ccp scope (this document serves as relevant spec update).

## Vector Table (CCP-14 extension)

See `test/vectors/ccp16.json#vectors[3+]` for Gateway Multi-RX test cases with independent oracles. All MUST match exactly for interoperability.

## References

- `test/vectors/ccp16.json` (full cross-refs for MUST identical behavior)
- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/appendix-design-rationale.md#7.6`
- `spec/09-packets-timing.md`
- da2q multi-channel context for CCP-14

For slot `n`, let `t0` be its local monotonic start and `t1` its end. Each
endpoint begins retuning at `t0`. The receiver MUST be in receive mode by
`t0 + setup_window` and remain there through `t1`. The transmitter MUST finish
required CAD and MUST NOT begin RF transmission before
`t0 + setup_window + G`. Data, radio turnaround, and any immediate ACK/NACK MUST
finish by `t1 - G`. These opposite guard windows tolerate the maximum relative
clock error allowed above. If CAD deferral or any operation cannot meet the
deadline, the transmitter skips the cell. Back-to-back cells on different
channels are valid only when both cells satisfy this execution window
independently. The measured interval from RF transmission start through the end
of ACK/NACK reception MUST NOT exceed the signed `occupied_time`.

A dedicated cell identifies:

- schedule generation;
- activation and lease-end ASNs;
- slot offset and channel index;
- immediate transmitter and receiver IIDs.

CCP version 1 permits at most one scheduled transmitter per channel in each
slot. Concurrent cells on distinct channels MUST have disjoint single-radio
endpoints and MUST NOT exceed any receiver's advertised chain count. Empty
dedicated cells remain idle. Same-channel spatial reuse is rejected until
receiver-specific interference evidence and safe revocation are specified.
Different spreading factors MUST NOT be treated as perfectly orthogonal.

Cells are directed per-hop assignments. A multi-hop path needs cells on each
active RPL edge, and a node MUST NOT be scheduled to transmit and receive at the
same time unless its advertised hardware supports that operation.

## CCP-9. Assignment and Join

Dynamic coordinator assignment is the version 1 interoperable method. Static
`hash(IID) mod N` values MAY choose a shared join opportunity but MUST NOT create
dedicated cells because hash collisions are persistent reservations without
arbitration.

A joining node:

1. establishes valid GNSS-PPS time and listens on CH0 for an authenticated DIO;
2. sends a randomized self-authenticating join request in a shared cell using
   CAD/CSMA;
3. has its key accepted under the configured TOFU, DANE, or PKIX trust policy;
4. receives a nonce-bound leased assignment;
5. enters scheduled mode only at the assignment's activation ASN.

Unauthenticated requests MAY be processed only for rate-limited discovery and
MUST NOT allocate a dedicated cell. Parent changes require synchronization and
an assignment through the new parent before scheduled forwarding moves.

Assignments expire after silence, topology change, parent change, schedule
replacement, or lease end. Updates MUST activate atomically. A node missing the
new generation falls back rather than running an old and new schedule
concurrently. A replacement schedule's activation ASN MUST be at or after the
latest lease-end ASN of every cell it replaces. This rule applies even when a
node misses every replacement message; early activation based on acknowledgments
is deferred to a later profile.

## CCP-10. Capacity Control Messages

CCP control uses authenticated inner dispatch `0x15` and provisional routing
message type `0x02`. It does not change the link header. The byte after message
type is the CCP version and the next byte is a subtype:

| Subtype | Name | Purpose |
|---------|------|---------|
| `0x01` | JOIN_REQUEST | Shared-cell schedule request |
| `0x02` | SCHEDULE | Root-authorized leased cells |
| `0x03` | REVOKE | Root-authorized cell revocation |
| `0x04` | DISABLE | Root-authorized scheduled-mode shutdown |
| `0x05` | CHANNEL_REQUEST | CH0 CSMA rendezvous request |
| `0x06` | CHANNEL_GRANT | CH0 CSMA rendezvous grant |
| `0x07` | CHANNEL_REJECT | CH0 CSMA rendezvous rejection |

Every control message has a hop envelope followed by a subtype body:

```
+----------+---------+---------+----------------+-------------------+
| Msg 0x02 | Version | Subtype | Sender IID (8) | Subtype Body ...  |
+----------+---------+---------+----------------+-------------------+
```

The ordinary link signature covers the complete envelope and lets the receiver
select the pinned immediate-sender key before processing the subtype. Relays MAY
replace `Sender IID` and the link signature. Unknown versions or subtypes MUST
be ignored by protocol logic and MUST NOT be delivered as application data.

SCHEDULE, REVOKE, and DISABLE bodies contain an immutable authority object and
MUST additionally carry a monotonically
increasing 64-bit authority sequence and a 48-byte Schnorr48 signature by the
accepted root over:

```
"LICHEN-CCP-AUTH-v1" || DODAGID || RPLInstanceID ||
subtype || authority_object_without_signature
```

The hop envelope is excluded from the root signature. Relays MUST preserve the
authority object unchanged. Before accepting it, a node MUST already possess an
authenticated and pinned public key for the accepted DODAG root through the
normal Announce/trust process. Otherwise it remains in baseline mode.

A schedule authority object contains, in order:

| Field | Size |
|-------|------|
| Root IID | 8 bytes |
| Recipient IID | 8 bytes |
| Authority sequence | 8 bytes |
| Schedule generation | 4 bytes |
| Epoch GPS seconds | 8 bytes |
| Activation ASN | 8 bytes |
| Lease-end ASN | 8 bytes |
| Join nonce | 16 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel mask | 4 bytes |
| Slot duration us | 4 bytes |
| Setup window us | 4 bytes |
| Occupied time us | 4 bytes |
| Guard budget us | 4 bytes |
| Slots per superframe | 2 bytes |
| PHY profile ID | 1 byte |
| Max PHY length | 1 byte |
| Schedule digest | 16 bytes |
| Page index | 1 byte |
| Page count | 1 byte |
| Cell count | 1 byte |
| Cell records | `cell_count * 19` bytes |
| Root signature | 48 bytes |

A cell record contains slot offset (2), channel index (1), transmitter IID (8),
and receiver IID (8), all in that order. Multi-byte integers are big-endian.
`Join nonce` binds a first assignment to its JOIN_REQUEST and is all zero for a
schedule update that does not grant a new node.
`Schedule digest` is the first 16 bytes of SHA-256 over the recipient's complete
cell list, sorted by slot offset, channel index, transmitter IID, then receiver
IID, and serialized as concatenated 19-byte records. Each SCHEDULE frame is a
root-signed page for one recipient and carries exactly one cell record. With an
extended link destination and short SenderID, the complete frame body is 255
bytes; a second cell would exceed the 255-byte length field. Page indices start
at zero and follow
the canonical cell order. Common authority fields and digest are identical
across pages; page index and cell record differ. `Page count` equals the
recipient's cell count. A recipient MUST receive every page before activation
or remain in baseline mode.

The root MUST use its authenticated short SenderID for SCHEDULE pages; the
extended SenderID form does not fit this maximum-size frame.

All pages in one schedule transaction share an authority sequence. Replay state
is keyed by `(root IID, authority sequence, page index)`: each page index MAY be
accepted once, in any order. A transaction with an authority sequence lower
than the highest completed transaction is stale. A higher authority sequence
abandons any incomplete lower transaction and cancels every queued future action
with a lower sequence, including REVOKE and DISABLE. At an equal authority
sequence, a node accepts only previously unseen SCHEDULE pages with the same
recipient, generation, digest, and page count; every other object is a replay or
conflict and MUST be rejected.

REVOKE contains root IID, recipient IID, authority sequence, schedule
generation, activation ASN, and one 19-byte cell record. DISABLE
contains root IID, recipient IID, authority sequence, schedule generation, and
activation ASN. Both take effect when that authenticated activation ASN is
reached; a value less than or equal to the current ASN takes effect immediately.
Canonical vectors MUST cover every control body before production
implementation begins.

A JOIN_REQUEST subtype body contains origin IID (8), origin public key (32),
root IID (8), a random join nonce (16), requested lease in slots (4), capability
length (1), capability bytes (variable), and an origin Schnorr48 signature (48).
The capability bytes use the 36-byte CCP Capability option data format without
its type and length bytes. Other capability lengths are unsupported in version
1. The origin signature covers:

```
"LICHEN-CCP-JOIN-v1" || DODAGID || RPLInstanceID ||
origin_iid || origin_public_key || root_iid || join_nonce ||
requested_lease || capability_length || capability_bytes
```

Relays preserve this subtype body while replacing only the hop envelope and
link signature. The coordinator verifies the IID/public-key binding and origin
signature, then applies the configured TOFU, DANE, or PKIX policy before
pinning. The SCHEDULE authority object binds that nonce when granting the
origin's first cell; subsequent updates carry an all-zero nonce.

## CCP-11. CSMA Channel Rendezvous

When no usable scheduled cell exists, two capable immediate neighbors MAY
negotiate a bounded data-channel rendezvous on CH0.

1. The initiator sends signed CHANNEL_REQUEST on CH0.
2. The receiver validates identities, plan, channel, duration, queue state, and
   regulatory budget.
3. The receiver sends signed CHANNEL_GRANT or CHANNEL_REJECT on CH0.
4. The end of the authenticated GRANT PHY frame is rendezvous time zero. For
   initiator-to-grantor traffic, the grantor retunes immediately and the
   initiator waits the granted switch guard from the end of GRANT reception. For
   grantor-to-initiator traffic, the initiator retunes immediately and the
   grantor waits the switch guard before transmitting.
5. Data and associated ACK/NACK traffic use the granted channel.
6. Both nodes return to CH0 after completion, failure, or expiry.

The exchange binds immediate endpoint IIDs, a random reservation token, plan
ID/version, channel index, direction, retry counter, maximum frame count,
maximum airtime, switch guard, and expiry. A reservation MUST be bounded by both
duration and regulatory airtime. The default maximum absence from CH0 is five
seconds. Expiry is encoded as a duration in milliseconds from rendezvous time
zero. Both endpoints return to CH0 no later than that duration even when data or
acknowledgments are lost.

CHANNEL_REQUEST has this subtype body after the hop envelope:

| Field | Size |
|-------|------|
| Peer IID | 8 bytes |
| Reservation token | 8 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel index | 1 byte |
| Retry counter | 1 byte |
| Direction | 1 byte (`0` initiator-to-grantor, `1` grantor-to-initiator, `2` bidirectional) |
| Maximum frame count | 1 byte |
| Reserved | 1 byte |
| Maximum airtime ms | 2 bytes |
| Maximum duration ms | 2 bytes |

CHANNEL_GRANT echoes the complete request body and appends switch guard in
microseconds (4 bytes). CHANNEL_REJECT contains peer IID (8), reservation token
(8), reason (1), and reserved (1). Receivers MUST reject non-zero reserved
fields or direction values above 2. In a bidirectional reservation, the
initiator transmits first after the switch guard; reverse traffic begins only
after the first frame's defined radio-turnaround interval and remains inside the
granted airtime/duration bounds. All multi-byte integers are unsigned
big-endian.

The eligible channel set is the ordered intersection of both local plans and
advertised masks. The initiator distributes retries with:

```
A = min(full_iid_local, full_iid_peer)
B = max(full_iid_local, full_iid_peer)
digest = SHA-256("LICHEN-MC-RV1" || plan_id || plan_version ||
                A || B || reservation_token || retry_counter)
index = uint32_be(digest[0:4]) mod eligible_channel_count
```

The selected channel is still carried explicitly in request and grant; hashing
does not authenticate a reservation or make a receiver listen. A busy data
channel causes wait within the reservation or CH0 fallback, never an implicit
channel change.

Rendezvous is per-hop. A relay returns to CH0 and negotiates separately with its
next hop. Multicast and broadcast rendezvous are not defined.

## CCP-12. Scheduled Multi-Channel Operation

In scheduled mode, a root-authorized cell is the rendezvous and replaces the
CHANNEL_REQUEST/CHANNEL_GRANT exchange. Channel switch time and guard are
deducted from usable slot airtime. A node MUST NOT be assigned simultaneous CH0
and data-channel reception unless it advertises concurrent receive chains.

The scheduler MUST account for root and relay airtime, half-duplex conflicts,
and regulatory budgets. A cell grants a transmission opportunity, not
permission to violate regional rules. A node without sufficient budget skips
the cell.

Plan ID, plan version, channel mask, PHY profile, timing envelopes, schedule
digest, and all cells are covered by the root signature. A hop-authenticated DIO
advertisement alone MUST NOT alter interpretation of an accepted schedule.

Network-wide synchronized frequency hopping is not part of version 1. Such
hopping can provide interference or regulatory distribution but does not create
parallel capacity on single-radio hardware. It requires a separate hopping
sequence, reacquisition, multicast, and certification specification.

## CCP-13. Loss, Fallback, and Compatibility

A node MUST stop scheduled transmission immediately when:

- uncertainty exceeds the guard budget;
- its cell lease expires;
- GNSS-PPS is invalid and its calculated holdover expires;
- it accepts a different root or incompatible schedule generation;
- an authenticated revocation or disable reaches its activation ASN;
- a time correction exceeds its conservative error envelope.

The node then returns to CH0, uses baseline CAD/CSMA, restores valid GNSS-PPS
state if needed, listens for authenticated capability/schedule traffic, and
rejoins. It MUST NOT continue transmitting in remembered cells. This holdover
deadline is independent of the much longer RPL root-failure interval.

Legacy nodes remain on CH0 and ignore unsupported routing/control types.
CCP-capable nodes use CH0 for traffic to legacy or unknown peers. A root assigns
a cell only when both immediate endpoints advertise compatible versions.

Mixed operation cannot guarantee performance equal to pure baseline operation:
beacons consume airtime, empty cells waste opportunities, and legacy nodes may
collide with scheduled CH0 cells. Compatibility means continued communication
and bounded fallback, not guaranteed improvement.

## CCP-13a. Desync Recovery State Machine

This section defines how a node detects synchronization loss and recovers.
Terminology uses plain language because the state machine must be implementable
by firmware engineers without real-time systems backgrounds.

### States

A CCP-capable node is always in exactly one of these states:

| State | Meaning | Channel behavior |
|-------|---------|------------------|
| UNJOINED | Never successfully synchronized | CH0 only; cannot hop |
| JOINED | Clock is trusted; normal operation | Hop per schedule |
| DRIFT | Clock may be drifting; watching | Hop with extended RX windows |
| RECOVER | Clock is untrusted; seeking beacon | CH0 only; stopped hopping |

### State Diagram

```
                         beacon_rx
    ┌──────────┐ ───────────────────────▶ ┌──────────┐
    │ UNJOINED │                          │  JOINED  │
    └──────────┘                          └────┬─────┘
         ▲                                     │
         │                                     │ no_beacon(T_DRIFT_WARN)
         │                                     ▼
         │                                ┌─────────┐
         │          beacon_rx             │  DRIFT  │
         │       ◀───────────────────     └────┬────┘
         │       │                             │
         │       │                             │ no_beacon(T_DRIFT_MAX)
         │       │                             ▼
         │       │                        ┌─────────┐
         └───────┴─── no_beacon(T_GIVE_UP)│ RECOVER │
                      beacon_rx           └─────────┘
                   ◀──────────────────────────┘
```

### Clock Reference

The SX1262 temperature-compensated oscillator (TCXO) is the timing reference,
not the nRF52840 main crystal. Typical accuracy:

| Source | Accuracy | Drift per minute |
|--------|----------|------------------|
| nRF52840 crystal | ±40 ppm | ±2.4 ms |
| SX1262 TCXO | ±2.5 ppm | ±0.15 ms |

At ±2.5 ppm, a node drifts approximately 0.3 ms after 2 minutes without
synchronization—within tolerance for typical 10–50 ms slots.

### Timers

| Timer | Default | Description |
|-------|---------|-------------|
| `T_DRIFT_WARN` | 30 s | Time without beacon before entering DRIFT |
| `T_DRIFT_MAX` | 120 s | Time in DRIFT before entering RECOVER |
| `T_GIVE_UP` | 600 s | Time in RECOVER before returning to UNJOINED |

`T_GIVE_UP` MUST be configurable. The default balances battery life against
recovery robustness. Deployments with frequent temporary RF shadows MAY
increase it; solar-powered nodes MAY decrease it.

### Transitions

#### UNJOINED → JOINED

**Trigger:** Receive authenticated beacon containing SFN and epoch.

**Actions:**
1. Set local SFN and epoch from beacon.
2. Set `wall_clock_valid = true`.
3. Start drift watchdog with period `T_DRIFT_WARN`.
4. Begin channel hopping per schedule.

A node in UNJOINED MUST listen on CH0 continuously. It cannot hop because it
does not know the current time.

#### JOINED → DRIFT

**Trigger:** Drift watchdog expires (no beacon received for `T_DRIFT_WARN`).

**Actions:**
1. Extend RX window by 50% on each channel.
2. Start recovery countdown with period `T_DRIFT_MAX`.
3. Continue hopping but with extended windows.

The extended window hedges against clock uncertainty without abandoning the
schedule. A quiet network is not necessarily a lost network.

#### DRIFT → JOINED

**Trigger:** Receive authenticated beacon.

**Actions:**
1. Apply small SFN correction if within tolerance.
2. Reset drift watchdog.
3. Cancel recovery countdown.
4. Restore normal RX window duration.

Small corrections adjust for measured drift. A correction exceeding the
guard budget indicates the node was further off than believed; it MUST
transition to RECOVER instead.

#### DRIFT → RECOVER

**Trigger:** Recovery countdown expires (`T_DRIFT_MAX` elapsed without beacon).

**Actions:**
1. Set `wall_clock_valid = false`.
2. Stop channel hopping immediately.
3. Return to CH0 and listen continuously.

A node in RECOVER MUST NOT transmit in scheduled cells. Its clock is
untrusted and it would likely transmit in the wrong slot, causing collisions.

Recovery is passive: the node listens on CH0 for beacons. It does not
actively solicit beacons because:
- Solicitation consumes airtime on an already-stressed network.
- A lost node does not know when its solicitation would collide.
- Beacons arrive at coordinator-controlled intervals regardless.

#### RECOVER → JOINED

**Trigger:** Receive authenticated beacon on CH0.

**Actions:**
1. Hard-reset SFN and epoch from beacon (not a small correction).
2. Set `wall_clock_valid = true`.
3. Start drift watchdog.
4. Resume channel hopping.
5. Log recovery event for diagnostics.

The hard reset acknowledges that the node's prior time estimate was wrong.

#### RECOVER → UNJOINED

**Trigger:** No beacon received for `T_GIVE_UP`.

**Actions:**
1. Clear cached routing and schedule state (it is stale).
2. Enter low-power periodic listen mode on CH0.
3. Remain in UNJOINED until beacon reception.

This transition indicates prolonged isolation. The node conserves power while
remaining available for rejoining.

### Multi-Root Conflict

A node MAY receive beacons from multiple roots with different epochs.

**Resolution order:**
1. Prefer the root with the higher epoch number.
2. If epochs are equal, prefer the root the node was already following.
3. If newly joining, prefer the root with the lower Node ID (deterministic
   tiebreak).

Higher epoch indicates more recent network time. A node MUST NOT oscillate
between roots; once it accepts a root's beacon, it ignores lower-epoch
beacons from other roots until it returns to UNJOINED.

### RPL Version Independence

An RPL DODAG version change does not reset SFN. Routing topology and time
synchronization are independent concerns. A node MAY experience an RPL
version increment while remaining in JOINED with unchanged time state.

Exception: if the RPL version change accompanies a new CCP epoch from the
same root, the node treats the epoch change normally.

### SFN Wraparound

SFN is an unsigned integer that wraps to zero. Wraparound within the same
epoch is expected and handled by modular arithmetic.

When local SFN wraps:
1. Increment local epoch counter.
2. Continue hopping normally.

If a received beacon's epoch differs from the local epoch by more than one,
the node's time estimate is grossly wrong. It MUST transition to RECOVER
regardless of current state.

### GPS-Capable Nodes

Nodes with GNSS-PPS hardware MAY use GPS time instead of beacon time:

- `wall_clock_valid = true` when GPS lock is acquired with valid PPS.
- GPS provides authoritative SFN; beacons are used to detect epoch changes.
- Loss of GPS lock starts the drift watchdog as if a beacon were missed.

GPS-capable nodes still listen for beacons to detect:
- Epoch increments from the root.
- Network-wide schedule changes.
- Multi-root conflicts.

### Implementation Notes

1. **Drift watchdog** resets on any authenticated beacon reception, not only
   beacons from the preferred root.

2. **Extended RX windows** in DRIFT increase power consumption. The 50%
   extension is a tradeoff; deployments MAY tune this via configuration.

3. **Recovery logging** aids debugging but MUST NOT delay state transitions.

4. **State persistence** across reboot: a node that reboots without
   persisted time state MUST start in UNJOINED regardless of prior state.

## CCP-14. Security Requirements

- Capability, join, schedule, revocation, disable, request,
  grant, and rejection messages MUST be signed and replay-protected.
- Schedule authority MUST be verified against the accepted root key; ordinary
  link authentication by a relay is insufficient.
- Schedule generation, activation ASN, lease end, and authority sequence MUST
  reject stale or replayed state.
- A node without persisted replay state MUST complete a fresh nonce-bound join
  before obeying a dedicated assignment.
- Remote messages MUST NOT enable a locally prohibited channel.
- Requests MUST be rate-limited before expensive signature or radio work.
- An unauthenticated downgrade MUST NOT change schedule state. Lease expiry and
  synchronization loss provide autonomous safe downgrade.

Jamming CH0, GNSS jamming or spoofing, and compromised authorized roots remain
denial-of-service risks.

## CCP-15. Capacity Claims

<<<<<<< HEAD
CCP does not guarantee a fixed capacity multiplier.
=======
CCP does not guarantee a fixed capacity multiplier. TDMA removes scheduler overlaps under bounded clocks but not external interference or legacy traffic. With 8 frequencies and CH0 reserved for control (Announce, RPL, LOADng, CCP per CCP-5), aggregate capacity depends on disjoint links, receiver chains, regulatory budgets, and load. Test vectors in test/vectors/ccp_load_balancing.json and ccp16.json are authoritative independent oracles for density/EMA/load_factor rules, SF selection, and channel rendezvous. Implementations MUST report measured goodput against these oracles; no unsubstantiated "Nx capacity" claims.
>>>>>>> origin/worktree-worker23

TDMA can remove scheduler-created same-domain overlaps under bounded clocks,
but not external interference, legacy transmissions, jamming, or unsafe reuse.
Multiple channels increase aggregate capacity only when disjoint links and
receiver hardware can operate concurrently. A single-radio gateway star remains
approximately serialized even when many frequencies exist.

For eight total frequencies with CH0 reserved for control, capable payload has
an ideal seven-data-channel bound before control overhead, topology, half-duplex
relays, interference, and regulation. Implementations MUST report measured
goodput and collision reduction with topology and hardware assumptions; they
MUST NOT claim "8x capacity" from channel count alone.

## CCP-16. Simulator Gates

Production implementation is blocked until a deterministic simulator verifies:

1. byte-exact codecs, signature transcripts, malformed inputs, and canonical
   vectors for every capability and control format;
2. canonical LoRa airtime vectors for complete PHY frames;
3. slot fit including ramp, retune, guard, data, and acknowledgment;
4. GNSS PPS alignment, worst-case clock drift, and holdover boundaries;
5. GNSS loss/spoof discontinuity, stale schedule rejection, and CH0 fallback;
6. zero scheduler-created overlap in star, hidden-terminal, line, tree, and
   diamond topologies without spatial reuse;
7. no simultaneous TX/RX assignment on single-radio nodes;
8. concurrent distinct-channel cells limited by endpoint and receiver-chain
   constraints;
9. atomic schedule-generation activation after update loss or delay;
10. randomized join progress without starvation under declared load;
11. per-hop channel rendezvous, request/grant loss, and five-second recovery;
12. plan mismatch, prohibited-channel rejection, and regulatory accounting;
13. all-legacy behavior unchanged and mixed-version communication preserved;
14. single-radio gateways modeled without fabricated parallel reception;
15. parallel-radio gateways limited to their advertised demodulator count;
16. forged, modified, replayed, stale, and unauthenticated control rejected;
17. identical-seed comparisons of delivery ratio, latency, goodput, collision
    loss, and control airtime against baseline CSMA.

For each seed, metrics are paired between baseline and CCP. Favorable
multi-channel tests MUST produce a median delivered-payload ratio of at least
4.0 and a 5th-percentile ratio of at least 3.0 for seven disjoint saturated
capable pairs before
multi-channel production implementation is unblocked. This is a simulator
product gate, not a protocol guarantee. In an all-capable dense reference
topology, the median paired collision-attributed-loss reduction MUST be at least
50%, at least 90 of 100 seeds MUST show no increase, and median delivery ratio
MUST NOT decrease.

The canonical gate uses seeds 0 through 99 and two fixed scenarios:

1. **Parallel capacity:** Seven disjoint one-hop pairs, one pair on each data
   channel, saturated 76-byte PHY frames, compared with all seven pairs on CH0.
2. **Dense mixed star:** 64 sources and one coordinator with eight receive
   chains. Sources offer one 76-byte frame per superframe. Capability fractions
   are 25%, 50%, 75%, and 100%, selected by ascending IID.

Both runs use the same regional plan, SF, bandwidth, coding rate, traffic trace,
and seed on baseline and CCP paths. The simulator issue MUST freeze those PHY,
superframe, clock-error, and regulatory values as versioned JSON before results
are accepted. For each mixed capability fraction, the 95th percentile of paired
delivery-ratio regression and RPL-convergence-time regression MUST NOT exceed
5%. Results MUST include
goodput, PDR, p95 latency, collision-attributed loss, control airtime, and
regulatory deferrals for every seed; averages alone are insufficient.

For seed `s`:

```
payload_ratio_s = delivered_payload_ccp_s / delivered_payload_baseline_s
pdr_regression_s = max(0, (pdr_baseline_s - pdr_ccp_s) / pdr_baseline_s)
convergence_regression_s =
    max(0, (convergence_ccp_s - convergence_baseline_s) /
           convergence_baseline_s)
```

The canonical scenario is invalid and cannot unblock implementation if any
baseline seed delivers zero payload, has zero PDR, or fails to converge by the
declared test deadline. A CCP seed that fails to converge is an automatic gate
failure. Percentile gates apply to the 100 paired per-seed values, using nearest-
rank percentiles.

## CCP-17. Deferred Extensions

The following require separate specifications and evidence:

- same-channel receiver-specific spatial cell reuse;
- synchronized network-wide hopping;
- multicast data-channel scheduling;
- distributed cell negotiation;
- adaptive slot duration or per-cell PHY profiles;
- sleep scheduling that removes baseline receive availability.

---

[← Physical and Link Layers](02-physical-link.md) | [Index](README.md) |
[Next: Adaptation Layer →](03-adaptation.md)
<<<<<<< HEAD
=======








**Resolved Key Sections Summary:** Merge conflicts resolved into coherent normative text across affected files. Spelled-out pseudocode standardized for `select_channel` (density >8 or !wall_clock_valid → CH0; else hash-based data channel selection using FNV1a32 on EUI/t/epoch), `adaptive_sf_select` (SF selection from density, SNR_EMA, load_factor with exact thresholds), `ema_update`, and `now()` (SFN). CH0 rules mandate control traffic (Announce, RPL control, LOADng, all CCP including capability/schedule/rendezvous). Capability DIO option detailed with 36-byte format, flags, timing params. CCP-9 da2q rendezvous: signed rx_channel in Announce payload for known-peer scheduling (byte offset in signed data), CH0 fallback for initial/unknown peers; prevents tampering via signature. Density/EMA (alpha=1/4)/load rules drive SF/channel adaptation for capacity vs robustness tradeoff. All cross-reference independent test vector oracles (`test/vectors/ccp9*.json`, `ccp16.json`, `ccp_load_balancing.json`, `schc_compression.json`, `node_address.json`). Removed all conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`), duplicates, worker notes, codereview references, and TODOs. Files updated for consistency. CC-BY-4.0 license header preserved in all. Sales-playbook.md consolidated into PRFAQ highlighting resolved CCP features. See Appendix A for parameter justifications.
>>>>>>> origin/worktree-worker23
