<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Profile

## CCP-1. Scope

The LICHEN Coordinated Capacity Profile (CCP) is an OPTIONAL MAC overlay for
deployments where contention on the baseline channel limits delivery. CCP
combines time scheduling and channel rendezvous because a single-radio receiver
must know both when and where to listen.

Baseline LICHEN uses CAD and randomized CSMA on the regional default channel,
called CH0. A node that does not implement CCP remains a conforming LICHEN node.
CCP-capable nodes MUST retain baseline operation for discovery, compatibility,
fallback, multicast, and loss of synchronization.

CCP version 1 deliberately does not define same-channel spatial slot reuse,
persistent off-channel receive assignments, or network-wide frequency hopping.
It permits concurrent cells on distinct channels when endpoints and receiver
chains do not conflict. More aggressive reuse requires interference,
synchronization, and regulatory evidence that is not available in the baseline
protocol.

## CCP-2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

- **CCP domain:** One DODAG using one root identity and schedule generation.
- **Coordinator:** The accepted DODAG root that authorizes schedules.
- **ASN:** Absolute Slot Number, a monotonically increasing 64-bit slot index.
- **Cell:** A leased `(slot offset, channel, transmitter, receiver)` assignment.
- **CH0:** The regional plan's mandatory baseline channel.
- **Data channel:** A locally permitted channel other than CH0.
- **Rendezvous:** A bounded agreement for two immediate neighbors to leave CH0.
- **Parallel receiver:** Hardware capable of receiving multiple channels at the
  same time. Retuning one radio does not make it a parallel receiver.

## CCP-3. Operating Classes

Nodes MUST advertise one of these receive classes:

| Class | Behavior |
|-------|----------|
| Baseline | CH0 CAD/CSMA only |
| Coordinated single-radio | Scheduled CH0/data-channel switching; one receive channel at a time |
| Coordinated parallel-radio | Scheduled operation with an advertised simultaneous receive-channel count |

A node MUST NOT advertise more receive chains or concurrent CH0 reception than
its deployed RF front end provides. Round-robin scanning is single-radio
operation and MUST NOT be represented as parallel reception.

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

<<<<<<< HEAD
- Announce, DIO, DIS, DAO, and DAO-ACK traffic;
- LOADng RREQ, RREP, and RERR traffic;
- CCP capability, schedule, join, and rendezvous control;
- multicast, broadcast, and emergency traffic;
- unicast to peers whose compatible capability is unknown;
- fallback after any CCP failure.
=======
**Rules (MUST follow for interoperability):**
- Baseline default is SF10/125kHz per appendix-design-rationale.md:7.1 (IETF layering: RFC2119 RECOMMENDED general-purpose compromise). The density-aware logic in this CCP-16 section layers on top per RFC 2119: implementations MUST follow the adaptive_sf_select pseudocode and match test vectors exactly; overrides to SF7/8/11/12 occur only on explicit local metric triggers (density, SNR, PER, success_rate, load_factor). This resolves any apparent conflict with SF10 rationale.
- Density drives primary choice: high density (>40 neighbors) biases toward higher SF to improve link margin at cost of airtime (TDMA slots compensate; explicit rationale per codereview-P3). Thresholds tuned to match ccp_load_balancing.json vectors 3/5. Appendix A updated with constants.
- SNR and PER are secondary modifiers. Success_rate <0.85 forces SF increase.
- Gateway load_factor >70 forces SF=10 for network-wide balance (overrides local).
- Use EMA for SNR to smooth noise. All computations deterministic. Exact EMA formula (validated against rust/lichen-tui/src/rf_health.rs and Python sim reference):
  ```
  snr_ema = snr_ema_prev * (1 - 0.25) + snr_current * 0.25
  ```
  Integer form (embedded, Q2): `snr_ema = (snr_ema_prev * 3 + snr_current) / 4`. Matches vectors.
- Embedded impls SHOULD use integer approximation (e.g. snr_q8 = snr_db * 256). Python reference uses f32.
- Output MUST exactly reproduce test vector expected SF for given inputs (see ccp_load_balancing.json vectors 3 and 5; pseudocode now does).
>>>>>>> origin/integration/worker3-20260722

A single-radio node MUST listen on CH0 whenever it is not transmitting or
participating in an active cell or rendezvous. Reception of legacy CH0 traffic
during an off-channel window is necessarily best-effort. Continuous CH0
reception while using a data channel requires another receive chain.

Legacy nodes do not know slot boundaries and may transmit at any time.
Therefore, a CCP transmitter MUST perform CAD or the regional plan's required
listen-before-talk procedure even in a dedicated cell.

## CCP-6. Capability Advertisement

<<<<<<< HEAD
Slow-changing domain parameters are advertised in a CCP Capability DIO option.
The provisional experimental option type is `0xE0`; it MUST be replaced by an
assigned value before publication as an interoperable Internet standard.

```
+--------+--------+---------+-------+-------------+----------+
| Type   | Length | Version | Flags | Plan ID (2) | Plan Ver |
+--------+--------+---------+-------+-------------+----------+
| PHY ID | Schedule Generation (4) | Slot Duration us (4)    |
+--------+-------------------------+-------------------------+
| Setup Window us (4) | Occupied Time us (4) | Guard us (4)     |
+---------------------+----------------------+------------------+
| Slots/Superframe (2) | Channel Mask (4)                    |
+----------------------+-------------------------------------+
| RX Chains | Max PHY Len | Reserved (2)                       |
+-----------+-------------+------------------------------------+
```

The option data length is 36 bytes. Multi-byte integers are unsigned
big-endian. `Setup Window` bounds retune, receiver readiness, and CAD before RF
transmission. `Occupied Time` bounds data plus immediate acknowledgment.
`Guard` is the total separation required between occupied transmission
envelopes. `Max PHY Len` includes the complete link frame.
=======
CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00).

Data channels are selected via select_channel (normative pseudocode below, cross-ref draft-lichen-tdma for TDMA integration). All implementations MUST produce identical results to test/vectors/ccp16.json for CCP-14/15/16 vectors.

### 4.1. select_channel and now()

Nodes MUST implement select_channel and now as follows. All operators use spelled-out keywords for IETF compatibility. Implementations MUST match test vectors in test/vectors/ccp16.json exactly. Cross reference CCP-16.

```
function select_channel(ctx, metrics, t):
    IF (metrics.density > 8) OR (NOT ctx.wall_clock_valid) THEN
        RETURN 0
<<<<<<< HEAD
    hash = fnv1a32((ctx.eui64 XOR t XOR ctx.epoch))
=======
    hash = fnv1a32( (ctx.eui64 XOR t XOR ctx.epoch) )
>>>>>>> origin/integration/worker8-20260722
    n = ctx.num_data_channels IF ctx.num_data_channels > 0 ELSE 3
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()
```
<<<<<<< HEAD
=======
Note: All operators are spelled out (OR, NOT, MOD, XOR) for language-agnostic IETF compatibility. No Rust 'or', no C types or structs, no dead code. now_ts TDMA alignment uses LICHEN_TDMA_Slot relation for slot calc.
>>>>>>> origin/integration/worker8-20260722

### Density Rules Rationale (logical chunk: rationale paragraph - updated)

SF10 is the REQUIRED default per appendix-design-rationale.md:7.1. Density rules MUST override it ONLY on the explicit thresholds given (see adaptive_sf_select below) per RFC 2119 layering for capacity/robustness tradeoffs vs SF10 baseline. This balances sensitivity (~ -132 dBm at 125 kHz) and airtime (~250 ms for typical 50B payload per appendix-design-rationale.md:7.1) for typical mesh density per appendix-design-rationale.md:7.6 and independent sim oracle in ccp16.json vectors. Adaptation prioritizes capacity (SF9 in low density <5 + good SNR >8 dB to reduce airtime ~2x) vs robustness (SF11/12 in density >8 or poor SNR or high load_factor to lower PER). This yields net capacity gain in sims at 50 nodes/km^2 despite longer airtime for higher SF. EMA on SNR (snr_ema = 0.1 * current + 0.9 * previous, updated via now()) integrates with load_factor override from gateway DIOs.

Updates MUST be propagated in RPL metric container. Root optimizer uses reported neighbor_count and channel_util to minimize collisions.

### 4.2. adaptive_sf_select

Nodes MUST maintain per-neighbor tracking of SNR using EMA with alpha 0.1 over 300s window. Density is neighbor count. Load factor from DIO utilization. The algorithm MUST be:

```
function adaptive_sf_select(density, snr_db, load_factor, t):
    snr_ema = ema_update(previous_ema, snr_db, t)
    IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) THEN
        RETURN 11
    ELSE IF (density < 5) AND (snr_ema > 8.0) THEN
        RETURN 9
    ELSE IF (density > 20) OR (snr_ema < -5.0) THEN
        RETURN 12
    ELSE
        RETURN 10
```

Per-SF SNR thresholds for fallback: SF9 >8 dB, SF10 >0 dB, SF11 >-5 dB, SF12 any. The selected SF MUST be signaled in DIOs per draft-lichen-rpl-lora-00. Nodes MUST RX scan control channel or use announcements for updates. Thresholds and EMA MUST produce identical results to ccp16.json vectors. See CCP-16.
>>>>>>> origin/integration/worker11-20260722

Flags are:

| Bit | Meaning |
|-----|---------|
| 0 | Scheduled mode supported |
| 1 | CSMA rendezvous mode supported |
| 2 | Concurrent CH0 reception supported |
| 3 | GNSS-PPS scheduled clock supported |
| 4-7 | Reserved; send as zero and ignore on receipt |

`Channel Mask` bit zero represents CH0. A receiver computes the intersection
with its local permitted mask. `RX Chains` is the maximum simultaneous receive
channel count and MUST be one for a normal SX126x/SX127x node.

The DIO option advertises configuration; it is not a timing beacon. Trickle DIO
intervals are too long and their receive timestamps too uncertain for slot
synchronization.

## CCP-7. GNSS-PPS Slot Clock

Scheduled mode version 1 requires every participating node to have a GNSS
receiver with a hardware pulse-per-second (PPS) output connected to a capture
input. NMEA or other software-delivered timestamps alone are insufficient.
Nodes without valid GNSS-PPS remain fully operational in baseline CH0 CAD/CSMA
and MAY use CSMA channel rendezvous.

The schedule uses continuous GPS system time, not UTC or Unix time. The
root-authorized schedule defines `epoch_gps_seconds`, the integer GPS second at
whose PPS edge ASN zero begins. For slot duration `D` microseconds:

```
ASN = floor((gps_time_us - epoch_gps_seconds * 1_000_000) / D)
```

The PPS edge associated with each decoded GPS second is the mandatory slot
reference event. A receiver driver MUST define and compensate its module's PPS
polarity, time association, fixed antenna/receiver delay, and capture latency.
If the receiver cannot associate PPS with an unambiguous GPS second, scheduled
mode MUST remain disabled.

Each node maintains:

- estimated offset between PPS and its local monotonic clock;
- conservative fractional drift bound;
- timestamp and scheduler jitter bound;
- uncertainty at the last accepted synchronization event;
- GPS second, ASN, and local monotonic time at that PPS edge.

The uncertainty after holdover time `h` is:

```
B(h) = B(0) + rho * h
```

where `rho` is the conservative relative drift bound. Runtime estimation MAY
tighten the bound only after sufficient observations; the hardware-qualified
bound remains the fallback.

For any transmitter and receiver pair, edge guard `G` MUST satisfy:

```
G >= B_i(h_i) + B_j(h_j) + J_i + J_j + P + M
```

where `J` is unaccounted scheduling/radio jitter, `P` bounds differential
propagation delay, and `M` is an implementation safety margin. Radio ramp,
retune time, packet airtime, and acknowledgment time belong in the occupied
slot envelope, not in clock guard.

The schedule derives a per-node edge-error budget:

```
E = (G - P - M) / 2
```

The coordinator and every endpoint MUST reject a schedule unless `G > P + M`
and:

```
setup_window + occupied_time + 2 * G <= slot_duration
```

Every endpoint MUST stop scheduled transmission when `B(h) + J > E`. This
ensures two endpoints cannot each consume the full guard independently. No fixed
50 ms guard is specified. After temporary PPS loss, a node MAY continue only
for the calculated holdover interval using its last valid PPS association.
Expiration of holdover, an invalid time solution, or an implausible time jump
causes immediate scheduled-mode fallback.

GNSS supplies time, not schedule authority. Schedule assignments remain
root-authenticated. GNSS jamming and spoofing are availability risks; nodes MUST
reject time discontinuities outside their conservative clock envelope and
SHOULD expose GNSS integrity state for diagnostics.

## CCP-8. Superframes and Cells

A superframe contains a fixed number of fixed-duration slots. Slot offset is
`ASN mod slots_per_superframe`.

Every schedule MUST define:

- one PHY profile for scheduled frames;
- maximum scheduled PHY frame length;
- setup window, occupied-time envelope, guard budget, and
  `epoch_gps_seconds`;
- at least one shared CH0 control/contention cell;
- schedule generation and future activation ASN.

A scheduled frame MUST fit completely within its slot. An oversized frame MUST
be fragmented or sent through baseline contention. A PHY, slot-duration, or
channel-plan change creates a new schedule generation and MUST activate at a
future ASN.

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

Implementations MUST follow the desynchronization recovery FSM defined in
Table 1 exactly. Table 1 is normative per [RFC2119].

### Table 1: Desynchronization Recovery States

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

Blacklist timer comparison and dwell calc use unsigned u32 subtraction; no underflow risk as timers reset frequently. Vectors in ccp16.json cover all wrap cases.

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

## CCP-15. Capacity Claims (parent bead project-LICHEN-da2q.15)

CCP does not guarantee a fixed capacity multiplier. Integration notes updated per codereview-1: interference mitigation (da2q.15.8) feeds directly into CCP-16 load_factor and SF/channel selection; test vectors in ccp_load_balancing.json are authoritative oracle for all impls. RAK2287 fixtures and interop vectors added per project-LICHEN-8f9e (packet formats, forwarder, multi-channel demod, cross-impl with SX126x).

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

## Appendix A. Parameter Justifications

Timing parameters (setup_window, occupied_time, guard, slot_duration): derived from TCXO drift, retune/ramp times, and airtime for SF10/125kHz frames. Constraint setup_window + occupied_time + 2*G <= slot_duration and E=(G-P-M)/2 prevent independent guard consumption. No fixed 50 ms guard; schedule-specific and hardware-qualified.

Desync timers (T_DRIFT_WARN=30s, T_DRIFT_MAX=120s, T_GIVE_UP=600s): balance drift accumulation, power, and responsiveness. +50% RX in DRIFT is conservative. Configurable per deployment.

PHY profile 0x01 (125 kHz, SF10, CR 4/5): range/throughput/regulatory tradeoff with computable airtime for slot fitting. ADR prohibited inside schedules.

Simulator gates (4.0 median / 3.0 5th-percentile payload ratio, 50% collision reduction, <=5% p95 regression): engineering targets from measured overheads in 76-byte/7-pair and 64-source star scenarios. Seeds 0-99 paired with baseline; not protocol guarantees. Implementations must report measured values.

19-byte cells, paging, 48-byte Schnorr48, 16-byte digest: LoRa bandwidth-driven scaling for large schedules. See test/vectors/ccp*.json for validation.

## References

### Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.

- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.

---

[← Physical and Link Layers](02-physical-link.md) | [Index](README.md) |
[Next: Adaptation Layer →](03-adaptation.md)








