<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# RPL Configuration for LoRa Mesh Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-rpl-lora-00                                        May 2026
Intended status: Experimental
Expires: November 2026
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

## Abstract

This document specifies RPL (IPv6 Routing Protocol for Low-Power and Lossy
Networks) configuration parameters optimized for LoRa mesh networks. It
addresses the unique characteristics of LoRa: very low data rates, high
latency, duty cycle restrictions, and long-range links. The profile modifies
Trickle timer parameters, defines a LoRa-specific objective function, and
specifies link-layer security integration.

## Table of Contents

1. Introduction
2. Terminology
3. LoRa Network Characteristics
4. RPL Mode of Operation
5. Objective Function
6. Trickle Timer Parameters
7. DAO and Downward Routes
8. Security
9. DIO Options
10. Implementation Considerations
11. Security Considerations
12. IANA Considerations
13. References

## 1. Introduction

RPL (RFC 6550) was designed for Low-Power and Lossy Networks (LLNs) such
as IEEE 802.15.4-based networks. LoRa networks share some characteristics
with these networks but differ significantly in:

- **Data rate:** LoRa is 10-100x slower than 802.15.4
- **Latency:** LoRa round-trip times are seconds, not milliseconds
- **Range:** LoRa links can span kilometers, not meters
- **Duty cycle:** LoRa is heavily duty-cycle restricted (1-10%)

This document specifies RPL parameters tuned for these characteristics.

### 1.1. Design Goals

- **Stable routing:** Minimize route oscillation in high-latency environment
- **Efficient control plane:** Reduce DIO/DAO overhead to preserve duty cycle
- **Long-range awareness:** Prefer shorter paths over marginally better links
- **Security:** Integrate with link-layer signature-based authentication

### 1.2. Applicability

This profile applies to LoRa mesh networks using:
- LoRa PHY (SX126x, SX127x, or similar)
- SF7-SF12, BW 125-500 kHz
- Mesh topology (not star/LoRaWAN)
- IPv6 with SCHC compression

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **DODAG:** Destination-Oriented Directed Acyclic Graph
- **DIO:** DODAG Information Object (downward advertisement)
- **DAO:** Destination Advertisement Object (upward registration)
- **DIS:** DODAG Information Solicitation
- **OF:** Objective Function (route selection algorithm)
- **MRHOF:** Minimum Rank with Hysteresis Objective Function
- **ETX:** Expected Transmission Count

## 3. LoRa Network Characteristics

### 3.1. Data Rate and Latency

| Spreading Factor | Bit Rate | Airtime (50B) | Typical RTT |
|------------------|----------|---------------|-------------|
| SF7 | 5470 bps | 72 ms | 200-500 ms |
| SF9 | 1760 bps | 206 ms | 500-1500 ms |
| SF12 | 293 bps | 1319 ms | 3-10 s |

Multi-hop RTT can exceed 30 seconds at SF12 with 3+ hops.

### 3.2. Duty Cycle

| Region | Band | Duty Cycle |
|--------|------|------------|
| EU | 868 MHz (g1) | 1% |
| EU | 868 MHz (g3) | 10% |
| US | 915 MHz | None (FCC) |
| AU | 915 MHz | None |

At 1% duty cycle with 200ms packets, maximum is 36 packets/hour.

### 3.3. Link Asymmetry

LoRa links may be asymmetric due to:
- Different TX power configurations
- Antenna placement
- Environmental factors
- Interference patterns

RPL MUST use bidirectional link verification.

## 4. RPL Mode of Operation

### 4.1. Mode Selection

This profile uses **Non-Storing Mode** exclusively:

| Aspect | Storing Mode | Non-Storing Mode |
|--------|--------------|------------------|
| Routing state | At each router | At root only |
| Downward routing | Hop-by-hop | Source routing |
| RAM required | O(network) | O(parents) |
| Root burden | Low | Higher |

Rationale: LoRa nodes are often memory-constrained. Non-storing mode
minimizes RAM requirements at routers.

Full multi-hop downward routing uses the end-to-end DAO Origin Signature Option
in Section 7.5. A DAO that fails that profile MUST NOT mutate downward route
state.

### 4.2. DODAG Configuration

| Parameter | Value | Rationale | Source |
|-----------|-------|-----------|--------|
| RPLInstanceID | 0 | Single instance | constants.toml:46, lichen-core::constants::RPL_INSTANCE_ID |
| Mode | Non-Storing (MOP=1) | Memory efficiency (root holds routes) | constants.toml:47, RPL_MODE_OF_OPERATION |
| Grounded | Yes (if BR) | Internet connectivity via 6LBR | draft-lichen-border-router |
| DAG Metric Container | Yes | Required for MRHOF ETX | RFC 6550 |

### 4.3. Multiple DODAGs

When multiple border routers exist:
- Each BR MAY form its own DODAG
- Nodes choose DODAG based on objective function
- Nodes MAY join multiple DODAGs (memory permitting)

## 5. Objective Function

### 5.1. MRHOF Adaptation

This profile uses MRHOF (RFC 6719) with LoRa-specific adaptations.

**Rank calculation:**

```
Rank = Rank(parent) + Step
Step = MinHopRankIncrease × (1 + ETX_factor × ETX + Latency_factor × RTT)
```

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| MinHopRankIncrease | 256 | Standard |
| ETX_factor | 0.5 | Reduce ETX sensitivity |
| Latency_factor | 0.1 | Mild preference for lower latency |
| PARENT_SWITCH_THRESHOLD | 192 | 0.75 × MinHopRankIncrease hysteresis |
| MAX_RANK_INCREASE | 1024 | Limit rank inflation |

### 5.2. Link Metrics

**ETX calculation:**

```
ETX = 1 / (forward_delivery × reverse_delivery)

forward_delivery = packets_acked / packets_sent
reverse_delivery = estimated from ACK reception
```

**RTT estimation:**

```
RTT_smoothed = 0.875 × RTT_smoothed + 0.125 × RTT_sample
```

### 5.3. Parent Selection

A node SHOULD switch to a new preferred parent if:

```
Rank(new_parent) + Step(new_parent) + THRESHOLD < Rank(current_parent)
```

This hysteresis prevents oscillation in noisy environments.

### 5.4. Bidirectional Verification

Before selecting a parent, verify bidirectionality:
1. Receive DIO from candidate parent
2. Send DAO to candidate parent
3. If DAO-ACK received within timeout: link is bidirectional
4. If not: mark link as unidirectional, do not use as parent

## 6. Trickle Timer Parameters

### 6.1. Standard Trickle

Trickle algorithm (RFC 6206) controls DIO transmission rate.

**Parameters:**

| Parameter | Symbol | Value | Rationale |
|-----------|--------|-------|-----------|
| Minimum interval | Imin | 4 seconds | Allow network to stabilize |
| Maximum interval | Imax | 17.5 minutes | 2^8 × Imin, reduce steady-state |
| Redundancy constant | k | 10 | High k = more suppression |

### 6.2. Interval Calculation

```
Imin = 4 s = 4000 ms
Imax = 2^8 × Imin = 256 × 4 s = 1024 s ≈ 17 minutes
```

**Behavior:**

| Network state | DIO interval |
|---------------|--------------|
| Startup/inconsistency | 4-8 seconds |
| Stabilizing | 8-64 seconds |
| Stable | 4-17 minutes |

### 6.3. Trickle Reset Triggers

Reset Trickle timer (back to Imin) on:
- DODAG version change
- Rank change
- DIO configuration change
- Loop detected

Do NOT reset on:
- New node joining (handled by DIS)
- Metric updates (allow settling)

### 6.4. DIS Handling

When a node sends DIS (solicit):
- Targeted DIS: unicast response with DIO
- Multicast DIS: reset Trickle, respond probabilistically

To prevent DIS storms:
- Rate limit DIS transmission (max 1 per 10 seconds)
- Ignore rapid DIS from same source

## 7. DAO and Downward Routes

### 7.1. DAO Timing

| Event | Timing |
|-------|--------|
| Initial DAO | Random 0-2s after parent selection |
| DAO retry | 4, 8, 16 seconds (exponential backoff) |
| DAO refresh | Every 15 minutes (50% of default lifetime) |
| DAO on parent change | Immediate (with jitter 0-500ms) |

**DAO Source Address Model:** DAO packets use routable ULA source (DODAG-root derived prefix) for multi-hop forwarding. Relays preserve the original IPv6 source end-to-end (see spec/04-network.md and SCHC Rule 4). This satisfies security requirements for source binding.

### 7.2. DAO Lifetime

```
Lifetime = DAO_LIFETIME_UNIT × DAO_LIFETIME
         = 60 seconds × 30
         = 1800 seconds = 30 minutes
```

Nodes MUST refresh DAO before lifetime expires (recommend 50% of lifetime).

### 7.3. DAO-ACK

For a newly accepted DAO that requests an acknowledgement, the root MUST send
a success DAO-ACK after replay-floor persistence. It MAY send a rejection
DAO-ACK for an invalid DAO.

An authenticated equal-sequence DAO whose complete signed-byte digest exactly
matches the stored digest is an idempotent retransmission. The root MAY resend
the same DAO-ACK and MUST NOT rewrite the replay floor. If volatile route state
is missing after a crash, it MAY repeat semantic parsing and exact self-Target
validation to reconcile that route idempotently. Equal-sequence DAOs with different bytes and
lower-sequence DAOs are rejected.

### 7.4. Source Routing Header

When the root is also the original packet source and the `/128` destination is
inside the RPL domain, it inserts an RFC 6554 Type 3 Source Routing Header that
describes the strict path to that node. The IPv6 base Destination Address is
the first hop; the SRH contains the remaining hops in the order required by
RFC 6554 processing. The originator MUST set `Segments Left` exactly to the
number of addresses in the SRH.

```
IPv6 header:
  Source: root
  Destination: hop 1

Routing Header (type 3, RFC 6554):
  Segments Left: N - 1
  Address[1]: hop 2
  ...
  Address[N-1]: target node
```

Maximum path length: 8 hops (header size constraint).

For every packet not originated by the root, including Internet-originated
traffic to a `/128`, the root MUST use the IPv6-in-IPv6 procedure in RFC 6554
Section 4.1. The same procedure is required for a prefix Target shorter than
`/128`, because that Target is not a hop address. Let `D` be the actual
destination, `E` the authenticated DAO origin authorized to advertise the
prefix, and `[H1, ..., E]` the strict mesh path. The root MUST preserve `D` in
an inner IPv6 packet and use an outer RFC 6554 route to `E`. The canonical
prefix value MUST NOT appear as a hop. At `E`, the outer destination MUST be
local and `Segments Left` MUST be zero before decapsulation. `E` MUST verify
that inner destination `D` still matches a prefix delegated to `E` before local
delivery or normal egress forwarding.

If the path has one hop, the root MAY omit the SRH but MUST retain the outer
IPv6 tunnel. If the root is `E`, it MUST route the original packet without an
RPL tunnel. The root MUST decrement the inner Hop Limit by the initial
`Segments Left`. When the root is forwarding rather than originating the inner
packet, it MUST first apply the additional normal forwarding decrement. The
initial `Segments Left` MUST be strictly less than the Hop Limit available
after any forwarding decrement. Routes that are incomplete, cyclic, or longer
than eight hops MUST be rejected rather than truncated. Packets larger than
one LoRa frame MUST use SCHC fragmentation after encapsulation and SCHC
compression. They are rejected only when the complete compressed datagram
cannot be represented by the configured SCHC fragmentation rule or no
fragmentation context exists.

### 7.5. DAO Origin Signature Option

Every DAO in this profile MUST contain exactly one DAO Origin Signature Option.
The temporary implementation value is RPL Control Message Option type `0x12`
pending IETF Review and IANA allocation. Its Data Length is 56 octets.
Deployments using this temporary value MUST coordinate to avoid collisions,
and future drafts may change it:

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Type=0x12    |  Length=56   |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 |                 Origin Sequence (8 octets)                    |
 +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                               |                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 |                                                               |
 |                    Schnorr48 (48 octets)                       |
 |                                                               |
 |                                                               |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Origin Sequence is an unsigned 64-bit integer in network byte order. Schnorr48
signs this 64-octet application message:

```
digest = SHA-512("LICHEN-DAO-ORIGIN-v1" || origin_ipv6 ||
                 effective_dodagid || origin_sequence_be ||
                 unsigned_dao_bytes)
signature = Schnorr48-Sign(origin_key, digest)
```

`"LICHEN-DAO-ORIGIN-v1"` is exactly 20 ASCII octets with no NUL terminator.
`origin_ipv6` is the 16-octet IPv6 Source Address preserved end to end.
`effective_dodagid` is the 16-octet DODAGID carried when `D=1`; when `D=0`, it
is the active DODAG's DODAGID for the DAO's RPLInstanceID.
`origin_sequence_be` is the eight on-wire sequence octets. `unsigned_dao_bytes`
is the exact byte string beginning at RPLInstanceID and ending immediately
before this option. It includes all DAO base fields, the DODAGID when `D=1`,
and every preceding option; it excludes the ICMPv6 header and this complete
option. Implementations MUST NOT decode, canonicalize, reorder, or re-encode
these bytes when constructing the transcript.

For example, the transcript concatenation is:

```
4c494348454e2d44414f2d4f524947494e2d7631  # domain, no NUL
<16-byte preserved IPv6 Source Address>
<16-byte effective DODAGID>
<8-byte big-endian Origin Sequence>
<exact DAO bytes from RPLInstanceID through the preceding option>
```

This option MUST be final. Before selecting a signature context, a receiver
MUST validate the fixed DAO base length and flags, require a configured
RPLInstanceID, derive the effective DODAGID, and require it to equal the active
DODAG for that instance. It then performs only bounds-safe option framing.
Unknown option types, missing, duplicate, or non-final origin-signature
options, trailing bytes, truncation, or any malformed option framing MUST
reject the whole DAO without semantic parsing or state mutation. An RPL Target
Option MUST have Data Length 18 (for /128); Prefix Length 128 and equality with
the origin are checked during semantic parsing. A Transit Information Option
Data Length MUST equal 20 and include the 16-octet Parent Address required by
this non-storing profile. The DAO Origin Signature Option Data Length MUST equal 56.

The verification key MUST be the 32-octet public key from an already
authenticated, pre-pinned Announce identity. The preserved source address IID
MUST equal the IID bound to that identity, and the key/IID binding MUST be
verified before signature use. An arbitrary caller-supplied or self-certified
key is insufficient. A DAO MUST NOT establish or replace an Announce identity.

Replay state is keyed by the pinned 32-octet public key, not by the full IPv6
address. Origin Sequence starts above zero, never wraps, and is strictly
monotonic for that key. Before transmitting a new logical DAO, the origin MUST
crash-safely commit a greater sequence and the complete signed DAO bytes before
transmission. Storage MUST provide atomic commit semantics or two independently
validated slots with generation numbers. Missing, corrupt, unavailable, or
partially committed state is a hard failure. The origin MUST remain fail closed
until valid state is restored or provisioned above every value previously used
with that key. At `0xffffffffffffffff`, it MUST NOT originate a new logical DAO.
The TX API MUST expose the complete retained signed DAO bytes after reboot so
an equal-sequence retry transmits those bytes exactly rather than rebuilding or
re-signing the DAO.

The root MUST crash-safely retain, per pinned public key, the accepted
high-water sequence and a collision-resistant digest of the complete signed DAO
bytes. It need not retain the received DAO or volatile route table. A greater
authenticated sequence is fresh. An equal sequence is accepted only when the
complete signed-byte digest equals the stored digest. Equal different bytes and
lower sequences are rejected. For a fresh DAO, the root MUST commit the new
floor before route use or success DAO-ACK, then atomically mutate route state in
memory. A crash between those operations may leave route state missing. An
equal retransmission does not rewrite the floor and may repeat semantic parsing
and exact self-Target validation solely to reconcile that missing route.

Relays MUST preserve the IPv6 Source Address and complete DAO bytes exactly;
they may change only Hop Limit and the enclosing hop-by-hop link frame and
signature. Link-layer fields are not DAO bytes.

The root MUST verify in this order:

1. Link framing and the immediate-hop link signature.
2. Fixed DAO base framing and flags, configured RPLInstanceID, and effective
   DODAGID equality with the active DODAG.
3. Bounds-safe framing of known option types, their exact lengths, and exactly
   one final DAO Origin Signature Option.
4. Pre-pinned Announce public-key lookup and its source-IID binding.
5. Exact transcript digest and Schnorr48 signature.
6. Crash-safe per-key sequence/digest classification, allowing only an
   identical signed DAO retransmission at the accepted high-water value.
7. DAO semantic parsing.
8. Exact self `/128` Target validation.
9. For a fresh DAO, persistence of the replay floor before route use or success
   DAO-ACK, followed by atomic in-memory route mutation. An identical
   retransmission does not rewrite the floor and may reconcile missing route
   state after a crash.

No expiry, replay, capacity, parent, or route state may be
changed before all applicable checks succeed. Any failure rejects the complete
DAO without such mutation.

### 7.6. Target Encoding

This profile requires that an authenticated DAO origin advertises exactly its own
IPv6 address as a node-owned `/128` Target. The 16 target octets MUST equal the
preserved Source Address from the IPv6 header and the Transit Information Option
MUST have `E=0`. Missing Target/Transit options, duplicates, or inconsistent
Path Sequence, Path Lifetime, or `E` values MUST reject the DAO after replay
classification.

Generalized prefix support for `/0`-`/127`, Target Descriptors, canonicalization,
and external egress (`E=1`) is future work outside current conformance scope.

### 7.6.1. Generalized Target Prefix Encoding

The Target route key is `(RPLInstanceID, DODAGID, Prefix Length, Prefix)`, with
all bits after Prefix Length cleared. A sender MUST use the minimum number of
prefix octets and set reserved flags and unused low bits to zero. Per RFC 6550,
a receiver MUST ignore reserved flags and bits beyond Prefix Length and
canonicalize its internal key. It MUST reject truncated or greater-than-128-bit
Targets before any DAOSequence replay or route mutation. Link-layer replay
state is updated independently after link authentication.

| Prefix | Prefix octets | Canonical requirement |
|--------|---------------|-----------------------|
| `/0` | 0 | `::/0`; exact root delegation required |
| `/64` | 8 | Final 64 bits cleared internally |
| `/127` | 16 | Sender sets final low bit to zero; receiver ignores it |
| `/128` | 16 | Exact address |

The authenticated DAO origin advertises every Target in its DAO and is the mesh
egress for a prefix shorter than `/128`. A Target MAY be owned by that origin
or MAY describe external reachability through it; external reachability MUST
set the Transit Information `E` flag. Forwarders MUST preserve the origin IPv6
source and ordered DAO content and MUST NOT combine Targets from different
origins.

The root MUST verify provenance under Section 7.5 and authorize each Target
before changing route state. Delegation MUST name the Target's single sequence
authority and whether the Target is node-owned (`E=0`) or external (`E=1`).
Prefix authorization is separate from provenance and remains limited to exact
static delegations. A valid origin signature conveys no implicit prefix rights.
`/0` requires an explicit exact delegation of `::/0` to that origin.

### 7.7. Target and Transit Processing

One or more Targets, each optionally followed by an RPL Target Descriptor,
followed by consecutive Transit Information options form one group; every
Transit applies to every Target in that group. This profile assigns no meaning
to Target Descriptors, but receivers MUST allow and ignore them while
preserving their bytes for provenance verification. A later Target starts a
new group. Any malformed ordering, duplicate Target, inconsistent Path
Sequence, Path Lifetime, or `E` flag among a group's Transit options, failed
authorization, cycle, or capacity failure MUST reject the entire DAO without
mutation.

DAOSequence state is per authenticated origin. Path Sequence and withdrawal
state are per canonical Target across the DODAG, and only the Target's
authorized sequence authority may originate them. Parent, egress, lifetime,
Path Control, and retention state are retained per candidate. A newer Path
Sequence replaces the complete candidate set and gives every installed edge
the accepted group's Path Lifetime. An equal sequence MUST be accepted only as
an exact idempotent copy of candidate state already installed by that
authority. The sequence authority MUST pack the complete redundant candidate
set for one Path Sequence into one atomic DAO; this profile does not accept
later equal-sequence candidate additions. Older or incomparable sequences,
forbidden equal updates, and unauthorized authorities MUST reject the complete
DAO before any DAO replay or route-state mutation. Other parent-set, Path
Control, and lifetime changes require a newer Path Sequence. Path Lifetime zero
withdraws a Target only with a newer Path Sequence from the sequence authority.

The root MUST use longest-prefix match over active, authorized Targets with a
complete path to their egress. Redundant candidates for one Target MUST be
originated by its sequence authority in one logical Path Sequence. The root
MUST mask bits outside the configured `PCS + 1` active bits, then compare each
candidate's most-preferred active non-empty Path Control subfield in PC1, PC2,
PC3, PC4 order. It MUST NOT compare complete Path Control octets or individual
bits numerically. A candidate with no active Path Control bit MUST cause atomic
DAO rejection. Candidates in the same subfield are ordered by the
lexicographically smallest complete root-to-egress address sequence.

## 8. Security

### 8.1. Security Model

This profile relies on **link-layer signatures** as the primary
security mechanism, not RPL's built-in security modes.

| RPL Security Mode | Usage |
|-------------------|-------|
| Unsecured | DEFAULT — link-layer sigs provide auth |
| Preinstalled | OPTIONAL — additional defense-in-depth |
| Authenticated | NOT RECOMMENDED — requires KDC |

### 8.2. Link-Layer Signature Protection

All RPL control messages (DIO, DAO, DIS) are link-layer frames that MUST carry Schnorr signatures per draft-lichen-link-01:4.2 (unsigned RPL control frames MUST be rejected by receivers; permissive mode is test-only). See spec/06-security.md:8.10 for full requirements.

This provides:
- Immediate-transmitter authentication
- Message integrity
- Replay protection (via epoch + sequence number)

For a forwarded DAO, the link signature authenticates only the immediate
relay. DAO-origin provenance is supplied by the mandatory DAO Origin Signature
Option in Section 7.5, which binds the preserved source, effective DODAGID,
persistent origin sequence, and exact unsigned DAO bytes. It MUST be verified
before semantic parsing, prefix authorization, or route mutation.

### 8.3. Optional Preinstalled Mode

For high-security deployments:
- Configure network-wide PSK
- Enable RPL preinstalled mode
- PSK authenticates control plane
- Defense-in-depth against compromised nodes

### 8.4. Root Verification

Nodes SHOULD verify root legitimacy:
- Root's public key should be pre-provisioned or TOFU-pinned
- Unexpected root changes should alert operator
- Multiple roots with different keys may indicate attack

## 9. DIO Options

### 9.1. Mandatory Options

| Option | When |
|--------|------|
| DODAG Configuration | Every DIO |
| Prefix Information | When advertising prefix |
| DAG Metric Container | When using MRHOF |

### 9.2. LICHEN-Specific Options

**SCHC Rule Version Option:**

```
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
  TBD      1        1 (uint8)
```

Advertises SCHC rule set version for compression compatibility.

**Time Synchronization Option:**

```
+--------+--------+--------+--------+--------+--------+
| Type   | Length | Stratum| Reserved| Timestamp (4B)  |
+--------+--------+--------+--------+--------+--------+
  TBD      1        1        1           4 (Unix epoch)
```

Provides time synchronization for replay protection.

**Congestion Level Option:**

```
+--------+--------+--------+
| Type   | Length | Level  |
+--------+--------+--------+
  TBD      1        1 (0-3)
```

Advertises node congestion for routing decisions (0-3 scale).

**Adaptive SF and RF Metrics Option (CCP-16):** The DAG Metric Container MUST include current SF per-neighbor EMA-derived recommendation, density, utilization, and metrics per CCP-16 in spec/02a-coordinated-capacity.md (sections 4.1-4.2). Nodes MUST compute TX_SF and adaptive_sf_select via the normative pseudocode there. Thresholds, EMA (alpha 0.1-0.25), and load_factor integration are normative. DIOs on CH0 provide announcements; RX scanning on control channel REQUIRED. Test vectors in test/vectors/ccp16*.json, ccp_load_balancing.json and ccp16-desync.json are the independent oracles; all implementations MUST match exactly for interop. Cross-reference capability DIO option and section 4.2 in spec/02a-coordinated-capacity.md for thresholds and EMA update.

**Root Conflict Resolution Option:**

When multiple roots advertise conflicting DODAG versions on the same RPLInstanceID,
nodes MUST detect the conflict and choose the authoritative root. This option
signals root identity for conflict resolution:

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| Type   | Length |  Flags |  Root Priority  |        Reserved       |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                     Root Public Key Fingerprint (8 bytes)               |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

Fields:
- **Type:** TBD (DIO option type for root conflict)
- **Length:** 10 (fixed)
- **Flags:** Bit 0 = authoritative (set by DODAG root), bits 1-7 reserved (zero)
- **Root Priority:** u8; lower value wins (0 = highest priority root)
- **Root Public Key Fingerprint:** First 8 bytes of SHA-512(root public key)

Nodes receiving conflicting DIOs with this option MUST:
1. Compare Root Priority; lower wins. Equal priority breaks tie by comparing
   Root Public Key Fingerprint as a big-endian unsigned integer.
2. Adopt the winning root's DODAG version and SFN.
3. Drop the losing root as a parent candidate.
4. Trigger desynchronization recovery (see 02a-coordinated-capacity.md §2a.5)
   if the node was previously synchronized to the losing root.

This option is OPTIONAL in DIO. Absence implies priority 128 and no
fingerprint verification (legacy fallback). See spec/02a-coordinated-capacity.md
§2a.2.3 for slot re-assignment after root change and test/vectors/ccp16.json,
ccp_tdma.json for conflict scenarios.

### 9.3. Prefix Information Option

When DODAG root advertises prefix:

```
+--------+--------+--------+--------+
| Type   | Length |  Flags |PrefLen |
+--------+--------+--------+--------+
|            Valid Lifetime         |
+--------+--------+--------+--------+
|          Preferred Lifetime       |
+--------+--------+--------+--------+
|              Reserved             |
+--------+--------+--------+--------+
|                                   |
|            Prefix (16 bytes)      |
|                                   |
|                                   |
+--------+--------+--------+--------+
```

## 10. Implementation Considerations

### 10.1. Memory Requirements

| Component | RAM | Notes |
|-----------|-----|-------|
| DODAG state | ~100 bytes | Version, rank, etc. |
| Parent table | ~50 bytes/parent | Typically 2-4 parents |
| Trickle state | ~20 bytes | Timers, counters |
| DAO retry state | ~20 bytes | Pending DAOs |
| **Total** | **~300 bytes** | Minimal footprint |

### 10.2. Timers

| Timer | Resolution | Notes |
|-------|------------|-------|
| Trickle | 1 second | Coarse is acceptable |
| DAO retry | 1 second | Exponential backoff |
| DAO lifetime | 1 minute | Refresh at 50% |
| Link timeout | 10 seconds | Neighbor unreachable |

### 10.3. Recommended Defaults

```c
#define RPL_INSTANCE_ID          0
#define RPL_MOP                  RPL_MOP_NON_STORING
#define RPL_TRICKLE_IMIN         (4 * 1000)    // 4 seconds
#define RPL_TRICKLE_IMAX         8             // 2^8 doublings
#define RPL_TRICKLE_K            10            // redundancy constant
#define RPL_DAO_LIFETIME_UNIT    60            // seconds
#define RPL_DAO_LIFETIME         30            // 30 minutes
#define RPL_DEFAULT_PARENT_COUNT 3             // max parents to track
#define LICHEN_RPL_PARENT_SWITCH_THRESHOLD 192 // parent switch hysteresis (0.75 × MinHopRankIncrease)
```

### 10.4. Implementation Status

The `lichen-rpl` crate (`#![no_std]`, `std` only for simulator/gateway) and the matching C port in `lichen/subsys/lichen/rpl/` fully implement the profile: DAO Origin Signature Option (temporary type 0x12, 56-octet), replay-floor persistence, non-storing source routing per RFC 6554, MRHOF+CCP-16, Trickle timers, and all verification rules. Validated bit-exactly against `test/vectors/dao_origin_vectors.rs`, `rpl_route_state_vectors.rs`, and `ccp16*.json`. This document is now the canonical normative reference; `spec/appendix-rpl.md` is non-normative summary only. Merge conflicts from parallel worktrees resolved and deduplicated.

## 11. Security Considerations

### 11.1. Routing Attacks

| Attack | Mitigation |
|--------|------------|
| DIO spoofing | Link-layer signatures |
| Rank manipulation | Hysteresis, neighbor validation |
| DAO flooding | Rate limiting, lifetime enforcement |
| DODAG partition | Root demotion protocol |

### 11.2. Sybil Attacks

An attacker with multiple identities could:
- Create fake routes
- Attract traffic to black hole
- Disrupt routing

Mitigation: EUI-64 bound to public key prevents identity forging.

### 11.3. Wormhole Attacks

Attacker relays DIO across mesh, advertising false proximity.

Partial mitigation:
- RTT-based rank calculation penalizes high-latency links
- Geographic verification (if GPS available)

Full mitigation requires secure localization, out of scope.

## 12. IANA Considerations

This document requests allocation under the IETF Review policy of:

- RPL Control Message Option type `0x12` for the DAO Origin Signature Option.
  Implementations use `0x12` temporarily pending IETF Review and IANA
  assignment; its Data Length is fixed at 56 octets.
  Deployments MUST coordinate use to avoid collisions. Future drafts may
  change this value, and implementations MUST use the allocated value when one
  is assigned.
- RPL DIO Option Types for:
  - SCHC Rule Version
  - Time Synchronization
  - Congestion Level

Specific values TBD.

## 13. References

### 13.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 6550] RPL: IPv6 Routing Protocol for LLNs
- [RFC 6554] RPL Source Routing Header
- [RFC 6206] The Trickle Algorithm
- [RFC 6719] MRHOF for RPL

### 13.2. Informative References

- [RFC 6551] RPL Metrics
- [LICHEN] LICHEN Protocol Specification

## Appendix A. Sample DODAG Configuration

```
RPLInstanceID: 0
DODAGID: 0200:1234:5678:9abc::1
Version: 1
Rank: 256 (root)
Mode: Non-Storing
Grounded: Yes
DTSN: 0
Flags: 0

Trickle:
  Imin: 4s
  Imax: 8 doublings (17 min)
  k: 10

# No prefix advertisement (02xx addresses are self-derived from key)
Valid Lifetime: 86400s (1 day)
Preferred Lifetime: 43200s (12 hours)
```

## Appendix B. Parent Selection Example

MRHOF parent selection uses the DAG Metric Container (including SF, density, EMA from CCP-16 per spec/02a-coordinated-capacity.md) with hysteresis (LICHEN_RPL_PARENT_SWITCH_THRESHOLD=192 default per rpl_dodag.h and lichen-rpl). Worked examples are validated against test vectors in ccp16.json and rpl_route_state_vectors.rs.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
