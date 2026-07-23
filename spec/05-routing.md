<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Routing

## 7. Routing Overview

### 7.1. Three-Tier Architecture

LICHEN uses a three-tier routing architecture optimized for different traffic patterns:

| Tier | Protocol | Traffic Type | Mechanism |
|------|----------|--------------|-----------|
| 1 | **RPL** | Border router ↔ mesh | Proactive DODAG tree |
| 2 | **Announce** | Peer-to-peer (active nodes) | Proactive gradient |
| 3 | **LOADng** | Peer-to-peer (fallback) | Reactive discovery |

**Rationale:**

- **RPL** excels at tree-shaped traffic (sensor → gateway → cloud). Most IoT traffic fits this pattern.

- **Announce routing** provides instant peer-to-peer paths for active mesh participants. Nodes that announce are immediately reachable via gradient following. No discovery latency.

- **LOADng** handles edge cases: new nodes, nodes that missed announces, or rarely-contacted destinations. Reactive discovery when gradient doesn't exist.

### 7.2. Routing Decision

Routing prefers **local mesh first** for 02xx addresses (gradient, LOADng, RPL) before Yggdrasil fallback. Link-local is always direct. `is_off_mesh()` reflects the single-primary 02xx model (no ULA/GUA).

```
def route_packet(dst):
    if is_02xx_off_mesh(dst):
        # 02xx destination not in local mesh routes (use Yggdrasil via BR)
        return forward_to_rpl_parent()

    if is_02xx(dst):  # Yggdrasil-derived primary (per 04-network.md §6.1, 06-security.md)
        # Local mesh first
        gradient = gradient_table.lookup(dst)
        if gradient and not gradient.expired:
            # Known peer via announce/LOADng/RPL
            return forward_to(gradient.next_hop)

        if rpl_route := rpl_lookup(dst):
            return forward_via_rpl(rpl_route)

        # No local route: Yggdrasil fallback (via BR TUN for off-mesh 02xx)
        return yggdrasil_forward(dst)
    else:
        # Non-02xx: off-mesh via RPL/BR
        return forward_to_rpl_parent()
```

**Updated `is_off_mesh()`:**

```
def is_off_mesh(dst):
    """True if destination cannot use local mesh (gradient/LOADng/RPL).
    For 02xx: only after local-mesh-first check fails (then Yggdrasil).
    Link-local: always False. Non-02xx: True. Removed GUA/ULA refs.
    """
    if is_link_local(dst):
        return False
    if not is_02xx(dst):
        return True
    # 02xx local-mesh-first
    return (gradient_table.lookup(dst) is None and not has_rpl_route(dst))
```

**Address classification:**

| Address Type | Classification | Routing |
|--------------|----------------|---------|
| Link-local (fe80::/10) | Direct neighbor | Send to neighbor |
| Primary (02xx::/7 Yggdrasil-derived per 06-security) | Local mesh peer | Gradient or LOADng |
| Primary (02xx::/7) off-mesh | Yggdrasil-routable | RPL to border router |
| Other/Unknown | Off-mesh | RPL to border router |

Addresses are primary 02xx::/7 derived from Ed25519 pubkey (see 06-security.md §8.5 and 04-network.md §6.1). No ULA or GUA.

### 7.3. Conformance Requirements

Keywords per RFC 2119. Device classes:

| Class | Example | RAM | Description |
|-------|---------|-----|-------------|
| **Constrained** | STM32WL | ≤64 KB | Battery-powered sensors/actuators |
| **Router** | ESP32, RPi | ≥256 KB | Powered relay nodes |
| **Border Router** | RPi, server | ≥1 MB | Internet gateway |

**Core Protocol (All Devices):**

| Feature | Constrained | Router | BR |
|---------|-------------|--------|-----|
| RPL join (DIO/DIS/DAO) | MUST | MUST | MUST |
| Announce send | MUST | MUST | MUST |
| Announce receive + gradient install | MUST | MUST | MUST |
| Announce relay | SHOULD | MUST | MUST |
| LOADng originate (RREQ/RREP) | MUST | MUST | MUST |
| LOADng relay | SHOULD | MUST | MUST |
| Gradient table (§11) | MUST | MUST | MUST |

**Extended Features (Routers Only):**

| Feature | Constrained | Router | BR |
|---------|-------------|--------|-----|
| Geographic coords in announce (§9.7) | MAY | MAY | MAY |
| GPSR fallback (§9.7) | -- | MAY | MAY |
| Backpressure tracking (§11.4) | -- | MAY | SHOULD |
| Store-and-forward / DTN (§9.8) | -- | MAY | SHOULD |
| Opportunistic forwarding (§9.9) | -- | MAY | MAY |

**Notes:**

- "--" means feature not applicable (insufficient resources).
- Constrained nodes MAY set DTN S-flag but do not buffer.
- Constrained nodes use unicast forwarding only (no opportunistic).
- All MAY features are independently optional; implement any subset.

---

## 8. RPL (Border Router Traffic)

### 8.1. Purpose

RPL (RFC 6550) handles traffic to and from border routers:
- **Upward:** Mesh nodes → Border router → Internet
- **Downward:** Internet → Border router → Mesh nodes (source routed)

RPL is NOT used for peer-to-peer mesh traffic (see Sections 9-10).

### 8.2. DODAG Topology

```
                    [Border Router]
                    (DODAG Root)
                         |
              +----------+----------+
              |                     |
          [Router 1]            [Router 2]
              |                     |
        +-----+-----+         +-----+-----+
        |           |         |           |
    [Node A]    [Node B]  [Node C]    [Node D]
```

### 8.3. Configuration

| Parameter | Value |
|-----------|-------|
| Mode | Non-storing (MOP=1) |
| Objective Function | MRHOF with ETX |
| Trickle Imin | 4 sec |
| Trickle Imax | 17 min |

See Appendix B for full RPL configuration.

### 8.4. Control Messages

| Message | Purpose |
|---------|---------|
| DIO | DODAG advertisement (downward flood) |
| DIS | Solicit DIO (join request) |
| DAO | Route advertisement to root |
| DAO-ACK | Confirm DAO receipt |

### 8.5. Downward Routing

Non-storing mode: the root source-routes downward packets to a mesh node's
primary 02xx address (or future authorized egress). All nodes self-derive their
primary 02xx::/7 address per 04-network.md and 06-security.md; no ULA prefix is
advertised by the root.

Full multi-hop downward routing uses the end-to-end DAO Origin Signature
Option in Section 8.6. A DAO that does not satisfy that profile MUST NOT create,
refresh, withdraw, or otherwise mutate downward route state.

### 8.6. DAO Origin Signature Option

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
is computed with the origin key over the 64-octet digest (origin IPv6 address
MUST be the sender's primary 02xx address):

```
SHA-512("LICHEN-DAO-ORIGIN-v1" || origin IPv6 address ||
        effective DODAGID || Origin Sequence || unsigned DAO bytes)
```

The domain is exactly the 20 ASCII octets shown, with no terminating NUL.
Origin Sequence is included as its eight on-wire big-endian octets. The origin
IPv6 address is the 16-octet primary 02xx Source Address preserved end to end.
The
effective DODAGID is the 16-octet DODAGID in a DAO with `D=1`, or the active
DODAG's 16-octet DODAGID for the DAO's RPLInstanceID when `D=0`. The unsigned
DAO bytes are the exact received bytes beginning with RPLInstanceID and ending
immediately before this option, including the DAO base fields, an explicit
DODAGID when present, and every preceding option. They exclude the ICMPv6
header and the complete DAO Origin Signature Option. No field is decoded,
normalized, reordered, or re-encoded for this transcript.

The option MUST be the final DAO option. Before selecting a signature context,
a receiver performs only bounds-safe structural processing: validate the fixed
DAO base length and flags, require a configured RPLInstanceID, derive the
effective DODAGID, and require it to equal the active DODAG for that instance.
It then frames every option without interpreting route semantics. Unknown
option types, a missing, duplicate, or non-final DAO Origin Signature Option,
an incorrect length, trailing bytes, truncation, or any other malformed option
framing MUST reject the entire DAO without semantic parsing or state mutation.
Each RPL Target Option in `.44.7` MUST have Data Length 18 exactly. Prefix
Length 128 and equality with the origin are checked during semantic parsing.
Each Transit Information Option MUST have Data Length 20 and carry its 16-octet
Parent Address, as required by this non-storing profile. The DAO Origin
Signature Option MUST have Data Length 56.

The verification key MUST be the 32-octet public key from an already
authenticated and pinned Announce identity. The preserved source address IID
MUST equal that identity's bound IID, and the key-to-IID binding MUST be valid
before the key is used. An arbitrary caller-supplied or self-certified key is
insufficient. Receipt of a DAO MUST NOT create or replace an Announce pin.

Replay state is keyed by the pinned 32-octet public key, not by the full IPv6
address. Origin Sequence starts above zero, never wraps, and is strictly
monotonic for that key. Before transmitting a new logical DAO, including any
change to the signed DAO bytes, the origin MUST crash-safely commit the greater
sequence and complete signed DAO bytes before transmission. The storage backend
MUST provide atomic commit semantics or use two independently validated slots
with generation numbers so interruption cannot expose a partially written
record. Missing, corrupt, or unavailable state is a hard failure: the origin
MUST NOT transmit until valid state is restored or provisioned above every
value previously used with that key. At `0xffffffffffffffff`, it MUST NOT
originate another logical DAO or wrap the sequence.

The receiver MUST maintain crash-safe persistent state per pinned public key
containing the accepted high-water sequence and a collision-resistant digest
of the complete signed DAO bytes. It need not persist the complete received DAO
or volatile route tables. A greater authenticated sequence is fresh. An equal
sequence is accepted only when the digest of the complete signed DAO, including
the Origin Signature Option, equals the stored digest; it is an idempotent
retransmission. An equal sequence with different bytes or a lower sequence MUST
be rejected. Missing, corrupt, or unavailable receive state MUST fail closed.

For a fresh DAO, the receiver MUST durably commit the new `(sequence, digest)`
floor before using the route or sending a success DAO-ACK. Route mutation then
occurs atomically in memory. A crash after the floor commit but before route
mutation can therefore leave a durable floor with missing volatile route state.
On a byte-identical retransmission, the receiver MUST NOT rewrite the replay
floor. If the route state is already present it performs no route mutation; if
route state is missing after restart, it MAY repeat semantic parsing and exact
self-Target validation and idempotently reconstruct that route state. This reconciliation
closes the crash window without requiring an impossible atomic transaction
across persistent replay storage and RAM routing tables.

On TX, the crash-safe record MUST contain the complete last signed DAO bytes in
addition to its sequence, and the TX API MUST expose those exact retained bytes
after reboot for retransmission.

Relays MUST preserve the IPv6 Source Address and complete DAO bytes exactly.
They may change only the IPv6 Hop Limit and the enclosing hop-by-hop link frame
and signature; none of those link-layer fields are DAO bytes.

The root MUST process a received DAO in this order: (1) link framing and link
signature; (2) bounds-safe DAO structure and active instance/DODAG context;
(3) pre-pinned key lookup, source-IID binding, exact transcript, and Schnorr48;
(4) per-key replay classification; (5) DAO semantic parsing; (6) exact self
`/128` Target validation; (7) replay-floor persistence for a fresh DAO; and (8) atomic
in-memory route mutation. Structural failure always precedes replay. Conversely,
a structurally and cryptographically valid lower sequence is rejected as replay
before malformed route semantics or a Target unequal to the preserved source is considered.
Failure at any step rejects the complete DAO without expiry, replay-floor,
capacity, parent, persistent-storage, or route mutation, except
for the explicit post-crash reconciliation described above.

### 8.7. DAO Target for the Current Profile

The current `.44.7` profile supports exactly one node-owned Target: the
authenticated origin's own primary 02xx IPv6 address encoded as a `/128`. The
Target Prefix Length MUST be 128, its 16 octets MUST equal the preserved DAO
Source Address (which is the origin's primary 02xx address), and the Transit
external (`E`) flag MUST be zero. Missing Target or Transit options, duplicate
Targets, nonzero `E`, or inconsistent Path Sequence or Path Lifetime values
across Transits MUST reject the DAO after replay classification and before route
or replay-floor mutation.

The generalized prefix model below is reserved for future `.44.9` work. It is
not part of `.44.7` conformance, and current implementations MUST NOT infer
support for prefix lengths other than /128, Target Descriptors, prefix
canonicalization, or external egress (`E=1`). All current DAO Targets use the
self-derived primary 02xx /128.

### 8.7.1. Future Generalized DAO Target Prefixes

An RPL Target is identified by `(RPLInstanceID, DODAGID, Prefix Length,
Prefix)`. In the no-ULA 02xx model, all nodes use self-derived primary 02xx
addresses; prefix advertisement is not used for DODAG formation. The Prefix MUST
have every bit after Prefix Length cleared. Target senders MUST use the minimum
number of prefix octets and set reserved flags and unused prefix bits to zero.
As required by RFC 6550, receivers MUST ignore reserved flags and bits beyond
Prefix Length, then canonicalize the internal key. Receivers MUST reject
truncated prefixes and prefix lengths greater than 128 without mutating
DAOSequence replay or routing state. Link-layer replay state is updated
independently after link authentication.

The required boundary encodings are:

| Prefix | Prefix octets | Rule |
|--------|---------------|------|
| `/0` | 0 | Canonical key is `::/0`; installation requires an exact `/0` delegation |
| `/64` | 8 | Remaining 64 bits are zero in the canonical key |
| `/127` | 16 | Sender sets the low bit of the final octet to zero; receiver ignores it |
| `/128` | 16 | Exact primary 02xx IPv6 address |

The authenticated DAO origin advertises every Target in that DAO and is the
mesh egress for a prefix shorter than `/128`. A Target MAY be owned by that
origin or MAY describe external reachability through it; external reachability
MUST use the Transit Information `E` flag. A Target prefix is reachability
information, not a hop address; its zero-filled canonical value MUST NOT be
inserted into a source route. Forwarders MUST preserve the DAO IPv6 source (the
origin's primary 02xx address) and the ordered DAO content. They MUST NOT
aggregate Targets from different origins into a newly originated DAO.

The root MUST verify DAO provenance as specified in Section 8.6 and authorize
every canonical Target against that origin before changing route state.
Delegation MUST name the Target's single sequence authority and whether the
Target is node-owned (`E=0`) or external (`E=1`). Prefix authorization is
separate from origin-signature verification and consists only of exact static
delegations; successful provenance MUST NOT imply authorization for any
prefix. `/0` is authorized only by an explicit exact delegation of `::/0` to
that origin. Prefix-authorization policy is specified separately in Section
.44.9.2.

### 8.8. Grouping and Route State

One or more Target options, each optionally followed by an RPL Target
Descriptor, followed by one or more consecutive Transit Information options
form a group. Every Transit applies to every Target in that group. This profile
assigns no semantics to Target Descriptors, but receivers MUST allow and ignore
them while preserving their bytes for provenance verification. A Target after
a Transit starts a new group. Malformed ordering, duplicate Targets,
inconsistent Path Sequence, Path Lifetime, or `E` flag among a group's Transit
options, failed authorization, cycles, or any capacity failure MUST reject the
complete DAO without mutation.

DAOSequence freshness is scoped to the authenticated origin. Path Sequence and
withdrawal state are scoped to the canonical Target across the DODAG, and only
the Target's authorized sequence authority may originate them. Parent, egress,
lifetime, Path Control, and replay-retention state are retained per candidate.
A newer Path Sequence replaces the complete candidate set and gives every
installed edge the accepted group's Path Lifetime. An equal sequence MUST be
accepted only when it is an exact idempotent copy of candidate state already
installed by that authority. The sequence authority MUST pack the complete
redundant candidate set for one Path Sequence into one atomic DAO; this profile
does not accept later equal-sequence candidate additions. Older or incomparable
sequences, forbidden equal updates, and unauthorized authorities MUST reject
the complete DAO before any DAO replay or route-state mutation. Other
parent-set, Path Control, or lifetime changes require a newer Path Sequence. A
zero Path Lifetime withdraws the Target only when its Path Sequence is newer
and its origin is the sequence authority.

Lookup MUST consider only authenticated, authorized, unexpired Targets having
a complete acyclic path to their egress. It MUST select the greatest matching
Prefix Length. A less-specific route remains eligible when a more-specific
route expires or is withdrawn. Redundant candidates for one Target MUST be
originated by its sequence authority in one logical Path Sequence. The root
MUST mask bits outside the configured `PCS + 1` active bits, then compare each
candidate's most-preferred active non-empty Path Control subfield in PC1, PC2,
PC3, PC4 order. It MUST NOT compare complete Path Control octets or individual
bits numerically. A candidate with no active Path Control bit MUST cause atomic
DAO rejection. Candidates in the same subfield are ordered by the
lexicographically smallest complete root-to-egress address sequence.

### 8.9. Prefix Source Routing (02xx Model)

Let `D` be the actual destination (primary 02xx) and `E` the authenticated
origin and egress for the selected Target (typically the node owning that 02xx
/128). The root builds the strict mesh path to `E`, not to a canonical prefix.
Whenever the root source-routes a packet it did not originate, including
traffic to an in-domain 02xx `/128`, it MUST use IPv6-in-IPv6 as specified by
RFC 6554. Routes require tunneling because the mesh path terminates at `E`
before final delivery to `D`:

- The inner IPv6 destination remains `D` (02xx address).
- The outer IPv6 destination and RPL Source Routing Header describe only the
  strict path from the root to `E`.
- `E` decapsulates and forwards locally after verifying the inner destination
  matches its authorized primary 02xx (or future delegated prefix).
- The route MUST NOT be emitted if it is incomplete, cyclic, or over eight
  hops. After encapsulation and SCHC compression, datagrams larger than one
  LoRa frame MUST use SCHC fragmentation as specified in Section 5.
- The root MUST decrement the inner Hop Limit by the initial `Segments Left`.
  When the root is forwarding rather than originating the inner packet, it
  MUST first apply the additional normal forwarding decrement. The initial
  `Segments Left` MUST be strictly less than the Hop Limit available after any
  forwarding decrement.

If the root is itself `E`, it routes the original packet through its egress
without an RPL source-route tunnel. All examples and logic use primary 02xx
addresses consistently; no ULA or GUA assumptions.

---

## 9. Announce Routing (Peer-to-Peer Primary)

### 9.1. Purpose

Announce routing provides zero-latency peer-to-peer paths for active mesh participants. Nodes periodically broadcast signed announcements; other nodes build gradients toward announcers.

**Key insight:** Most peer-to-peer traffic is between nodes that are actively participating in the mesh. These nodes announce regularly. No discovery needed.

### 9.2. Announce Message (CCP-9 updated)

Nodes broadcast announces periodically inside the L2 routing/control namespace.
The authenticated link payload is `0x15 || announce` (L2 dispatch `0x15` per
`test/vectors/l2_payload.json:routing_announce_min`), where the announce bytes
begin with Type `0x01`. Receivers MUST NOT treat an unwrapped link payload
beginning with `0x01` as an announce because SCHC global CoAP also uses rule ID
`0x01`.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x01   | rx_channel         | Hop Cnt | Seq Num (BE u16)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator IID (8 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Public Key (32 bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes Schnorr48)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Optional: App Data (variable)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fixed announce size: 93 bytes (type(1)+flags/rx_channel(1)+hop(1)+seq(2)+IID(8)+pubkey(32)+sig(48)); total L2 payload ~94 bytes minimum. `rx_channel` (0-7) packed in flags byte at announce offset 1 (per `_l2_announce_with_channel` oracle in `test/vectors/generate.py` and `ccp9.json`).

**Fields:**
- **Type:** `0x01` – Announce identifier (inside L2 routing dispatch `0x15`).
- **rx_channel:** Preferred RX channel for da2q rendezvous (0=CH0 control fallback, packed in flags byte at offset 1). MUST be <8. Included in signed_data (CCP-9) to prevent tampering.
- **Hop Count:** Incremented by each relay (MUST NOT be signed).
- **Seq Num:** 16-bit big-endian monotonic counter per originator (duplicate/freshness).
- **Originator IID:** 8-byte Interface Identifier of announcer.
- **Public Key:** 32-byte public key.
- **Signature:** 48-byte Schnorr signature (draft-lichen-schnorr-00.md).
- **App Data:** Optional variable-length authenticated application data (node name, capabilities, coordinates per §9.7).

**signed_data (Schnorr profile-specific transcript):** originator_iid(8) || pubkey(32) || seq_num(2) || rx_channel(1) || app_data (see rust/lichen-core/src/announce.rs:90 and lichen/subsys/lichen/routing/announce.c:129). Hop excluded (relays increment it). rx_channel signed per CCP-9.

> "For different profiles the signed message (`msg` in §4.2) is defined by the using specification" (draft-lichen-schnorr-00.md:5.5 on profile-specific transcripts; here CCP-9 + announce per rust/lichen-core/src/announce.rs:142 and ccp9.json).

### 9.3. Announce Processing

**On receive announce (after L2 unwrap + parse):**

```
def process_announce(announce, from_neighbor):
    if not verify_schnorr(announce.pubkey, announce.signature, announce.signed_data):
        drop("invalid signature")
        return

    # Check for duplicate/old
    existing = gradient_table.get(announce.originator)
    if existing and existing.seq_num >= announce.seq_num:
        drop("stale announce")
        return

    # Install/update gradient
    gradient_table.update(
        destination=announce.originator,
        next_hop=from_neighbor,
        hop_count=announce.hop_count,
        seq_num=announce.seq_num,
        source="announce",
        expires=now() + GRADIENT_TIMEOUT
    )

    # Forward if hop count allows
    if announce.hop_count < MAX_ANNOUNCE_HOPS:
        announce.hop_count += 1
        broadcast(announce)
```

`now()` returns current TDMA slot/ASN per Slot struct (see draft-lichen-tdma for SFN interaction).

### 9.4. Announce Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| ANNOUNCE_INTERVAL | 300 sec | Time between announces |
| MAX_ANNOUNCE_HOPS | 15 | Maximum propagation |
| GRADIENT_TIMEOUT | 600 sec | 2× announce interval |
| ANNOUNCE_JITTER | 0-30 sec | Random delay to prevent collision |

### 9.5. Bandwidth Budget

For a 20-node mesh:
- 20 nodes × 92 bytes × 12 announces/hr = 22 KB/hr
- At SF10/125kHz: ~15 seconds airtime/hr network-wide
- ~0.04% of 1% duty cycle

Acceptable overhead for instant peer-to-peer routing.

### 9.6. Security

Announces are self-authenticating:
1. Signature proves sender holds private key for pubkey
2. TOFU binding associates pubkey with IID
3. Cannot forge announce for another node's address

First announce from a new node establishes TOFU binding.

### 9.7. Geographic Fallback (GPSR)

When gradient is missing and LOADng times out, nodes with GPS can fall back to geographic routing.

**Coordinates in App Data:**

```
App Data (coords present):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x01 |             LatE7 (4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         LonE7 (4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type 0x01:** Geographic coordinates present
- **LatE7/LonE7:** Signed 32-bit fixed-point, 1e-7 degree resolution
  - Range: latitude MUST be within ±90°, longitude MUST be within ±180°
  - Encoding: `(degrees * 10000000)` as a signed 32-bit integer in network byte order
  - Rationale: e7 coordinates cover the full geographic range and match the
    firmware/HAL and Meshtastic position representation.

**GradientEntry Extension:**

Nodes store coords from announces:
```
coords: (lat, lon) | None  # from app_data if present
```

The coordinates are peer-owned routing metadata. A receiver MUST NOT treat
coordinates from another node's announce as the receiver's own physical
location by default. Border routers and gateways MAY expose a derived
`NETWORK` location only when an explicit local policy enables approximate
mesh-derived location fallback. Such a derived location MUST preserve
provenance (`source_class=NETWORK`, source name such as `mesh-announce`), MUST
be withdrawn or marked stale when the underlying announce expires, and MUST NOT
upgrade the peer's fix source to local GNSS, manual/static, or local-client
location. It MUST NOT outrank a fresh local position provider such as onboard
GNSS, external GNSS, manual/static configuration, or a local-client position.
The derived location is an approximation useful for diagnostics and coarse mesh
context, not a privacy-neutral replacement for this node's own position
provider.

Type `0x01` coordinate app data carries no Unix fix timestamp. Firmware
build/provision epoch floors apply only if another network source submits a
wall-clock or fix timestamp to the shared time provider; they do not make
coordinate-only announce metadata fresh or trustworthy by themselves.

**GPSR Forwarding:**

```
def gpsr_forward(dst_coords, packet):
    # Find neighbor closest to destination
    best = None
    best_dist = my_distance_to(dst_coords)  # greedy progress required

    for neighbor in neighbor_table:
        if neighbor.coords is None:
            continue
        d = distance(neighbor.coords, dst_coords)
        if d < best_dist:
            best_dist = d
            best = neighbor

    if best:
        forward_to(best)
    else:
        # Local minimum - perimeter mode or drop
        drop("gpsr: no progress")  # ponytail: perimeter mode if needed later
```

**When GPSR is attempted:**
1. No gradient for destination
2. LOADng RREQ timed out (RREQ_RETRIES exhausted)
3. Destination coords known (from previous announce or out-of-band)
4. At least one neighbor has coords

**Privacy:**

Coords reveal physical location. Nodes MAY omit coords from announces if privacy is required. GPSR fallback unavailable for such nodes.

Relays and border routers that store announce coordinates MUST apply the same
freshness and provenance rules when presenting them outside the routing table.
Publishing another peer's coordinates as local status without explicit
approximate-location policy is forbidden, even when the announce signature and
TOFU binding are valid.

### 9.8. Store-and-Forward (DTN)

Border routers MAY buffer messages for unreachable destinations, delivering when a path appears.

**When used:**
- Destination has no gradient and LOADng fails
- Message has store-and-forward flag set
- Router has buffer space

**Message Header Extension:**

```
DTN Flags (1 byte in IPv6 hop-by-hop options):
+-+-+-+-+-+-+-+-+
|S|   Reserved  |
+-+-+-+-+-+-+-+-+
S = Store-and-forward requested
```

**Absolute TTL:**

Store-and-forward messages carry absolute expiry (Unix timestamp, 4 bytes)
instead of hop limit. Expired messages are dropped silently. Expiry
comparison requires valid wall-clock time from the firmware time provider
(see `docs/firmware-time-provider.md`). Nodes without valid wall-clock time
MUST NOT drop messages based on expiry timestamp alone; they SHOULD forward
or store messages and let downstream nodes with valid time enforce expiry.

```
App Data (DTN expiry):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x03 | Expiry (4 bytes, UTC)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Storage Policy:**

| Parameter | Value |
|-----------|-------|
| Max buffer | 64 KB per router |
| Eviction | Oldest-first when full |
| Default TTL | 24 hours |
| Max TTL | 7 days |

**Handoff via Announce:**

Routers with buffered messages advertise pending destinations:

```
App Data (pending destinations):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x04 | Count | IID₁ (8B) | IID₂ (8B) ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

When a node sees its IID in a pending list, it sends a pull request to retrieve buffered messages.

**Scope:**

Border routers and powered routers only. Constrained nodes set the S flag but do not buffer--they forward or drop.

<!-- ponytail: spray-and-wait if single-copy delivery too slow -->

### 9.9. Opportunistic Forwarding (Optional)

Routers MAY use coordinated broadcast forwarding to exploit LoRa's broadcast nature in lossy conditions.

**Concept:**

Instead of unicast to one next-hop, broadcast once. Multiple receivers hear it; the best one forwards, others suppress.

**Forwarder List:**

Sender includes ranked forwarder candidates (by hop count to destination):

```
Opportunistic Header (after IPv6 header):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=OPP | Count | IID₁ (8B) | IID₂ (8B) | ...     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Count:** Number of candidate forwarders (1-4)
- **IIDₙ:** Candidates ranked best-first (lowest hop count to destination)

**Timed Suppression:**

Each candidate waits before forwarding:

```
def opportunistic_forward(packet, my_rank):
    wait_time = my_rank * SLOT_TIME  # rank 0 = immediate
    wait(wait_time)

    if heard_forward_from_better_rank:
        suppress()  # higher-priority node handled it
    else:
        forward(packet)
```

| Parameter | Value |
|-----------|-------|
| SLOT_TIME | 100 ms |
| MAX_CANDIDATES | 4 |

**When Used:**

Sender chooses opportunistic mode when:
- Multiple neighbors have gradient to destination
- Link quality is poor (high packet loss observed)

**Scope:**

Routers only. Constrained nodes use standard unicast forwarding--timing coordination adds code complexity.

<!-- ponytail: no ACK-based batch, add if throughput matters -->

---

## 10. LOADng (Peer-to-Peer Fallback)

### 10.1. Purpose

LOADng provides reactive route discovery when no gradient exists:
- New nodes not yet heard announcing
- Nodes that stopped announcing (sleeping, failed)
- First contact before any announce received

### 10.2. When LOADng is Used

```
if gradient_table.lookup(dst) returns None or expired:
    initiate LOADng discovery
```

### 10.3. Route Request (RREQ)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREQ | Flags     | Hop Limit   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREQ is flooded. Each node:
1. If I am destination → send RREP
2. If I have gradient to destination → send RREP (intermediate reply)
3. If seen before (originator + seq) → drop
4. Otherwise → record reverse gradient, decrement hop limit, rebroadcast

### 10.4. Route Reply (RREP)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREP | Flags     | Hop Count   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREP follows reverse path. Each hop installs forward gradient.

### 10.5. Gradient Unification

RREP installs the same gradient entry as announces:

```
gradient_table.update(
    destination=rrep.destination,
    next_hop=from_neighbor,
    hop_count=rrep.hop_count,
    source="rrep",  # different source, same table
    expires=now() + GRADIENT_TIMEOUT
)
```

Once discovered, the destination is in gradient table. Future traffic uses gradient, not LOADng.

### 10.6. Route Error (RERR)

When link fails, send RERR toward affected sources. Recipients invalidate gradient entries through broken link.

### 10.7. Parameters

| Parameter | Value |
|-----------|-------|
| RREQ_WAIT_TIME | 5 sec |
| RREQ_RETRIES | 3 |
| INITIAL_HOP_LIMIT | 4 (expanding ring) |
| MAX_HOP_LIMIT | 15 |

See Appendix B2 for full LOADng configuration.

---

## 11. Gradient Table

### 11.1. Unified Structure

All routing methods populate a single gradient table:

```
GradientEntry:
    destination: IID or IPv6Address
    next_hop: link-local address of neighbor
    hop_count: distance in hops
    seq_num: for freshness comparison
    source: "announce" | "rrep" | "data" | "rpl"
    expires: timestamp
    coords: (lat, lon) | None  # from announce app_data (§9.7)
```

### 11.2. Passive Learning

Forwarding nodes can learn gradients from data traffic:

```
on_forward_packet(packet, from_neighbor):
    # I just received a packet FROM this source
    # Therefore, to REACH this source, send to from_neighbor
    gradient_table.update(
        destination=packet.source,
        next_hop=from_neighbor,
        source="data",
        expires=now() + DATA_GRADIENT_TIMEOUT
    )
```

DATA_GRADIENT_TIMEOUT is shorter (60 sec) since it's opportunistic.

### 11.3. Entry Priority

When multiple sources provide gradient for same destination:

| Source | Priority | Rationale |
|--------|----------|-----------|
| announce | High | Explicitly advertised, fresh |
| rrep | High | Explicitly discovered |
| data | Low | Opportunistic, may be stale |

Higher priority entry replaces lower. Same priority: prefer lower hop count, then lower congestion (§11.4).

### 11.4. Backpressure (Optional)

Routers MAY track neighbor congestion to spread load across alternate paths.

**Neighbor Queue Depth:**

```
NeighborEntry (extended):
    queue_depth: uint8  # packets queued toward this neighbor
```

Incremented when packet enqueued, decremented on TX complete or drop.

**Congestion in Announces:**

Routers MAY include queue depth in app_data:

```
App Data (congestion):
+-+-+-+-+-+-+-+-+
| Type=0x02 | Q |
+-+-+-+-+-+-+-+-+
```

- **Type 0x02:** Congestion indicator
- **Q:** Current outbound queue depth (0-255)

**Path Selection:**

When multiple next-hops have equal hop count:

```
def select_next_hop(candidates):
    # Prefer least-congested path. See Section 2a.2 of draft-lichen-tdma
    # for TDMA channel selection + now() SFN wrap semantics (unsigned modular arithmetic).
    return min(candidates, key=lambda n: n.queue_depth)
```

**Scope:**

Border routers and powered routers only. Constrained nodes (≤64KB RAM) skip backpressure tracking--the memory cost exceeds the benefit at low traffic volumes.

<!-- ponytail: no per-flow fairness, add if starvation observed -->

---

## 12. Summary

```
                         ┌─────────────────┐
                         │  Border Router  │
                         │   (Internet)    │
                         └────────┬────────┘
                                  │
                            RPL (DODAG)
                          upward/downward
                                  │
┌─────────────────────────────────┴─────────────────────────────────┐
│                                                                    │
│    Node A ◄──────── Gradient ────────► Node B                     │
│       │            (from announces)        │                       │
│       │                                    │                       │
│    Node C ◄─── LOADng (if no gradient) ──► Node D                 │
│                                                                    │
│                      Mesh Interior                                 │
└────────────────────────────────────────────────────────────────────┘
```

| Traffic | Primary | Fallback |
|---------|---------|----------|
| To/from internet | RPL | -- |
| Peer (active node) | Announce gradient | LOADng |
| Peer (unknown node) | LOADng | RPL via root (inefficient) |
| Broadcast | Hop-limited flood | -- |

The three-tier approach optimizes for each traffic pattern while providing fallbacks for edge cases.

---

[← Previous: Network Layer](04-network.md) | [Index](README.md) | [Next: Security →](06-security.md)
