<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Network Layer

## 6. Network Layer

### 6.1. IPv6 Addressing

**Design Principles:**
- Isolated meshes (no border router) MUST work
- Multiple border routers MUST be tolerated
- No central address authority required

**Address Types:**

| Type | Construction | Use |
|------|--------------|-----|
| Link-local | `fe80::/64 + IID` | NDP, RPL control, and direct-neighbor diagnostics |
| Native unicast | `AddrForKey(Ed25519 public key)` | All application unicast, locally and through Yggdrasil |

**1. Link-Local -- Always Available**

Every node has a link-local address from boot:
```
fe80::<IID>
```
Works without any infrastructure. Sufficient for single-hop communication
and mesh formation. RPL control messages use link-local.

**2. Native Yggdrasil Address -- Primary Unicast**

Every node MUST derive one native Yggdrasil `/128` from the same raw 32-byte
Ed25519 public key used for LICHEN authentication. Native node addresses occupy
`0200::/8`; `0200::/7` also contains Yggdrasil's routed `0300::/8` subnet
space, which LICHEN does not use for node identity.

`AddrForKey` is compatible with current `yggdrasil-go`:

1. Complement every byte of the public key.
2. Scan the result most-significant bit first and count its leading one bits
   as `n`.
3. Discard those `n` one bits and the following zero bit.
4. Set address byte 0 to `0x02` and byte 1 to `n`.
5. Pack the remaining bits most-significant bit first into complete octets,
   discarding any incomplete trailing octet.
6. Copy at most the first 14 packed octets into address bytes 2 through 15 and
   leave any unfilled address bytes as zero.

No SHA hash, EUI-64, gateway prefix, or link-local IID participates in this
derivation. The input MUST be a 32-byte Ed25519 public key accepted by signature
verification. A receiver that knows the public key MUST reject a claimed native
address that does not equal `AddrForKey(public_key)`.

`AddrForKey` is a lossy encoding, so the address alone is not proof of a unique
public key. If two authenticated keys produce the same native `/128` or key
token, implementations MUST mark the mapping ambiguous, reject compressed
context that depends on it, and require explicit operator resolution. TOFU
MUST NOT replace an existing binding silently.

The address works as a flat identifier on an isolated LICHEN mesh; no
Yggdrasil daemon is required for local forwarding. Global reachability requires
the node to participate in Yggdrasil under the same key. The required
constrained-node transport is outside this baseline, so implementations MUST
treat non-local native destinations as unreachable unless another
specification defines that participation. A gateway-owned Yggdrasil identity
MUST NOT emit traffic with a node's native source address.

**Isolated Meshes (No Border Router):**

When no border router is present, the mesh self-organizes:

**Root Election:**
- Any router MAY elect itself as DODAG root
- Election: lexicographically lowest authenticated native `/128` wins
- Self-elected root forms the DODAG but advertises no address prefix
- If a "real" border router appears, nodes prefer it (lower rank)

**Root Failure Detection:**

Nodes monitor root health via DIO reception:

| Condition | Action |
|-----------|--------|
| No DIO from root for 3× Imax | Declare root unreachable |
| Root unreachable + no alternate path | Initiate re-election |

Re-election process:
1. Node with next-lowest authenticated native `/128` waits random delay (0-5 seconds)
2. If no DIO received during delay, self-elect as root
3. Form a new DODAG without assigning an address prefix
4. Advertise DIO; other candidates stand down

**Root Demotion:**

Nodes MAY vote to demote a misbehaving root:

| Misbehavior | Evidence |
|-------------|----------|
| Selective forwarding | Packets dropped, detected via E2E ACKs |
| Rank manipulation | Advertised rank inconsistent with topology |
| Resource exhaustion | Root stops responding to DAO |

Demotion protocol:
1. Detecting node broadcasts DEMOTION_REQUEST naming the root's native `/128`
   and carrying an evidence hash
2. Other nodes validate evidence independently
3. If >50% of mesh (by node count) agree, root is demoted
4. Demoted node MUST NOT self-elect for 1 hour
5. Next-lowest authenticated native `/128` becomes root

DEMOTION_REQUEST format (ICMPv6 RPL Control Message):
```
+--------+--------+--------+--------+
| Type   | Code   | Checksum        |
+--------+--------+--------+--------+
| Target Native Address (16 bytes)  |
+--------+--------+--------+--------+
| Evidence Hash (16 bytes, SHA-256 truncated) |
+--------+--------+--------+--------+
| Signature (48 bytes, Schnorr)     |
+--------+--------+--------+--------+
```

Nodes track demotion votes per-target. Votes expire after 10 minutes.

**Limitations:**

- Identity rotation can evade a prior demotion, but the new key derives a new
  native address and loses the old identity's trust
- Demotion requires >50% honest nodes (Byzantine assumption)
- Small meshes (<5 nodes) should use manual root configuration

**Multiple Border Routers:**

Multiple BRs are supported. Each BR:
- Advertises its grounded state and routing objective via RPL DIO
- Forms its own DODAG (same or different RPL Instance)
- Nodes may join multiple DODAGs only when they use distinct RPL Instance IDs,
  or pick the best DODAG within one Instance

Coordination between BRs is NOT required. Nodes retain the same native `/128`
across DODAG changes and select a preferred grounded root using the RPL
objective function.

### 6.2. Interface Identifier (IID) Derivation

From the node public key:
```
IID = SHA-256(public_key)[0:8]
IID[0] = IID[0] AND 0xfd
```

The cleared U/L bit marks this synthetic IID as locally administered. This
IID is used only in link-local and hop-local identifiers; it is not the low
half of the native Yggdrasil address.

From 16-bit short address:
```
IID = 0x0000_00FF_FE00_0000 | (short_addr << 48)
```

**Stable IIDs only.** IIDs are stable and key-derived for the life of
the node. Temporary addresses (RFC 4941) and opaque/random IIDs (RFC 7217)
MUST NOT be used. This is a deliberate deviation from the RFC 8064 default:
root election, short-address assignment, replay windows, and signature
caching all key on a stable node identity, and every frame is already bound
to a stable public key, so a rotating IID would break the mesh while
providing no unlinkability. See Privacy in Security Considerations
(section 15.5 in Security) for the full analysis.

### 6.3. Multicast and Broadcast

#### 6.3.1. Multicast Scopes

IPv6 multicast addresses encode scope in bits 8-11:

| Scope | Value | Address Prefix | Meaning |
|-------|-------|----------------|---------|
| Interface-local | 1 | ff01:: | Loopback only |
| Link-local | 2 | ff02:: | Single hop (direct neighbors) |
| Realm-local | 3 | ff03:: | Within one LICHEN DODAG realm (RFC 7346) |
| Site-local | 5 | ff05:: | Administrative domain |
| Global | 14 | ff0e:: | Internet-wide |

**Standard multicast groups:**

| Address | Scope | Usage |
|---------|-------|-------|
| ff02::1 | Link-local | All nodes (1 hop) |
| ff02::1a | Link-local | All RPL nodes (1 hop) |
| ff02::2 | Link-local | All routers (1 hop) |
| ff03::1 | Realm-local | All nodes in the DODAG |
| ff03::fc | Realm-local | All LICHEN nodes in the DODAG |

#### 6.3.2. Hop-Limited Broadcast

For scoped flooding without full multicast routing, use **Hop Limit**:

| Hop Limit | Reach | Use Case |
|-----------|-------|----------|
| 1 | Direct neighbors | Discovery, link probing |
| 2 | 2 hops | Local announcement |
| 3-4 | Small cluster | Team coordination |
| 5-7 | Mesh diameter | Mesh-wide alert |

**How it works:**

Every realm-local application multicast that may be relayed MUST carry its
RPL Instance ID, DODAGID, original Hop Limit, and a 32-bit LICHEN Broadcast
Sequence in an IPv6 Hop-by-Hop option. Together the RPL Instance ID and DODAGID
identify the realm. The original Hop Limit MUST be in the range 1-7.
Origins persist this counter while retaining their key and increment it for
each new multicast.
Loss of sequence state is a fail-closed key-state error. Relays preserve this
option. Retransmission of the same origin packet reuses the same value. RPL
control messages use RPL's own duplicate suppression instead.

```
+--------+--------+----------+---------------+----------+----------------+
| TBD1   | Len=22 | Instance | DODAGID (16) | Orig. HL | Broadcast Seq. |
+--------+--------+----------+---------------+----------+----------------+
   1B       1B        1B          16B           1B           4B
```

The option type is pending IANA allocation. Implementations MUST make it
configurable and MUST NOT ship RFC 4727 experimental value `0x1e` as a default.
LICHEN development and canonical-vector configurations explicitly select
`0x1e`; production deployments require an allocated or explicitly coordinated
value.
The allocated type's action bits will permit nodes that do not implement realm
forwarding to skip the option, and its change-en-route bit will be clear because
relays MUST NOT modify it.

Relayed application multicast MUST also carry byte-exact end-to-end origin
authentication that binds the native source address, destination, realm
identifier, original Hop Limit, Broadcast Sequence, and application operation. The
baseline defines this only for SOS in Applications section 18.4. Other
application multicast remains single-hop until its application profile defines
an equivalent signed input. A packet without valid end-to-end origin
authentication MUST be dropped, not consumed or relayed. Rate limiting keys on
the verified origin identity, not an unverified IPv6 source supplied by a relay.

Receivers maintain a persistent 32-bit serial replay window per verified
origin identity. The serial comparison uses the same half-space rule as link
replay, widened to 32 bits. A packet outside that window MUST NOT be delivered
or relayed even after the short-lived duplicate cache expires.

1. Sender sets Hop Limit and the immutable original Hop Limit to the same value
2. Sender includes the selected realm identifier and broadcasts to ff03::1
3. Each relay:
   - Verifies that the identified realm is one of its active DODAG memberships
   - Drops the packet if it arrived outside that realm
   - Drops the packet unless current Hop Limit is at most original Hop Limit
   - Decrements Hop Limit
   - If Hop Limit > 0: rebroadcast only within the same realm
   - If Hop Limit = 0: consume locally, don't relay

No destination route is consulted. Forwarding uses the receiving interface and
active DODAG membership to preserve the identified realm. A node joined to
multiple DODAGs MUST NOT copy a received realm-local multicast into another
realm.

#### 6.3.3. Broadcast Rate Limiting

Broadcasts are expensive -- each packet is relayed by every node in range.
Without limits, a single node can flood the network.

**Distributed rate limiting (no central authority):**

Each node tracks broadcasts by verified origin, authenticated immediate sender,
and realm-wide aggregate. A packet is relayed only when all three budgets allow
it, preventing identity rotation from creating unbounded aggregate capacity:

```
Broadcast Relay State:
  origin_id: <verified native source address>
  immediate_sender_id: <authenticated hop sender>
  hop_bucket[1-7]: <count in rolling 1-hour window>
  realm_bucket[1-7]: <aggregate count in rolling 1-hour window>
  last_seen: <timestamp>
```

**Hop-aware budgets:**

Higher Hop Limit = larger blast radius = stricter limit:

| Hop Limit | Budget (per sender per hour) | Rationale |
|-----------|------------------------------|-----------|
| 1 | 200 | Neighbors only, low impact |
| 2 | 100 | Small radius |
| 3-4 | 30 | Medium radius |
| 5-7 | 10 | Mesh-wide, expensive |
| SOS (any) | 3 | Emergency, always relay once |

**Relay decision:**

```
on_receive_broadcast(packet):
  sender = packet.source_identity
  hl = packet.original_hop_limit
  if hl < 1 or hl > 7 or packet.hop_limit > hl:
    drop(packet)
    return
  packet_id = SHA256(
      packet.source || packet.destination || packet.realm ||
      packet.broadcast_sequence
  )[0:8]

  if seen_cache.contains(packet_id):
    drop(packet)
    return
  seen_cache.insert(packet_id, expires=now() + 2 * MAX_MESH_TRAVERSAL_TIME)

  if sender not in relay_state:
    relay_state[sender] = new_entry()

  budget = get_budget(hl)
  count = relay_state[sender].hop_bucket[hl]

  if count >= budget:
    drop(packet)  # sender exceeded budget
    return

  if count >= budget * 0.5:
    # Probabilistic relay in yellow zone
    if random() > 0.5:
      drop(packet)
      return

  relay_state[sender].hop_bucket[hl] += 1
  decrement_hop_limit(packet)

  if packet.hop_limit > 0:
    rebroadcast(packet)
```

**Properties:**

- **No coordination:** Each node enforces independently
- **No network map:** Only local state per sender
- **Spammers isolated:** Immediate neighbors stop relaying
- **Graceful degradation:** Probabilistic relay in yellow zone
- **Memory bounded:** Expire old entries after 2 hours idle
- **Loop suppression:** Immutable packet IDs are cached before relay

**State size:**

Implementations MUST bound both sender-rate and packet-ID caches. Packet IDs
exclude Hop Limit, link addresses, link replay counters, and link signatures,
so every re-signed copy of one origin packet has the same ID. A hash collision
may suppress a packet but MUST NOT bypass authentication or rate limits.

#### 6.3.4. Border Router Multicast Filtering

When a separately specified identity-preserving Yggdrasil profile is active,
border routers apply this filter:

| Direction | Unicast | Multicast |
|-----------|---------|-----------|
| Mesh → Yggdrasil | Profile MAY forward native unicast | **Drop** |
| Yggdrasil → Mesh | Profile MAY forward known local native unicast | **Drop** |

Rationale:
- Mesh broadcasts are not meaningful globally
- Prevents accidental flood amplification
- Protects mesh from external multicast storms

Cross-mesh multicast is outside this profile. A future non-Yggdrasil transport
may define authenticated multicast peering; Yggdrasil forwarding remains
unicast-only.

### 6.4. ICMPv6

Standard ICMPv6 (RFC 4443) for:
- Echo Request/Reply (ping)
- Destination Unreachable
- Packet Too Big
- RPL control messages (see Section 7)

---

## 12. Addressing

### 12.1. Address Structure

See Section 6.1 for full addressing design. Summary:

```
Link-local:  fe80::<IID>                    (control plane)
Native:      02xx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
             (application unicast)
```

The IID and native address are distinct derivations from the same public key.

### 12.2. Example Addresses

| Type | Example | Routable To |
|------|---------|-------------|
| Link-local | fe80::1234:5678:9abc:def0 | Direct neighbors |
| Native | 200:848a:604f:bb7e:4384:65db:8db6:6895 | Local mesh and Yggdrasil |

A node has both addresses regardless of whether a border router is present.

### 12.3. Short Address Assignment

16-bit short addresses optimize 6LoWPAN compression (2 bytes vs 8).

Assignment methods (no central authority required):
1. **Derived from EUI-64:** Hash lower 16 bits, check for collision
2. **Self-assigned + DAD:** Pick random, verify uniqueness via DAD
3. **DODAG root assignment:** Root allocates from pool (optional optimization)

Collision resolution: If DAD detects duplicate, regenerate and retry.

Short addresses are mesh-local; they compress the IID for routing efficiency
but the full IID remains the stable identifier for security (key binding).

---

[← Previous: Adaptation Layer](03-adaptation.md) | [Index](README.md) | [Next: Routing →](05-routing.md)
