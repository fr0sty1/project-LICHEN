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

**Address Types (Layered):**

| Type | Prefix | When Available | Routable To |
|------|--------|----------------|-------------|
| Link-local | fe80::/10 | After lichen_link_init() | Direct neighbors (control only) |
| 02xx (Yggdrasil) | 0200::/7 | Always (self-derived from pubkey) | Mesh peers and internet gateways (Ed25519 per 06-security) |
| GUA | 2000::/3 | BR with upstream prefix | Internet |
| ULA | fd00::/8 | Optional (legacy) | Mesh (if configured) |

All addresses share a stable IID derived from the node's Ed25519 public key using the unified derivation normatively specified in 06-security.md §8.5 (and draft-lichen-schnorr-00 once stabilized; see also 03-addressing.md and test/vectors/). This binds identity cryptographically with no new secrets or key exposure. Link-local addresses are restricted to after `lichen_link_init()` per the subsystem initialization dependency graph in AGENTS.md. Mesh peer routing uses Ed25519-derived IID consistent with the address classification table in 05-routing.md.
**1. Link-Local -- Control Traffic (post-init)**

Every node has a link-local address after `lichen_link_init()`:
```
fe80::<IID>
```
Works without any infrastructure. Sufficient for single-hop communication
and mesh formation. RPL control messages use link-local.

**2. ULA -- Mesh-Routable (Default)**

When a DODAG root is present, it advertises a ULA /64 prefix via RPL DIO:
```
fd<40-bit random>:<16-bit subnet>::<IID>
```

ULA prefix generation (at DODAG root):
- Generate 40-bit random value per RFC 4193
- Persist across reboots (stable prefix)
- 16-bit subnet ID: 0x0001 for primary mesh

Nodes derive their ULA address from the advertised prefix + their IID.
Traffic is routable throughout the mesh but not to the internet.

**3. GUA -- Internet-Routable (Optional)**

When a border router has an upstream prefix, it advertises a GUA /64:
```
<delegated prefix>::<IID>
```

Sources of GUA prefix:
- DHCPv6-PD from upstream ISP
- Static configuration
- Tunnel broker (e.g., Hurricane Electric)
- Own PI space

Nodes MAY have both ULA and GUA addresses simultaneously.

**Isolated Meshes (No Border Router):**

When no border router is present, the mesh self-organizes:

**Root Election:**
- Any router MAY elect itself as DODAG root
- Election: lowest EUI-64 wins (deterministic, no negotiation)
- Self-elected root generates and advertises ULA prefix
- If a "real" border router appears, nodes prefer it (lower rank)

**Root Failure Detection:**

Nodes monitor root health via DIO reception:

| Condition | Action |
|-----------|--------|
| No DIO from root for 3× Imax | Declare root unreachable |
| Root unreachable + no alternate path | Initiate re-election |

Re-election process:
1. Node with next-lowest EUI-64 waits random delay (0-5 seconds)
2. If no DIO received during delay, self-elect as root
3. Generate new ULA prefix (or reuse if known)
4. Advertise DIO; other candidates stand down

**Root Demotion:**

Nodes MAY vote to demote a misbehaving root:

| Misbehavior | Evidence |
|-------------|----------|
| Selective forwarding | Packets dropped, detected via E2E ACKs |
| Rank manipulation | Advertised rank inconsistent with topology |
| Resource exhaustion | Root stops responding to DAO |

Demotion protocol:
1. Detecting node broadcasts DEMOTION_REQUEST with evidence hash
2. Other nodes validate evidence independently
3. If >50% of mesh (by node count) agree, root is demoted
4. Demoted node MUST NOT self-elect for 1 hour
5. Next-lowest EUI-64 becomes root

DEMOTION_REQUEST format (ICMPv6 RPL Control Message):
```
+--------+--------+--------+--------+
| Type   | Code   | Checksum        |
+--------+--------+--------+--------+
| Target EUI-64 (8 bytes)           |
+--------+--------+--------+--------+
| Evidence Hash (16 bytes, SHA-256 truncated) |
+--------+--------+--------+--------+
| Signature (48 bytes, Schnorr)     |
+--------+--------+--------+--------+
```

Nodes track demotion votes per-target. Votes expire after 10 minutes.

**Limitations:**

- EUI-64 gaming requires hardware access; if attacker controls hardware,
  network is already compromised
- Demotion requires >50% honest nodes (Byzantine assumption)
- Small meshes (<5 nodes) should use manual root configuration

**Multiple Border Routers:**

Multiple BRs are supported. Each BR:
- Advertises its own prefix(es) via RPL DIO
- Forms its own DODAG (same or different RPL Instance)
- Nodes may join multiple DODAGs or pick the best one

Coordination between BRs is NOT required. Nodes handle multiple prefixes:
- May have multiple addresses (one per prefix)
- Route selection based on destination prefix
- Default route via any BR with GUA prefix

### 6.2. Interface Identifier (IID) Derivation

IID is derived from Ed25519 public key via the unified normative function in 06-security.md §8.5 (MUST match test vectors exactly; see also 03-addressing.md:12-18, draft-lichen-schnorr-00, rust/lichen-link/src/identity.rs:24, python/src/lichen/crypto/identity.py):

```
hash = SHA-256(pubkey)  // or hash_32 variant per vectors
IID = hash[0:8]
IID[0] &= 0b11111101    // clear U/L bit (RFC 4291)
```

**Stable cryptographic IIDs only.** The IID binds the IPv6 address to the Ed25519 keypair used for signatures and OSCORE (no new key material). Temporary (RFC 4941) and opaque (RFC 7217) IIDs MUST NOT be used. See 06-security.md §8.7 for full analysis and privacy considerations. Short address derivation for 6LoWPAN remains compatible but defers to the key-derived IID for identity.

### 6.3. Multicast and Broadcast

#### 6.3.1. Multicast Scopes

IPv6 multicast addresses encode scope in bits 8-11:

| Scope | Value | Address Prefix | Meaning |
|-------|-------|----------------|---------|
| Interface-local | 1 | ff01:: | Loopback only |
| Link-local | 2 | ff02:: | Single hop (direct neighbors) |
| Mesh-local | 3 | ff03:: | Within DODAG (LICHEN extension) |
| Site-local | 5 | ff05:: | Administrative domain |
| Global | 14 | ff0e:: | Internet-wide |

**Standard multicast groups:**

| Address | Scope | Usage |
|---------|-------|-------|
| ff02::1 | Link-local | All nodes (1 hop) |
| ff02::1a | Link-local | All RPL nodes (1 hop) |
| ff02::2 | Link-local | All routers (1 hop) |
| ff03::1 | Mesh-local | All nodes (entire mesh) |
| ff03::fc | Mesh-local | All LICHEN nodes |

#### 6.3.2. Hop-Limited Broadcast

For scoped flooding without full multicast routing, use **Hop Limit**:

| Hop Limit | Reach | Use Case |
|-----------|-------|----------|
| 1 | Direct neighbors | Discovery, link probing |
| 2 | 2 hops | Local announcement |
| 3-4 | Small cluster | Team coordination |
| 5-7 | Mesh diameter | Mesh-wide alert |
| 255 | Unlimited | Flood (bounded by topology) |

**How it works:**

1. Sender sets Hop Limit (e.g., 4)
2. Sender broadcasts to ff03::1 (mesh-local all nodes)
3. Each relay:
   - Receives packet
   - Decrements Hop Limit
   - If Hop Limit > 0: rebroadcast
   - If Hop Limit = 0: consume locally, don't relay

No routing table consulted. Purely local decision at each hop.

#### 6.3.3. Broadcast Rate Limiting

Broadcasts are expensive -- each packet is relayed by every node in range.
Without limits, a single node can flood the network.

**Distributed rate limiting (no central authority):**

Each node tracks broadcasts it relays, per sender:

```
Broadcast Relay State:
  sender_iid: <IID of original sender>
  hop_bucket[1-7]: <count in rolling 1-hour window>
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
  sender = packet.source_iid
  hl = packet.hop_limit

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

**State size:**

Per-sender entry: ~20 bytes (IID + 7 bucket counters + timestamp)
At 100 active senders: ~2 KB

#### 6.3.4. Border Router Multicast Filtering

Border routers MUST NOT forward mesh multicasts to the internet:

| Direction | Unicast | Multicast |
|-----------|---------|-----------|
| Mesh → Internet | Forward (route normally) | **Drop** |
| Internet → Mesh | Forward (route normally) | **Drop** (unless explicit config) |

Rationale:
- Mesh broadcasts are not meaningful globally
- Prevents accidental flood amplification
- Protects mesh from external multicast storms

**Exception:** Explicitly configured multicast peering between meshes
(future work -- requires multicast routing protocol like PIM).

### 6.4. ICMPv6

Standard ICMPv6 (RFC 4443) for:
- Echo Request/Reply (ping)
- Destination Unreachable
- Packet Too Big
- RPL control messages (see Section 7)

---

## 12. Addressing

### 12.1. Address Structure

See Section 6.1 for full addressing design (unified Ed25519 IID per 06-security.md §8.5). Summary:

```
Link-local:  fe80::<IID>                    (control, post-lichen_link_init)
02xx:        02xx::[derived-from-pubkey]   (primary mesh routable, Ed25519 per 06-security)
GUA:         <delegated prefix>::<IID>      (internet optional)
```

IID is derived from Ed25519 pubkey (see Section 6.2 and 06-security.md), ensuring cryptographic binding. ULA optional in some deployments.

### 12.2. Example Addresses

| Type | Example | Routable To |
|------|---------|-------------|
| Link-local | fe80::0211:22ff:fe33:4455 | Direct neighbors (control) |
| 02xx (primary) | 0201:0203:0405:0607:0211:22ff:fe33:4455 | Mesh peers (Ed25519 per 06-security) |
| GUA | 2001:db8:1234:1::0211:22ff:fe33:4455 | Internet |

A node typically has link-local + primary 02xx address; GUA when BR provides upstream prefix. Consistent with 05-routing.md table.

### 12.3. Short Address Assignment

16-bit short addresses optimize link-layer addressing and SCHC rule targets
(2 bytes vs 8).

Assignment methods (no central authority required):
1. **Derived from IID (Ed25519-derived):** Hash lower 16 bits of stable IID, check for collision
2. **Self-assigned + DAD:** Pick random, verify uniqueness via DAD
3. **DODAG root assignment:** Root allocates from pool (optional optimization)

Collision resolution: If DAD detects duplicate, regenerate and retry.

Short addresses are mesh-local; they compress the IID for routing efficiency
but the full key-derived IID remains the stable identifier for security (key binding per 06-security).

---

[← Previous: Adaptation Layer](03-adaptation.md) | [Index](README.md) | [Next: Routing →](05-routing.md)
