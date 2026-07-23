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

| Type | Prefix | Availability | Purpose |
|------|--------|--------------|---------|
| Link-local | fe80::/10 | After `lichen_link_init()` | Control traffic only (NDP, RPL control, neighbor discovery) |
| Primary (Yggdrasil) | 0200::/7 | Always (self-derived from Ed25519 pubkey) | All routable traffic (mesh, inter-mesh, BR forwarding). Cryptographically bound to key per 06-security.md §8.5 |

All addresses use stable IID derived from Ed25519 public key (unified derivation in 06-security.md §8.5, test/vectors/yggdrasil-derivation.json, 03-addressing.md). This provides cryptographic identity binding with no additional secrets. Link-local restricted to post-`lichen_link_init()` per AGENTS.md initialization graph. Single-primary model eliminates ULA/GUA layering, scope selection bugs, and prefix advertisement complexity while preserving isolated-mesh and multi-BR behavior via Yggdrasil.

**Isolated Meshes (No BR):**

Mesh self-organizes without infrastructure. Nodes derive primary 02xx address independently from their Ed25519 key (no prefix advertisement needed). Root election (lowest EUI-64) establishes RPL DODAG for control and routing using primary addresses. Full peer-to-peer, announce, LOADng, and application functionality works offline.

**Root Election, Failure, Demotion:**

Unchanged mechanics (lowest EUI-64 deterministic election, DIO monitoring, >50% vote demotion with Schnorr-signed DEMOTION_REQUEST). Root no longer generates/advertises ULA prefix. Demotion limitations and protocol remain as documented above (EUI-64 gaming requires hardware compromise; Byzantine threshold applies).

**Multiple Border Routers & Yggdrasil:**

BRs attach LICHEN meshes to Yggdrasil overlay using nodes' native 02xx addresses. 

- Local traffic stays on LoRa (RPL/gradient/LOADng on primary addresses)
- Off-mesh 02xx traffic forwards to BR Yggdrasil TUN
- Yggdrasil provides global routing tree connecting meshes without coordination between BRs
- Multi-BR redundancy via Yggdrasil anycast/failover

**LICHEN-on-Yggdrasil Tree Metaphor (P4):**

```
               Yggdrasil Global Backbone (trunk)
                       /          |          \
               LICHEN-MeshA     LICHEN-MeshB    Internet
                 (BR1)            (BR2)
                       \          /
                        LICHEN-MeshC (multi-BR)
```

Each LICHEN LoRa mesh is a leaf cluster. Primary 02xx addresses enable seamless end-to-end IPv6 across the tree. See parent epic project-LICHEN-zt3c for full diagram.

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

See Section 6.1 for single-primary model (unified Ed25519 derivation per 06-security.md §8.5 and test/vectors/yggdrasil-derivation.json). Summary:

```
Link-local:  fe80::<IID>                    (control only)
Primary:     02xx::[Yggdrasil-derived + IID] (all routable traffic)
```

IID and full 02xx address derived from same Ed25519 pubkey (MUST: lower 64 bits of primary address == IID for binding; see 06-security.md). No ULA or layered GUA model.

### 12.2. Example Addresses

| Type | Example | Routable To |
|------|---------|-------------|
| Link-local | fe80::0211:22ff:fe33:4455 | Direct neighbors (control) |
| Primary (02xx) | 0201:0203:0405:0607:0211:22ff:fe33:4455 | Mesh, inter-mesh via Yggdrasil, internet |

Node uses link-local for control + single primary 02xx for everything else. Consistent with updated 05-routing.md and 06-security.md. Matches all test vectors.

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
