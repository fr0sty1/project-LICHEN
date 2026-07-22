<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Network Layer

## 6. Network Layer

### 6.1. IPv6 Addressing (updated for no-ULA model)

**Model: Link-Local (control) + Primary 02xx (Ed25519/Yggdrasil-derived, no ULA)**

Every node has exactly two addresses. The 02xx address is primary and routable for nearly all traffic (see project-LICHEN-f9x1 for DAO source model).

| Address | Scope | Use |
|---------|-------|-----|
| `fe80::<IID>` | Link-local | NDP, single-hop RPL control (DIO/DIS), bootstrap |
| `02xx::<IID>` | Global (`02xx::/7`) | **Primary**: application data, multi-hop RPL (DAO to root), mesh routing, Yggdrasil overlay, internet forwarding |

**Derivation:** Ed25519 pubkey (32 bytes) → SHA-512 → Yggdrasil-style truncation with `02` prefix (normative details, test vectors in 6.2, 06-security.md:109, test/vectors/). IID (lower 64 bits) shared. Unifies identity across signatures, OSCORE, addressing (see 06-security.md).

**DAO Source Address Model (routable multi-hop, resolves prior ULA model per project-LICHEN-f9x1):**
- Single-hop control (DIO, DIS, NDP): IPv6 source = link-local `fe80::<IID>`
- Multi-hop upward control (DAO): IPv6 source = primary `02xx::<IID>` (routable end-to-end; relays preserve source)
- This replaces old ULA DAO source model; SCHC rules/vectors to be updated in 03-adaptation.md

**Why no ULA:**
- 02xx addresses fully routable in RPL DODAG without prefix ads or per-node Yggdrasil
- Self-elected roots coordinate DODAG; no PIO/RA prefix generation
- Eliminates source selection policy (no ULA/global confusion)
- Simplifies SCHC rules, test vectors, impl, security binding to one primary address
- Yggdrasil provides inter-mesh when BRs join (zt3c epic)

**Isolated meshes:** Stable 02xx at boot from keypair. Lowest-IID root election. RPL: link-local for local control, 02xx for data/DAOs. No prefix advertisement.

**Multiple BRs:** No coordination needed. 02xx primary for non-link-local; Yggdrasil for global overlay.

RPL control: link-local for single-hop; 02xx for multi-hop routability.

### 6.2. Interface Identifier (IID) Derivation

IID is the lower 64 bits of the cryptographically derived value from the node's Ed25519 keypair (exact algorithm, truncation, and U/L bit clear in 06-security.md:109 "unified Ed25519 derivation (no-ULA model)" and test/vectors/). Ensures binding between identity, signatures, OSCORE contexts, and both addresses.

**Formats:**
- Link-local: `fe80::[IID]` (always available, control plane)
- Primary: `02xx::[IID]` (Yggdrasil-derived global, data plane and multi-hop)

**Human-readable short address:** Crockford Base32 of IID (13 chars with dashes): e.g. `KCVN-MRPX-QWERT`. See 12.3, `02-physical-link.md:215`, test/vectors/ for derivation (`hash_32(EUI-64,0)` with collision/DAD rules), vectors, and short address assignment.

**Stable IIDs only** (no RFC 4941/7217 temporaries). Root election by lowest IID. EUI-64 used only for link layer per `02-physical-link.md:101`. Full consistency with 6.1 DAO model and 06-security.md.

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

See [03-addressing.md](03-addressing.md) for the complete human-readable Crockford base32 node address specification, derivation, test vectors, and IID integration.

### 12.1. Address Structure

See Section 6.1 for full design. Nodes have exactly two addresses:

- Link-local: `fe80::<IID>` (for control plane)
- Primary: `02xx::<IID>` (Yggdrasil-derived, used for all application traffic)

IID and 02xx address are both deterministically derived from the Ed25519 public key (see 6.2 and 6.1). This binds identity across layers.

### 12.2. Example Addresses

| Address | Example | Routable To |
|---------|---------|-------------|
| Link-local | fe80::1234:5678:9abc:def0 | Direct neighbors, NDP, RPL |
| Primary (02xx) | 02ab:cd12:3456:7890:1234:5678:9abc:def0 | Mesh + global (via Yggdrasil) |

The 02xx address is always present and primary. No ULA or per-prefix GUAs.

### 12.3. Short Address Assignment

16-bit short addresses optimize 6LoWPAN compression (2 bytes vs 8 bytes for IID). Full details and hybrid (coordinator vs self-assignment) procedure in `02-physical-link.md:171` (section 4.5); see exact line `02-physical-link.md:215` for note on `hash_32(EUI-64,0)` collision risk (with crc32_ieee per `02a-coordinated-capacity.md:119`), DAD retry strategy using `concat(EUI-64, retry)` seed mixing, exponential backoff, and 8-probe max.

Assignment methods (no central authority required):
1. **Derived from IID:** `short_addr = (hash_32(EUI-64 bytes, 8) & 0xFFFE) | 0x0001` (explicit `hash_32(EUI-64,0)` per `02-physical-link.md:199`; collision mitigation at :215)
2. **Self-assigned + DAD:** Hash-derived or random candidate, verified via DAD probe on link (up to 8 attempts)
3. **Root-assisted (optional):** DODAG root coordinates pool and assigns authoritatively via DAO-ACK (see `02-physical-link.md:178`)

Short addresses are mesh-local and compress the IID; full 02xx or link-local used for end-to-end identification and security binding. EUI-64 retained only for link layer per `02-physical-link.md:101`.

---

[← Previous: Adaptation Layer](03-adaptation.md) | [Index](README.md) | [Next: Routing →](05-routing.md)
