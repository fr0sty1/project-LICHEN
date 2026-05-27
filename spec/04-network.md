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
| Link-local | fe80::/10 | Always | Direct neighbors |
| ULA | fd00::/8 | DODAG root present | Entire mesh |
| GUA | 2000::/3 | BR with upstream prefix | Internet |

All addresses use the same IID, derived from EUI-64 (see 6.2).

**1. Link-Local -- Always Available**

Every node has a link-local address from boot:
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

- Any router MAY elect itself as DODAG root
- Election: lowest EUI-64 wins (deterministic, no negotiation)
- Self-elected root generates and advertises ULA prefix
- If a "real" border router appears, nodes prefer it (lower rank)

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

From EUI-64 (IEEE method):
```
IID = EUI-64 XOR 0x0200_0000_0000_0000
```

From 16-bit short address:
```
IID = 0x0000_00FF_FE00_0000 | (short_addr << 48)
```

### 6.3. Multicast

| Address | Scope | Usage |
|---------|-------|-------|
| ff02::1 | Link-local | All nodes |
| ff02::1a | Link-local | All RPL nodes |
| ff02::2 | Link-local | All routers |

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
Link-local:  fe80::<IID>                    (always available)
ULA:         fd<40-bit random>:<subnet>::<IID>  (mesh-routable)
GUA:         <delegated prefix>::<IID>      (internet-routable)
```

IID is derived from EUI-64 (see Section 6.2), ensuring stable identity.

### 12.2. Example Addresses

| Type | Example | Routable To |
|------|---------|-------------|
| Link-local | fe80::1234:5678:9abc:def0 | Direct neighbors |
| ULA | fd12:3456:789a:0001::1234:5678:9abc:def0 | Entire mesh |
| GUA | 2001:db8:1234:1::1234:5678:9abc:def0 | Internet |

A node typically has all three when a BR with upstream connectivity is present.

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
