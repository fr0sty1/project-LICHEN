# LICHEN Protocol Specification

**LoRa IPv6 CoAP Hybrid Extended Network**

**Document Status:** Proposed Design
**Version:** Draft 0.1
**Date:** 2026-05-26
**License:** CC-BY-4.0 (documentation)

## Abstract

LICHEN (LoRa IPv6 CoAP Hybrid Extended Network) is a LoRa-based mesh networking
protocol built entirely on IETF standards: IPv6 with SCHC header compression,
RPL mesh routing, and CoAP application protocols. The design prioritizes
interoperability with existing IP infrastructure, efficient use of constrained
bandwidth, and cryptographic authentication of all packets.

Unlike Meshtastic and MeshCore, LICHEN uses real IPv6 addressing, enabling
direct communication with internet hosts via border routers and compatibility
with the broader IoT ecosystem. LICHEN runs on existing Meshtastic-compatible
hardware as a reflash — same radios, new protocol.

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Protocol Stack](#2-protocol-stack)
3. [Physical Layer](#3-physical-layer)
4. [Link Layer](#4-link-layer)
5. [Adaptation Layer (6LoWPAN/SCHC)](#5-adaptation-layer)
6. [Network Layer (IPv6)](#6-network-layer)
7. [Routing (RPL)](#7-routing-rpl)
8. [Security Architecture](#8-security-architecture)
9. [Transport Layer](#9-transport-layer)
10. [Application Layer](#10-application-layer)
11. [Node Types and Roles](#11-node-types-and-roles)
12. [Addressing](#12-addressing)
13. [Packet Formats](#13-packet-formats)
14. [Timing and Duty Cycle](#14-timing-and-duty-cycle)
15. [Security Considerations](#15-security-considerations)
16. [Implementation Notes](#16-implementation-notes)
17. [Local Client Interface](#17-local-client-interface)
18. [Applications](#18-applications)
- [Appendix A: SCHC Compression Rules](#appendix-a-schc-compression-rules)
- [Appendix B: RPL Configuration](#appendix-b-rpl-configuration)
- [Appendix C: CoAP Resource Directory](#appendix-c-coap-resource-directory)
- [Appendix D: Comparison with Existing Protocols](#appendix-d-comparison-with-existing-protocols)
- [Appendix E: Example Network](#appendix-e-example-network)
- [Appendix F: SenML Sensor Profile](#appendix-f-senml-sensor-profile)

---

## 1. Design Principles

### 1.1. Standards-Based

Every protocol layer uses existing IETF standards:

| Layer | Standard | RFC |
|-------|----------|-----|
| Compression | SCHC | RFC 8724 |
| Adaptation | 6LoWPAN | RFC 4944, 6282 |
| Network | IPv6 | RFC 8200 |
| Routing | RPL | RFC 6550 |
| Security | OSCORE, LLSec | RFC 8613, custom |
| Transport | UDP | RFC 768 |
| Application | CoAP, MQTT-SN | RFC 7252, OASIS |

### 1.2. Design Goals

1. **Real IPv6:** Globally routable addresses, not proprietary node IDs
2. **Efficient:** SCHC compresses headers to 6-15 bytes
3. **Authenticated:** Every packet cryptographically signed
4. **Interoperable:** Standard CoAP/MQTT-SN applications work unmodified
5. **Mesh:** RPL provides multi-hop routing without central coordination
6. **Gateway-friendly:** Border routers connect mesh to internet

### 1.3. Non-Goals

- Backward compatibility with Meshtastic or MeshCore
- Support for non-IP protocols
- Complex QoS or traffic engineering

---

## 2. Protocol Stack

```
+----------------------------------------------------------+
|                    Application Layer                      |
|  CoAP (RFC 7252) | MQTT-SN (OASIS) | Raw UDP | ICMPv6    |
+----------------------------------------------------------+
|                    Security Layer                         |
|  OSCORE (RFC 8613) for CoAP | DTLS 1.3 for MQTT-SN       |
+----------------------------------------------------------+
|                    Transport Layer                        |
|  UDP (RFC 768) - compressed via SCHC                      |
+----------------------------------------------------------+
|                    Network Layer                          |
|  IPv6 (RFC 8200) - compressed via SCHC                    |
|  Link-local (fe80::/10) or Global (/64 prefix)            |
+----------------------------------------------------------+
|                    Routing Layer                          |
|  RPL (RFC 6550) - DODAG mesh formation                    |
|  Source routing via 6LoRH (RFC 8138)                      |
+----------------------------------------------------------+
|                    Adaptation Layer                       |
|  6LoWPAN (RFC 4944, 6282) - fragmentation                 |
|  SCHC (RFC 8724) - header compression                     |
+----------------------------------------------------------+
|                    Link Security Layer                    |
|  Ed25519 signatures (truncated) | Replay protection       |
+----------------------------------------------------------+
|                    MAC Layer                              |
|  TSCH (RFC 7554) or CSMA/CA                               |
+----------------------------------------------------------+
|                    Physical Layer                         |
|  LoRa CSS (Semtech SX126x/SX127x)                         |
+----------------------------------------------------------+
```

---

## 3. Physical Layer

### 3.1. Modulation

LoRa Chirp Spread Spectrum (CSS) as implemented by Semtech SX126x and SX127x.

### 3.2. Recommended Parameters

| Parameter | Symbol | Default | Notes |
|-----------|--------|---------|-------|
| Frequency | FREQ | Regional | See 3.3 |
| Bandwidth | BW | 125 kHz | Balance of range/throughput |
| Spreading Factor | SF | 9 | Adjustable per-link |
| Coding Rate | CR | 4/5 | Minimal FEC overhead |
| Preamble | - | 8 symbols | Standard LoRa |
| Sync Word | SYNC | 0x34 | Distinct from Meshtastic (0x2B) |
| CRC | - | Enabled | Hardware CRC |

### 3.3. Frequency Bands

| Region | Band | Default Channel | Channels |
|--------|------|-----------------|----------|
| US/CA | 915 MHz ISM | 903.9 MHz | 64 (200 kHz spacing) |
| EU | 868 MHz | 868.1 MHz | 3 (duty cycle limited) |
| AU/NZ | 915 MHz | 916.8 MHz | 64 |

### 3.4. Adaptive Data Rate (ADR)

Nodes SHOULD implement ADR to optimize SF/TX power based on link quality:

1. Track SNR of received packets from each neighbor
2. If SNR > threshold + margin: decrease SF (faster)
3. If SNR < threshold: increase SF (more robust)
4. Propagate via RPL DIO options

---

## 4. Link Layer

### 4.1. Frame Format

```
+--------+--------+--------+----------+---------+--------+
| Length | LLSec  | SeqNum | Dst Addr | Payload | MIC    |
+--------+--------+--------+----------+---------+--------+
   1B       1B       2B       2-8B      var      4-8B
```

| Field | Size | Description |
|-------|------|-------------|
| Length | 1 byte | Total frame length (excl. Length field) |
| LLSec | 1 byte | Link-layer security flags |
| SeqNum | 2 bytes | Sequence number (replay protection) |
| Dst Addr | 2-8 bytes | Compressed destination address |
| Payload | Variable | 6LoWPAN/SCHC compressed packet |
| MIC | 4-8 bytes | Message Integrity Code |

### 4.2. Link-Layer Security (LLSec) Byte

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| E | S |  MIC Len  | Addr Mode |
+---+---+---+---+---+---+---+---+
```

| Field | Bits | Values |
|-------|------|--------|
| Addr Mode | 0-1 | 0=none, 1=16-bit, 2=64-bit, 3=elided |
| MIC Length | 2-4 | 0=32-bit, 1=64-bit, 2=reserved |
| Signature | 5 | 1=Ed25519 signature present |
| Encrypted | 6 | 1=payload encrypted (AES-CCM) |
| Reserved | 7 | Must be 0 |

### 4.3. Addressing Modes

| Mode | Size | Description |
|------|------|-------------|
| None (0) | 0B | Broadcast |
| Short (1) | 2B | 16-bit short address (assigned by coordinator) |
| Extended (2) | 8B | EUI-64 derived from hardware |
| Elided (3) | 0B | Derived from IPv6 destination |

### 4.4. Sequence Number

16-bit counter per sender, incremented for each transmission.
Used for:
- Duplicate detection (discard if seen recently)
- Replay protection (reject if SeqNum <= last_seen)

Receivers maintain per-sender SeqNum state, with 32-entry window for
out-of-order tolerance.

---

## 5. Adaptation Layer

### 5.1. SCHC Overview (RFC 8724)

Static Context Header Compression uses pre-shared "rules" to compress
headers. Both sender and receiver store identical rule sets; packets
carry only a Rule ID and residue (changed fields).

### 5.2. Compression Gains

| Headers | Uncompressed | SCHC Compressed |
|---------|--------------|-----------------|
| IPv6 | 40 bytes | 1-2 bytes (link-local) |
| IPv6 + UDP | 48 bytes | 3-6 bytes |
| IPv6 + UDP + CoAP | 60+ bytes | 6-12 bytes |

### 5.3. Rule Structure

Each rule specifies, for each header field:
- **TV (Target Value):** Expected value
- **MO (Matching Operator):** equal, ignore, MSB(n), etc.
- **CDA (Compression/Decompression Action):** not-sent, value-sent, LSB(n), etc.

### 5.4. Default Rules

**Rule 0: Link-local IPv6 + UDP (most common)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (from L2) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (from L2) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 2 bytes** (Rule ID + 2x 4-bit port residue)

**Rule 1: Global IPv6 + UDP (internet-routable)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.SrcPrefix | mesh_prefix/64 | equal | not-sent |
| IPv6.DstPrefix | 0 | ignore | value-sent (64 bits) |
| (other fields as Rule 0) | | | |

**Compressed size: 10 bytes** (includes full destination prefix)

### 5.5. Fragmentation

Packets exceeding L2 MTU are fragmented per RFC 8724 Section 8:

**Fragment Header:**
```
+--------+--------+--------+
| RuleID | W | FCN | (MIC) |
+--------+--------+--------+
```

- **W (Window):** 1-bit window indicator
- **FCN (Fragment Counter):** 6 bits, counts down from N to 0
- **MIC:** Message Integrity Check on final fragment

**ACK-on-Error mode** recommended for LoRa: receiver only sends NACK
for missing fragments.

---

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

**1. Link-Local — Always Available**

Every node has a link-local address from boot:
```
fe80::<IID>
```
Works without any infrastructure. Sufficient for single-hop communication
and mesh formation. RPL control messages use link-local.

**2. ULA — Mesh-Routable (Default)**

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

**3. GUA — Internet-Routable (Optional)**

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

## 7. Routing (RPL)

### 7.1. Overview

RPL (Routing Protocol for Low-Power and Lossy Networks, RFC 6550) builds
a DODAG (Destination-Oriented Directed Acyclic Graph) rooted at a border
router or coordinator.

### 7.2. Topology

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

### 7.3. Control Messages

| Message | ICMPv6 Code | Direction | Purpose |
|---------|-------------|-----------|---------|
| DIO | 0x9B, 0x01 | Downward | DODAG Information Object |
| DIS | 0x9B, 0x00 | Upward | DODAG Information Solicitation |
| DAO | 0x9B, 0x02 | Upward | Destination Advertisement Object |
| DAO-ACK | 0x9B, 0x03 | Downward | DAO acknowledgment |

### 7.4. DIO (DODAG Information Object)

Broadcast by routers to advertise DODAG membership:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   RPLInstanceID   |    Version    |            Rank           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|G|0|MOP|Prf|           DTSN            |     Flags     | Res   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          DODAGID                              +
|                       (128 bits)                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Options                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 7.5. Objective Function

**OF0 (RFC 6552):** Minimize hop count
**MRHOF (RFC 6719):** Minimize ETX (expected transmissions)

Recommended: **MRHOF with ETX** for LoRa, as link quality varies significantly.

### 7.6. Rank Calculation

```
Rank(N) = Rank(Parent) + RankIncrease
RankIncrease = (ETX * MinHopRankIncrease) / 128
```

Default MinHopRankIncrease: 256

### 7.7. Trickle Timer

DIO transmissions follow Trickle algorithm (RFC 6206):

| Parameter | Value | Description |
|-----------|-------|-------------|
| Imin | 2^12 ms (~4 sec) | Minimum interval |
| Imax | 2^20 ms (~17 min) | Maximum interval |
| k | 10 | Redundancy constant |

### 7.8. Downward Routes (Non-Storing Mode)

For point-to-point traffic, root inserts source route via **6LoRH** (RFC 8138):

```
+--------+--------+--------+--------+
| 6LoRH  | Hop 1  | Hop 2  | Hop 3  |
+--------+--------+--------+--------+
   1B      2B       2B       2B
```

Compressed addresses (16-bit short addresses) minimize overhead.

### 7.9. Loop Avoidance

- Rank must strictly increase toward leaves
- Data-path validation via RPL Packet Information (RPI)
- Inconsistency detection triggers local repair

---

## 8. Security Architecture

### 8.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | OSCORE encryption (CoAP), DTLS (MQTT-SN) |
| Spoofing | Link-layer signatures (Ed25519) |
| Replay | Sequence numbers, OSCORE replay window |
| Routing attacks | RPL secure mode (optional), signed DIOs |
| DoS | Rate limiting, admission control |

### 8.2. Security Layers

```
+---------------------------------------------------+
| Application Security                              |
| OSCORE (CoAP) | DTLS 1.3 (MQTT-SN) | Custom (UDP) |
+---------------------------------------------------+
| Link-Layer Security (LLSec)                       |
| Ed25519 signature (32B) | AES-128-CCM (optional)  |
+---------------------------------------------------+
```

### 8.3. Link-Layer Signatures

Every transmitted frame carries an Ed25519 signature for sender authentication.

**Full signature (64 bytes)** is prohibitive for LoRa. We use **truncated
signatures (32 bytes)** providing 128 bits of security:

```
Signature = Ed25519_Sign(PrivKey, Frame)[0:32]
```

Verification:
```
Valid = Ed25519_Verify_Truncated(PubKey, Frame, Signature)
```

**Implementation note:** Truncated Ed25519 requires custom verification
that checks if any of the 2^256 possible full signatures (sharing the
truncated prefix) is valid. In practice, we use a deterministic scheme
where the second half is derived from the first.

### 8.4. Alternative: ECDSA with secp256r1

If Ed25519 truncation is unacceptable, use ECDSA with secp256r1:
- 64-byte signature (r, s)
- Can truncate r to 32 bytes, send full s (48 bytes total)
- More CPU-intensive than Ed25519

### 8.5. Key Management

**Design Principles:**
- No pre-shared network keys (each node has its own keypair)
- No mandatory CA infrastructure
- Trust is per-peer, not per-network
- Packet overhead must not increase for verified peers

**Bootstrap:**
1. Device generates Ed25519 keypair at first boot
2. Public key bound to node identifier (EUI-64 → IPv6 IID)
3. Private key stored securely, never transmitted

**Trust Establishment (Layered):**

Implementations MUST support TOFU. Other methods are OPTIONAL.

| Method | Infrastructure | Trust Level | Use Case |
|--------|---------------|-------------|----------|
| TOFU | None | Pinned | Default, works offline |
| DANE | DNSSEC | Verified | Internet-connected nodes |
| PKIX | CA | Verified | Enterprise deployments |

**1. TOFU (Trust On First Use) — Baseline**

- On first contact, accept peer's public key and pin it
- Bind key to peer's IPv6 IID (derived from EUI-64)
- On subsequent contacts, verify key matches pinned value
- Key change → reject and alert (potential MITM or hardware swap)
- Works entirely offline, no external infrastructure

```
Key Store Entry:
  IID: 1234:5678:9abc:def0
  PubKey: <32 bytes>
  TrustLevel: TOFU
  FirstSeen: <timestamp>
  LastSeen: <timestamp>
```

**2. DANE (RFC 6698) — Optional Upgrade**

When a node has a DNS name and internet connectivity:

- Derive DNS name from IPv6 address or explicit configuration
- Query TLSA record: `_25519._mesh.<node-name>`
- Verify public key matches DNSSEC-signed record
- Upgrade trust level from TOFU to DANE-verified
- Cache result; re-verify periodically or on key change

DANE verification happens out-of-band (via border router), not over LoRa.
No additional per-packet overhead.

**3. PKIX/ACME — Optional Upgrade**

For enterprise deployments requiring CA-issued certificates:

- Node provisions certificate via ACME (RFC 8555) or manual issuance
- Certificate stored locally, served on request
- Peers MAY fetch certificate via:
  - CoAP GET to `/.well-known/cert` (works over LoRa)
  - Border router HTTP endpoint (out-of-band)
  - Resource Directory certificate link
  - Pre-provisioning
- Once fetched, certificate is cached; only public key used in frames
- Certificate chains MUST NOT be embedded in every packet

**Out-of-Band Verification — Optional**

For high-security pairing without infrastructure:

- Display public key fingerprint (e.g., QR code, hex string)
- Manual comparison or scanning
- Upgrade trust level to "Verified"

**Key Compromise and Rotation:**

- Nodes SHOULD support key rotation announcements
- Key change with valid signature from old key → accept new key
- Key change without signature → reject, require re-verification
- Revocation: remove from local key store; no global revocation list

### 8.6. OSCORE (RFC 8613)

Object Security for Constrained RESTful Environments provides end-to-end
security for CoAP:

| Feature | OSCORE Provides |
|---------|-----------------|
| Confidentiality | AES-CCM-16-64-128 |
| Integrity | AEAD tag |
| Replay protection | Sequence number |
| Key derivation | HKDF from master secret |

**OSCORE Overhead:** 8-13 bytes (Partial IV + Tag)

### 8.7. RPL Secure Mode

RPL defines three security modes:

| Mode | Authentication | Confidentiality |
|------|----------------|-----------------|
| Unsecured | None | None |
| Preinstalled | Shared key | Optional |
| Authenticated | Per-node keys | Optional |

Recommended: **Preinstalled mode** with network-wide key for control plane,
OSCORE for data plane.

---

## 9. Transport Layer

### 9.1. UDP

Standard UDP (RFC 768), compressed via SCHC.

**Ports:**
| Port | Protocol |
|------|----------|
| 5683 | CoAP (unencrypted) |
| 5684 | CoAPS (DTLS) |
| 10883 | MQTT-SN |

### 9.2. No TCP

TCP is NOT recommended for LoRa mesh due to:
- High overhead (20-byte header minimum)
- Poor performance over lossy links
- Congestion control incompatible with duty cycles

Use CoAP (with Observe) or MQTT-SN for reliable messaging.

---

## 10. Application Layer

### 10.1. CoAP (RFC 7252)

Constrained Application Protocol - REST-like for constrained devices.

**Message Format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver| T |  TKL  |      Code     |          Message ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Token (if any, TKL bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Methods:**
| Code | Method |
|------|--------|
| 0.01 | GET |
| 0.02 | POST |
| 0.03 | PUT |
| 0.04 | DELETE |

### 10.2. CoAP Observe (RFC 7641)

Subscribe to resource changes:

```
GET /.well-known/core?rt=temperature
Observe: 0

<-- 2.05 Content
    Observe: 1
    {temperature: 23.5}

<-- 2.05 Content (notification)
    Observe: 2
    {temperature: 24.0}
```

### 10.3. CoAP Block-wise Transfer (RFC 7959)

Large payloads fragmented at CoAP layer (independent of SCHC fragmentation):

| Option | Value |
|--------|-------|
| Block1 | Request payload blocks |
| Block2 | Response payload blocks |
| Size1 | Request size hint |
| Size2 | Response size hint |

Block size: 16, 32, 64, 128, 256, 512, or 1024 bytes.

### 10.4. MQTT-SN (OASIS Standard)

MQTT for Sensor Networks - UDP-based MQTT variant.

**Key Differences from MQTT:**
- Topic IDs instead of strings (2 bytes vs. variable)
- QoS -1 (fire and forget, no connection)
- Gateway-assisted topic registration

**Message Types:**
| Type | Code | Description |
|------|------|-------------|
| CONNECT | 0x04 | Client connect |
| CONNACK | 0x05 | Connect acknowledgment |
| REGISTER | 0x0A | Register topic alias |
| REGACK | 0x0B | Registration acknowledgment |
| PUBLISH | 0x0C | Publish message |
| PUBACK | 0x0D | Publish acknowledgment |
| SUBSCRIBE | 0x12 | Subscribe to topic |
| SUBACK | 0x13 | Subscribe acknowledgment |

### 10.5. MQTT-SN over LoRa Mesh

**Architecture:**
```
[Sensor Node] --LoRa--> [MQTT-SN Gateway] --IP--> [MQTT Broker]
                              |
                        [Border Router]
```

Gateway at border router translates MQTT-SN ↔ MQTT 3.1.1/5.0.

### 10.6. Resource Directory (RFC 9176)

Border router runs CoAP Resource Directory for discovery:

```
# Registration
POST coap://[border-router]/rd?ep=sensor-42
</temperature>;rt="sensor";if="core.s"

# Lookup
GET coap://[border-router]/rd-lookup/res?rt=sensor
```

---

## 11. Node Types and Roles

### 11.1. Role Definitions

| Role | IPv6 | RPL | Forwards | Description |
|------|------|-----|----------|-------------|
| Leaf | Host | None | No | Endpoint device, no routing |
| Router | Router | Full | Yes | Mesh router, participates in DODAG |
| Border Router | Router | Root | Yes | DODAG root, internet gateway |
| Gateway | Host | None | L7 only | Protocol translator (MQTT-SN→MQTT) |

### 11.2. Leaf Node (Endpoint)

- Minimal resources (constrained MCU)
- Associates with one parent router
- Does not participate in RPL
- Sends all traffic via default parent

### 11.3. Router

- Full RPL participation
- Maintains neighbor table and routing state
- Forwards packets for children
- Sends DIOs, processes DAOs

### 11.4. Border Router (6LBR)

- DODAG root
- Assigns global prefix to mesh
- Routes between mesh and external IPv6
- Runs Resource Directory, NTP, etc.
- May aggregate multiple DODAGs

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

## 13. Packet Formats

### 13.1. Complete Packet Example

**Scenario:** Leaf node sends CoAP temperature reading to border router.

**Application payload (CoAP):**
```
Ver=1, T=NON, TKL=1, Code=2.05 (Content)
Token: 0x42
Options: Content-Format=60 (CBOR)
Payload: {temperature: 23.5} → A1 6B 74656D7065726174757265 F9 4BC0
         (17 bytes)
```

**After OSCORE:** (if enabled)
```
OSCORE option + encrypted payload + tag
(adds ~10 bytes)
```

**After SCHC compression (Rule 0):**
```
Rule ID: 0x00 (1 byte)
Residue: SrcPort[3:0], DstPort[3:0] (1 byte)
Compressed CoAP header: 0x42 0x45 (2 bytes)
Payload: (17 bytes)
Total: 21 bytes
```

**With 6LoWPAN dispatch:**
```
SCHC dispatch: 0x14 (1 byte)
SCHC packet: (21 bytes)
Total: 22 bytes
```

**Link-layer frame:**
```
Length: 38 (1 byte)
LLSec: 0x20 (signature, no encryption, short addr) (1 byte)
SeqNum: 0x0042 (2 bytes)
DstAddr: 0x0001 (border router short) (2 bytes)
Payload: (22 bytes)
Signature: (32 bytes, truncated Ed25519)
Total: 60 bytes
```

**LoRa PHY:**
```
Preamble: 8 symbols
Header: 3 bytes (implicit mode)
Payload: 60 bytes
CRC: 2 bytes
```

### 13.2. Packet Size Summary

| Layer | This Protocol | Meshtastic | MeshCore |
|-------|---------------|------------|----------|
| App payload | 17 | 17 | 17 |
| Security (E2E) | 10 | 0* | 2 |
| Transport + Network | 2 | 16 | - |
| Routing overhead | 0-6 | 0-7 | 0-64 |
| Link security | 35 | 0 | 4 |
| **Total** | **64-70** | **33-40** | **23-87** |

*Meshtastic AES-CTR has no auth overhead; this is a weakness.

### 13.3. RPL DIO Packet

```
Link-layer:
  [Len] [LLSec] [SeqNum] [DstAddr=ff02::1a] [Payload] [Sig]

IPv6 (compressed):
  [SCHC Rule 2] [HopLimit] [Multicast flag]

ICMPv6:
  Type=155, Code=1 (DIO)

DIO payload:
  [RPLInstanceID] [Version] [Rank] [Flags] [DODAGID]

Options:
  [DODAG Configuration] [Prefix Information]
```

---

## 14. Timing and Duty Cycle

### 14.1. Trickle Timer (DIO)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Imin | 4 seconds | Allow network stabilization |
| Imax | 17 minutes | Reduce steady-state overhead |
| k | 10 | Suppress redundant DIOs |

### 14.2. DAO Timing

| Event | Delay |
|-------|-------|
| Initial DAO | Random 0-2 seconds after joining |
| DAO retry | 4, 8, 16 seconds (exponential backoff) |
| DAO refresh | 30 minutes (soft state lifetime / 2) |

### 14.3. Data Traffic

| Traffic Type | Recommended Interval |
|--------------|---------------------|
| Periodic telemetry | 5-60 minutes |
| Event-driven | As needed |
| Heartbeat/keepalive | 30 minutes |

### 14.4. Duty Cycle Compliance

**EU 868 MHz (10% duty cycle):**

At SF9/125kHz, airtime per 60-byte packet ≈ 200ms.

Max packets per hour: `3600s * 0.1 / 0.2s = 1800 packets`

Per node, accounting for routing: ~100-300 packets/hour comfortable.

### 14.5. CSMA/CA Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CAD timeout | 3 symbols | Channel activity detection |
| Backoff unit | 10 ms | Slot time |
| Backoff max | 5 | CW = 2^backoff - 1 |
| Retry limit | 3 | Before reporting failure |

---

## 15. Security Considerations

### 15.1. Cryptographic Strength

| Primitive | Security Level | Notes |
|-----------|----------------|-------|
| Ed25519 | 128 bits | Truncated to 32B OK |
| AES-128-CCM | 128 bits | Used by OSCORE |
| HKDF-SHA256 | 256 bits | Key derivation |

### 15.2. Key Storage

Private keys MUST be stored in:
- Hardware secure element (preferred)
- Flash with readout protection
- Never transmitted over the air

### 15.3. Replay Protection

| Layer | Mechanism |
|-------|-----------|
| Link | 16-bit SeqNum with window |
| OSCORE | Partial IV / Sequence Number |
| RPL | Secure mode counters |

### 15.4. Known Limitations

1. **No perfect forward secrecy:** Static ECDH keys
2. **Truncated signatures:** 128-bit security (acceptable for most uses)
3. **DoS possible:** Radio jamming cannot be prevented
4. **Metadata visible:** Link-layer headers unencrypted

### 15.5. Recommendations

1. Rotate keys annually or on suspected compromise
2. Use OSCORE for all CoAP traffic
3. Enable RPL secure mode in adversarial environments
4. Monitor for routing anomalies

---

## 16. Implementation Notes

### 16.1. Recommended Platforms

| Platform | OS | Notes |
|----------|-----|-------|
| nRF52840 | Zephyr, RIOT | BLE + LoRa (via SPI radio) |
| ESP32-S3 | ESP-IDF, Zephyr | WiFi gateway + LoRa |
| STM32WL | Zephyr, bare metal | Integrated LoRa SoC |
| STM32L4 + SX126x | Contiki-NG | Mature 6LoWPAN stack |

### 16.2. Software Stack

| Component | Recommended |
|-----------|-------------|
| 6LoWPAN/RPL | Contiki-NG, RIOT GNRC |
| SCHC | libschc, OpenSCHC |
| CoAP | libcoap, microcoap |
| OSCORE | RISE OSCORE, aiocoap |
| MQTT-SN | Eclipse Paho MQTT-SN |
| Crypto | TweetNaCl, mbedTLS |

### 16.3. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| IPv6 stack | 8-16 KB | 20-40 KB |
| RPL | 4-8 KB | 15-25 KB |
| CoAP | 2-4 KB | 10-20 KB |
| OSCORE | 2-4 KB | 10-15 KB |
| Crypto | 1-2 KB | 10-20 KB |
| **Total** | **20-40 KB** | **65-120 KB** |

Feasible on nRF52840 (256KB RAM, 1MB Flash) or ESP32.

---

## 17. Local Client Interface

### 17.1. Overview

The Local Client Interface (LCI) connects external applications (phone apps,
desktop clients, RTOS tasks) to the mesh node. Unlike Meshtastic's proprietary
protobuf-over-GATT approach, LCI treats the local connection as another IPv6
interface, using the same CoAP protocol stack as mesh traffic.

**Design Principles:**

1. **Unified protocol:** CoAP everywhere, no separate local API
2. **Transport-agnostic:** Same framing works over BLE, serial, USB, IPC
3. **Client is a neighbor:** Gets link-local IPv6 address, routes through node
4. **Standard tools work:** Any CoAP client can control the node
5. **Push via Observe:** Notifications use CoAP Observe (RFC 7641)

### 17.2. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         Client Device                          │
│  (Phone, Laptop, RTOS Task)                                    │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Mesh App     │  │ Config Tool  │  │ Other CoAP Clients   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘ │
│         │                 │                      │             │
│         └─────────────────┼──────────────────────┘             │
│                           │                                    │
│                    ┌──────┴───────┐                            │
│                    │ CoAP Client  │                            │
│                    │ fe80::client │                            │
│                    └──────┬───────┘                            │
└───────────────────────────┼────────────────────────────────────┘
                            │ SLIP / BLE / IPC
┌───────────────────────────┼────────────────────────────────────┐
│                    ┌──────┴───────┐          Mesh Node         │
│                    │ Local I/F    │                            │
│                    │ fe80::1      │                            │
│                    └──────┬───────┘                            │
│                           │                                    │
│                    ┌──────┴───────┐                            │
│                    │  IPv6 Stack  │                            │
│                    │  CoAP Server │                            │
│                    │  fe80::node  │                            │
│                    └──────┬───────┘                            │
│                           │                                    │
│                    ┌──────┴───────┐                            │
│                    │ LoRa Radio   │                            │
│                    │ Interface    │                            │
│                    └──────────────┘                            │
└────────────────────────────────────────────────────────────────┘
```

The client and node communicate via link-local IPv6. The node acts as a
router: traffic to mesh addresses is forwarded over LoRa.

### 17.3. Transport Bindings

All transports carry IPv6 packets. Framing adapts to the transport.

#### 17.3.1. Serial / USB (SLIP)

SLIP (RFC 1055) framing over UART or USB CDC-ACM:

```
┌──────┬─────────────────────┬──────┐
│ 0xC0 │  IPv6 Packet        │ 0xC0 │
│ END  │  (escaped)          │ END  │
└──────┴─────────────────────┴──────┘
```

Escaping:
- 0xC0 (END) in data → 0xDB 0xDC
- 0xDB (ESC) in data → 0xDB 0xDD

Recommended baud: 115200 or higher.

#### 17.3.2. Bluetooth Low Energy

**Option A: SLIP over BLE UART (Nordic UART Service or similar)**

- UUID: vendor-specific or 6E400001-B5A3-F393-E0A9-E50E24DCCA9E (NUS)
- TX/RX characteristics carry SLIP-framed IPv6
- Simple, works with existing BLE serial libraries

**Option B: 6LoWPAN over BLE (RFC 7668)**

- Standard IPSP (Internet Protocol Support Profile)
- L2CAP connection-oriented channels
- More overhead, but fully standard
- Header compression via 6LoWPAN IPHC

Implementations SHOULD support Option A. Option B is OPTIONAL.

#### 17.3.3. Bluetooth Classic (SPP)

SLIP framing over RFCOMM/SPP. Same as serial.

#### 17.3.4. RTOS IPC (Same-Device)

For applications running on the same MCU as the network stack:

```c
// Send IPv6 packet to network stack
void lci_send(const uint8_t *ipv6_pkt, size_t len);

// Receive IPv6 packet from network stack
size_t lci_recv(uint8_t *buf, size_t max_len, uint32_t timeout_ms);
```

Implementation may use:
- FreeRTOS queues / stream buffers
- Zephyr message queues / pipes
- Direct function calls (if same thread context)

No framing needed; packets are discrete.

### 17.4. Client IPv6 Address

The client obtains a link-local address for the local interface:

**Static (simple):**
```
Client: fe80::2
Node:   fe80::1
```

**EUI-64 derived:**
```
Client: fe80::<IID from device MAC>
Node:   fe80::<IID from node EUI-64>
```

The node acts as default router for the client. Client's routing table:

```
fe80::/10       → local interface (direct)
::/0            → fe80::1 (node)
```

### 17.5. CoAP Resources

The node exposes a CoAP server on UDP port 5683. All resources below are
relative to the node's link-local address.

#### 17.5.1. Discovery

```
GET coap://[fe80::1]/.well-known/core

Response:
</config>;rt="config",
</config/radio>;rt="config",
</config/identity>;rt="config",
</status>;rt="status";obs,
</status/neighbors>;rt="status";obs,
</status/routes>;rt="status",
</keys>;rt="keystore",
</mesh>;rt="proxy"
```

#### 17.5.2. Configuration Resources

**Node Configuration**

```
GET /config
Content-Format: application/cbor

{
  "name": "my-node",
  "role": "router",         // "leaf", "router", "border-router"
  "radio": "/config/radio",
  "identity": "/config/identity"
}
```

```
PUT /config
Content-Format: application/cbor

{
  "name": "new-name",
  "role": "router"
}

Response: 2.04 Changed
```

**Radio Configuration**

```
GET /config/radio
Content-Format: application/cbor

{
  "freq_mhz": 906.875,
  "bw_khz": 125,
  "sf": 9,
  "cr": "4/5",
  "tx_power_dbm": 20,
  "sync_word": "0x34"
}
```

```
PUT /config/radio
Content-Format: application/cbor

{
  "sf": 10,
  "tx_power_dbm": 17
}

Response: 2.04 Changed
```

**Identity (Read-Only)**

```
GET /config/identity
Content-Format: application/cbor

{
  "eui64": "0x0011223344556677",
  "pubkey": "<base64 Ed25519 public key>",
  "pubkey_fingerprint": "SHA256:xY7...",
  "addrs": {
    "link_local": "fe80::0211:22ff:fe33:4455",
    "ula": "fd12:3456:789a:1::0211:22ff:fe33:4455",
    "gua": null
  }
}
```

#### 17.5.3. Status Resources

**Node Status (Observable)**

```
GET /status
Observe: 0
Content-Format: application/cbor

{
  "uptime_s": 3600,
  "battery_pct": 87,
  "battery_mv": 3950,
  "mem_free_kb": 42,
  "dodag": {
    "joined": true,
    "rank": 512,
    "parent": "fe80::1234:5678:9abc:def0",
    "root": "fd12:3456:789a:1::1"
  },
  "radio": {
    "rx_packets": 1234,
    "tx_packets": 567,
    "rx_errors": 12,
    "duty_cycle_pct": 2.3
  }
}
```

Status updates pushed via Observe on significant changes.

**Neighbor Table (Observable)**

```
GET /status/neighbors
Content-Format: application/cbor

{
  "neighbors": [
    {
      "addr": "fe80::aaaa:bbbb:cccc:dddd",
      "rssi_dbm": -85,
      "snr_db": 7.5,
      "etx": 1.2,
      "last_seen_s": 30,
      "trust": "tofu"
    },
    {
      "addr": "fe80::1111:2222:3333:4444",
      "rssi_dbm": -72,
      "snr_db": 12.0,
      "etx": 1.0,
      "last_seen_s": 5,
      "trust": "dane"
    }
  ]
}
```

**Routing Table**

```
GET /status/routes
Content-Format: application/cbor

{
  "routes": [
    {
      "prefix": "fd12:3456:789a:1::/64",
      "via": "fe80::1234:5678:9abc:def0",
      "metric": 512,
      "lifetime_s": 1800
    }
  ],
  "default_route": "fe80::1234:5678:9abc:def0"
}
```

#### 17.5.4. Key Store

**List Keys**

```
GET /keys
Content-Format: application/cbor

{
  "keys": [
    {
      "iid": "1234:5678:9abc:def0",
      "pubkey_fp": "SHA256:xY7...",
      "trust": "tofu",
      "first_seen": "2026-05-26T12:00:00Z",
      "last_seen": "2026-05-26T14:30:00Z"
    }
  ]
}
```

**Get Single Key**

```
GET /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "iid": "1234:5678:9abc:def0",
  "pubkey": "<base64>",
  "trust": "tofu",
  "first_seen": "2026-05-26T12:00:00Z",
  "last_seen": "2026-05-26T14:30:00Z"
}
```

**Add/Update Key (Manual Trust)**

```
PUT /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "pubkey": "<base64>",
  "trust": "verified"
}

Response: 2.04 Changed
```

**Delete Key**

```
DELETE /keys/1234:5678:9abc:def0

Response: 2.02 Deleted
```

#### 17.5.5. Mesh Proxy

The client can reach any mesh node by addressing it directly. The local
node routes the traffic. No special proxy resource is required.

```
# Client sends directly to mesh node
GET coap://[fd12:3456:789a:1::aaaa:bbbb:cccc:dddd]/sensors/temp

# Node routes via LoRa mesh, returns response to client
Response: 2.05 Content
{temperature: 23.5}
```

For discovery, the client can query the Resource Directory (if available):

```
GET coap://[fd12:3456:789a:1::1]/rd-lookup/res?rt=temperature
```

#### 17.5.6. Messaging (Application-Level)

For human messaging (chat-like), nodes MAY implement:

```
# Send message
POST /msg
Content-Format: application/cbor

{
  "to": "fd12:3456:789a:1::aaaa:bbbb:cccc:dddd",
  "body": "Hello from the mesh!",
  "ack": true
}

Response: 2.01 Created
Location-Path: /msg/outbox/42
```

```
# Receive messages (Observable)
GET /msg/inbox
Observe: 0
Content-Format: application/cbor

{
  "messages": [
    {
      "id": 17,
      "from": "fd12:3456:789a:1::1111:2222:3333:4444",
      "body": "Hi there!",
      "received": "2026-05-26T14:35:00Z"
    }
  ]
}
```

This is OPTIONAL. Applications MAY instead use CoAP directly to mesh nodes.

### 17.6. Security

#### 17.6.1. Transport Security

The local link may be unencrypted (trusted physical access) or encrypted:

| Transport | Encryption |
|-----------|------------|
| USB/Serial | None (physical security) |
| BLE | BLE pairing (LE Secure Connections) |
| WiFi | WPA2/3 |
| RTOS IPC | None (same device) |

#### 17.6.2. Application Security

For sensitive operations, use OSCORE over the local link:

- OSCORE context established via pairing
- Protects against compromised transport
- Same mechanism as mesh traffic

#### 17.6.3. Access Control

Implementations SHOULD support restricting local client access:

| Level | Allowed Operations |
|-------|-------------------|
| Read-only | GET on all resources |
| Standard | GET, Observe, mesh proxy |
| Admin | All operations including PUT /config, DELETE /keys |

Access level determined by transport (e.g., USB = admin, BLE = standard).

### 17.7. Implementation Notes

**Minimal Implementation:**

A constrained node MUST implement:
- SLIP framing (serial)
- /.well-known/core
- /config (read-only acceptable)
- /status

**Full Implementation:**

A capable node (border router, gateway) SHOULD implement:
- All transports (SLIP, BLE, WiFi if available)
- All resources
- Observe on status resources
- OSCORE for local link

**Memory Impact:**

| Component | Additional RAM | Additional Flash |
|-----------|----------------|------------------|
| SLIP framing | 256 B | 512 B |
| LCI CoAP resources | 1-2 KB | 4-8 KB |
| BLE UART service | 512 B | 2 KB |

---

## 18. Applications

This section defines standard application-layer features using IETF protocols.
All features use CoAP (RFC 7252) with CBOR payloads and leverage existing
standards wherever possible.

### 18.1. Messaging

Text messaging between nodes, supporting unicast, multicast, and broadcast.

**Relevant Standards:**
- CoAP (RFC 7252) for transport
- CoAP Observe (RFC 7641) for push notifications
- CBOR (RFC 8949) for encoding

#### 18.1.1. Message Format

```cbor
{
  "id": 12345,                    ; unique message ID (uint)
  "from": "fd12:...:1111",        ; sender IPv6 (string)
  "to": "fd12:...:2222",          ; recipient or "ff02::1" for broadcast (string)
  "ts": 1716742800,               ; Unix timestamp (uint)
  "body": "Hello from the mesh",  ; message text (tstr)
  "ack": true,                    ; request delivery receipt (bool, optional)
  "priority": 0,                  ; 0=normal, 1=high, 2=emergency (uint, optional)
  "reply_to": 12340,              ; references previous message (uint, optional)
  "ttl": 3600                     ; message expires after N seconds (uint, optional)
}
```

#### 18.1.2. Resources

**Send Message:**

```
POST coap://[destination]/msg/inbox
Content-Format: application/cbor

{
  "body": "Hello!",
  "ack": true
}

Response: 2.01 Created
Location-Path: /msg/sent/12345
```

For broadcast, POST to `coap://[ff02::1]/msg/inbox` (link-local all-nodes)
or use the mesh multicast address.

**Receive Messages (Observable):**

```
GET coap://[node]/msg/inbox
Observe: 0
Content-Format: application/cbor

{
  "messages": [
    {"id": 123, "from": "...", "ts": ..., "body": "Hi"}
  ],
  "unread": 3
}
```

New messages trigger Observe notifications.

**Delivery Receipt:**

When `ack: true`, recipient sends:

```
POST coap://[sender]/msg/ack
Content-Format: application/cbor

{
  "id": 12345,
  "status": "delivered",    ; "delivered", "read", "failed"
  "ts": 1716742900
}
```

#### 18.1.3. Canned Messages

Pre-defined messages for quick sending (configurable):

```
GET coap://[node]/msg/canned
Content-Format: application/cbor

{
  "messages": [
    {"id": 0, "text": "I'm OK"},
    {"id": 1, "text": "Need assistance"},
    {"id": 2, "text": "At checkpoint"},
    {"id": 3, "text": "Returning to base"},
    {"id": 4, "text": "Emergency - send help"}
  ]
}
```

```
POST coap://[destination]/msg/inbox
Content-Format: application/cbor

{"canned": 4, "ack": true}
```

#### 18.1.4. Store-and-Forward

Nodes MAY implement store-and-forward for offline recipients:

1. Sender POSTs to destination
2. If destination unreachable, intermediate node stores message
3. When destination appears, stored messages are delivered
4. TTL prevents unbounded storage

Store-and-forward nodes advertise capability:

```
GET /.well-known/core?rt=msg.store

</msg/store>;rt="msg.store"
```

Implementation is OPTIONAL. Maximum stored messages and TTL are
implementation-defined.

### 18.2. Position Sharing

Real-time location sharing for mutual awareness ("blue force tracking").

**Relevant Standards:**
- SenML (RFC 8428) for data format (see Appendix F)
- CoAP Observe (RFC 7641) for streaming
- GeoJSON (RFC 7946) for waypoint concepts

#### 18.2.1. Position Beacon

Nodes with GPS SHOULD periodically broadcast position:

```
PUT coap://[ff02::1]/pos
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416}
]
```

Beacon interval: configurable, default 60 seconds when moving, 300 when stationary.

Nodes receiving beacons update their position cache:

```
GET coap://[node]/pos/cache
Content-Format: application/cbor

{
  "positions": [
    {
      "node": "fd12:...:1111",
      "lat": 37.774929,
      "lon": -122.419416,
      "alt": 10.5,
      "ts": 1716742800,
      "age_s": 45
    }
  ]
}
```

#### 18.2.2. Position Query

Request current position from specific node:

```
GET coap://[target]/sensors/location
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:...", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "alt", "u": "m", "v": 10.5},
  {"n": "speed", "u": "m/s", "v": 1.2},
  {"n": "heading", "u": "deg", "v": 45}
]
```

#### 18.2.3. Position Subscribe

Observe a node's position for continuous tracking:

```
GET coap://[target]/sensors/location
Observe: 0

<-- 2.05 Content (initial position)
<-- 2.05 Content (notification on movement)
...
```

Notification triggers: distance threshold (e.g., 50m) or time interval.

#### 18.2.4. Privacy Considerations

Nodes MAY implement position privacy:

| Setting | Behavior |
|---------|----------|
| public | Beacon to all, respond to queries |
| group | Beacon to group only, query requires auth |
| private | No beacon, query requires explicit auth |
| off | GPS disabled, no position sharing |

```
GET coap://[node]/config/privacy
Content-Format: application/cbor

{"location": "group"}
```

### 18.3. Waypoints

Shareable points of interest with metadata.

**Relevant Standards:**
- GeoJSON (RFC 7946) concepts, CBOR-encoded
- CoAP Resource Directory (RFC 9176) for discovery

#### 18.3.1. Waypoint Format

```cbor
{
  "id": "wpt-001",              ; unique ID (tstr)
  "name": "Rally Point Alpha",  ; human-readable name (tstr)
  "lat": 37.774929,             ; WGS84 latitude (float)
  "lon": -122.419416,           ; WGS84 longitude (float)
  "alt": 10.5,                  ; altitude meters (float, optional)
  "icon": "flag",               ; icon hint (tstr, optional)
  "color": "#FF0000",           ; color hint (tstr, optional)
  "notes": "Meet here at 1400", ; description (tstr, optional)
  "created": 1716742800,        ; creation time (uint)
  "creator": "fd12:...:1111",   ; creator node (tstr)
  "expires": 1716829200         ; expiration time (uint, optional)
}
```

Icon values (suggested): `flag`, `marker`, `camp`, `water`, `danger`,
`medical`, `vehicle`, `poi`, `start`, `finish`, `checkpoint`.

#### 18.3.2. Resources

**List Waypoints:**

```
GET coap://[node]/waypoints
Content-Format: application/cbor

{
  "waypoints": [
    {"id": "wpt-001", "name": "Rally Point Alpha", "lat": ..., "lon": ...},
    {"id": "wpt-002", "name": "Water Source", "lat": ..., "lon": ...}
  ]
}
```

**Get Single Waypoint:**

```
GET coap://[node]/waypoints/wpt-001
Content-Format: application/cbor

{"id": "wpt-001", "name": "Rally Point Alpha", ...}
```

**Create Waypoint:**

```
POST coap://[node]/waypoints
Content-Format: application/cbor

{
  "name": "Checkpoint 3",
  "lat": 37.78,
  "lon": -122.42,
  "icon": "checkpoint"
}

Response: 2.01 Created
Location-Path: /waypoints/wpt-003
```

**Share Waypoint:**

```
POST coap://[destination]/waypoints
Content-Format: application/cbor

{
  "name": "Rally Point Alpha",
  "lat": 37.774929,
  "lon": -122.419416,
  "notes": "Meet here at 1400",
  "creator": "fd12:...:1111"
}

Response: 2.01 Created
```

**Broadcast Waypoint:**

```
POST coap://[ff02::1]/waypoints
Content-Format: application/cbor

{...waypoint...}
```

**Delete Waypoint:**

```
DELETE coap://[node]/waypoints/wpt-001

Response: 2.02 Deleted
```

#### 18.3.3. Routes

Ordered list of waypoints:

```cbor
{
  "id": "route-001",
  "name": "Patrol Route A",
  "waypoints": ["wpt-001", "wpt-002", "wpt-003"],
  "distance_m": 2500,           ; total distance (uint, optional)
  "created": 1716742800,
  "creator": "fd12:...:1111"
}
```

Resources: `/routes`, `/routes/{id}` - same CRUD pattern as waypoints.

### 18.4. Emergency / SOS

Priority alerting for emergencies.

**Relevant Standards:**
- CoAP (RFC 7252)
- CAP concepts (OASIS Common Alerting Protocol) for alert structure

#### 18.4.1. Emergency Alert Format

```cbor
{
  "type": "sos",               ; "sos", "medical", "security", "cancel" (tstr)
  "node": "fd12:...:1111",     ; originating node (tstr)
  "ts": 1716742800,            ; timestamp (uint)
  "lat": 37.774929,            ; position if available (float, optional)
  "lon": -122.419416,          ; (float, optional)
  "msg": "Injured, need evac", ; details (tstr, optional)
  "seq": 1                     ; sequence for updates (uint)
}
```

Alert types:

| Type | Meaning |
|------|---------|
| sos | General emergency |
| medical | Medical emergency |
| security | Security threat |
| fire | Fire emergency |
| cancel | Cancel previous alert |

#### 18.4.2. Sending Emergency Alert

**Dedicated SOS endpoint with multicast:**

```
POST coap://[ff02::1]/sos
Content-Format: application/cbor

{
  "type": "sos",
  "msg": "Injured, need help"
}

Response: 2.01 Created
```

Nodes receiving SOS:
1. Display alert prominently
2. Re-broadcast once (controlled flooding, TTL-limited)
3. Log to `/sos/log`

#### 18.4.3. SOS Button Behavior

Hardware SOS button (if present):

| Action | Result |
|--------|--------|
| Press and hold 3s | Initiate SOS |
| Triple-press | Initiate SOS |
| Press during SOS | Send update with current position |
| Hold 5s during SOS | Cancel SOS |

#### 18.4.4. Emergency Resources

**View Active Emergencies:**

```
GET coap://[node]/sos
Content-Format: application/cbor

{
  "active": [
    {
      "node": "fd12:...:1111",
      "type": "medical",
      "ts": 1716742800,
      "lat": 37.77,
      "lon": -122.42,
      "msg": "Broken leg"
    }
  ]
}
```

**Emergency Log:**

```
GET coap://[node]/sos/log
Content-Format: application/cbor

{
  "events": [
    {"ts": 1716742800, "node": "...", "type": "sos", "action": "initiated"},
    {"ts": 1716743000, "node": "...", "type": "sos", "action": "cancelled"}
  ]
}
```

#### 18.4.5. Network Behavior During Emergency

When SOS is active:

1. **Priority routing:** SOS packets get priority in TX queue
2. **Beacon boost:** Originating node beacons position every 30s
3. **Relay duty:** All nodes relay SOS (once per SOS ID)
4. **Persistence:** SOS remains active until cancelled or 4-hour timeout

### 18.5. Presence and Status

Node availability and activity status.

**Relevant Standards:**
- PIDF concepts (RFC 3863) simplified for CBOR
- CoAP Observe (RFC 7641)

#### 18.5.1. Presence Format

```cbor
{
  "status": "available",      ; presence status (tstr)
  "activity": "moving",       ; activity hint (tstr, optional)
  "msg": "On patrol",         ; custom status message (tstr, optional)
  "battery": 87,              ; battery percentage (uint, optional)
  "ts": 1716742800            ; last update (uint)
}
```

Status values (based on RFC 3863 simplified):

| Status | Meaning |
|--------|---------|
| available | Online and reachable |
| busy | Online but occupied |
| away | Temporarily unavailable |
| offline | Not reachable |
| emergency | In emergency state |

Activity values (optional refinement):

| Activity | Meaning |
|----------|---------|
| stationary | Not moving |
| moving | In motion |
| resting | Taking break |
| working | Performing task |

#### 18.5.2. Resources

**Get/Set Own Presence:**

```
GET coap://[node]/presence
Content-Format: application/cbor

{"status": "available", "activity": "moving", "battery": 87}
```

```
PUT coap://[node]/presence
Content-Format: application/cbor

{"status": "busy", "msg": "In meeting"}

Response: 2.04 Changed
```

**Subscribe to Peer Presence:**

```
GET coap://[peer]/presence
Observe: 0

<-- 2.05 Content {"status": "available", ...}
<-- 2.05 Content {"status": "away", ...}  (on change)
```

**Presence Cache (All Known Nodes):**

```
GET coap://[node]/presence/cache
Content-Format: application/cbor

{
  "nodes": [
    {"addr": "fd12:...:1111", "status": "available", "battery": 87, "age_s": 30},
    {"addr": "fd12:...:2222", "status": "away", "battery": 45, "age_s": 120}
  ]
}
```

#### 18.5.3. Automatic Status

Nodes SHOULD automatically update status based on:

| Condition | Status | Activity |
|-----------|--------|----------|
| GPS shows movement | available | moving |
| GPS stationary > 5min | available | stationary |
| No user interaction > 30min | away | - |
| SOS active | emergency | - |
| Battery < 10% | (unchanged) | (add low_battery flag) |

### 18.6. Check-In / Roll Call

Group accountability and safety checks.

**Relevant Standards:**
- CoAP Group Communication (RFC 7390)
- CoAP Observe (RFC 7641)

#### 18.6.1. Check-In

Individual node checks in with group/leader:

```
POST coap://[leader]/checkin
Content-Format: application/cbor

{
  "node": "fd12:...:1111",
  "ts": 1716742800,
  "lat": 37.77,
  "lon": -122.42,
  "status": "ok",              ; "ok", "help", "delayed"
  "msg": "At checkpoint 2"     ; optional note
}

Response: 2.04 Changed
```

#### 18.6.2. Roll Call (Group Query)

Leader initiates roll call via multicast:

```
POST coap://[ff02::mesh]/rollcall
Content-Format: application/cbor

{
  "id": "roll-001",
  "from": "fd12:...:leader",
  "ts": 1716742800,
  "timeout_s": 60
}
```

Nodes respond with unicast check-in to leader.

#### 18.6.3. Roll Call Status

Leader tracks responses:

```
GET coap://[leader]/rollcall/roll-001
Content-Format: application/cbor

{
  "id": "roll-001",
  "started": 1716742800,
  "timeout_s": 60,
  "responded": [
    {"node": "fd12:...:1111", "ts": 1716742810, "status": "ok"},
    {"node": "fd12:...:2222", "ts": 1716742815, "status": "ok"}
  ],
  "missing": [
    {"node": "fd12:...:3333", "last_seen": 1716740000}
  ]
}
```

#### 18.6.4. Scheduled Check-Ins

Nodes can be configured for automatic periodic check-in:

```
PUT coap://[node]/config/checkin
Content-Format: application/cbor

{
  "enabled": true,
  "target": "fd12:...:leader",
  "interval_s": 900,           ; every 15 minutes
  "include_location": true
}
```

Missed check-ins trigger alerts (see 18.4).

### 18.7. Range Testing

Link quality diagnostics.

**Relevant Standards:**
- ICMPv6 Echo (RFC 4443)
- SenML (RFC 8428) for telemetry response

#### 18.7.1. Basic Ping

Standard ICMPv6 Echo Request/Reply for reachability:

```
ping6 fd12:3456:789a:1::1111
```

Returns: RTT, reachable/unreachable.

#### 18.7.2. Extended Range Test

Application-layer test with radio telemetry:

```
POST coap://[target]/diag/rangetest
Content-Format: application/cbor

{
  "seq": 1,
  "payload_len": 32,          ; optional: test with specific payload size
  "count": 5                  ; optional: request N responses
}

Response: 2.05 Content
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:...", "bt": 1716742800},
  {"n": "seq", "v": 1},
  {"n": "rssi", "u": "dBm", "v": -85},
  {"n": "snr", "u": "dB", "v": 7.5},
  {"n": "sf", "v": 9},
  {"n": "freq", "u": "MHz", "v": 906.875}
]
```

#### 18.7.3. Continuous Range Test

For walk/drive testing:

```
GET coap://[target]/diag/rangetest
Observe: 0
Content-Format: application/cbor

{"interval_ms": 5000}

<-- 2.05 Content (every 5s with RSSI/SNR)
```

#### 18.7.4. Trace Route

Discover path through mesh:

```
GET coap://[target]/diag/traceroute
Content-Format: application/cbor

{
  "hops": [
    {"addr": "fe80::1111", "rssi": -65, "rtt_ms": 120},
    {"addr": "fe80::2222", "rssi": -78, "rtt_ms": 340},
    {"addr": "fe80::3333", "rssi": -82, "rtt_ms": 580}
  ],
  "total_hops": 3,
  "total_rtt_ms": 580
}
```

Implementation: Uses RPL source routing information or hop-by-hop probing.

### 18.8. Groups and Channels

Logical separation of communication.

**Relevant Standards:**
- CoAP Group Communication (RFC 7390)
- OSCORE Group (RFC 9203) for group encryption

#### 18.8.1. Group Concept

Groups provide:
1. **Multicast address:** For group-wide broadcasts
2. **Encryption context:** Optional per-group OSCORE key
3. **Resource namespace:** `/groups/{gid}/...`

```cbor
{
  "id": "team-alpha",
  "name": "Team Alpha",
  "mcast": "ff35:40:fd12:3456:789a:1::1",  ; mesh-local multicast
  "members": [
    "fd12:...:1111",
    "fd12:...:2222",
    "fd12:...:3333"
  ],
  "key_id": "key-alpha-001"    ; OSCORE Group key reference (optional)
}
```

#### 18.8.2. Group Multicast Addressing

Per RFC 7390 and RFC 3306 (unicast-prefix-based multicast):

```
ff35:0040:<64-bit ULA prefix>::<16-bit group ID>
```

Example: Group 1 on mesh `fd12:3456:789a:1::/64`:
```
ff35:0040:fd12:3456:789a:0001::0001
```

#### 18.8.3. Group Resources

**List Groups:**

```
GET coap://[node]/groups
Content-Format: application/cbor

{
  "groups": [
    {"id": "team-alpha", "name": "Team Alpha", "members": 3},
    {"id": "all", "name": "All Nodes", "members": 12}
  ]
}
```

**Group Messaging:**

```
POST coap://[group-mcast]/msg/inbox
Content-Format: application/cbor

{"body": "Team Alpha, rally at checkpoint 2"}
```

**Group Position Sharing:**

```
PUT coap://[group-mcast]/pos
Content-Format: application/senml+cbor

[...position SenML...]
```

#### 18.8.4. Group Key Management

For encrypted groups (OSCORE Group per RFC 9203):

```
GET coap://[node]/groups/team-alpha/key
Content-Format: application/cbor

{
  "key_id": "key-alpha-001",
  "algorithm": "AES-CCM-16-64-128",
  "expires": 1716829200
}
```

Key distribution is out-of-band or via secure unicast to each member.

### 18.9. Resource Summary

| Resource | Methods | Observable | Description |
|----------|---------|------------|-------------|
| /msg/inbox | GET, POST | Yes | Message inbox |
| /msg/sent | GET | No | Sent messages |
| /msg/ack | POST | No | Delivery receipts |
| /msg/canned | GET, PUT | No | Preset messages |
| /pos | PUT | No | Position broadcast (multicast) |
| /pos/cache | GET | Yes | Cached peer positions |
| /waypoints | GET, POST | Yes | Waypoint list |
| /waypoints/{id} | GET, PUT, DELETE | No | Single waypoint |
| /routes | GET, POST | No | Route list |
| /routes/{id} | GET, PUT, DELETE | No | Single route |
| /sos | GET, POST | Yes | Emergency alerts |
| /sos/log | GET | No | Emergency history |
| /presence | GET, PUT | Yes | Own presence status |
| /presence/cache | GET | Yes | Peer presence cache |
| /checkin | POST | No | Check-in submission |
| /rollcall | POST | No | Initiate roll call |
| /rollcall/{id} | GET | Yes | Roll call status |
| /groups | GET, POST | No | Group list |
| /groups/{id} | GET, PUT, DELETE | No | Single group |
| /diag/rangetest | GET, POST | Yes | Range testing |
| /diag/traceroute | GET | No | Path discovery |

### 18.10. Content-Format Summary

| Content-Format | ID | Usage |
|----------------|-----|-------|
| application/cbor | 60 | General structured data |
| application/senml+cbor | 112 | Sensor/telemetry data |
| application/link-format | 40 | Resource discovery |

---

## Appendix A: SCHC Compression Rules

### A.1. Rule Set

| Rule ID | Use Case | Compressed Size |
|---------|----------|-----------------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes |
| 2 | ICMPv6 Echo | 3 bytes |
| 3 | RPL DIO | 8 bytes |
| 4 | RPL DAO | 6 bytes |
| 255 | No compression | Full headers |

### A.2. CoAP Compression

| Field | TV | MO | CDA |
|-------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent (2 bits) |
| TKL | - | ignore | value-sent (4 bits) |
| Code | - | ignore | value-sent (8 bits) |
| MID | - | ignore | value-sent (16 bits) |
| Token | - | ignore | value-sent (TKL bytes) |

---

## Appendix B: RPL Configuration

### B.1. Objective Function

**MRHOF (Minimum Rank with Hysteresis Objective Function):**

```
ETX(link) = transmissions / successes
PathETX = sum(ETX(link)) for all links to root
Rank = (PathETX * 128) + MinHopRankIncrease
```

### B.2. Configuration Option Values

| Parameter | Value |
|-----------|-------|
| RPLInstanceID | 0 (default instance) |
| Mode of Operation | Non-Storing (MOP=1) |
| MinHopRankIncrease | 256 |
| MaxRankIncrease | 2048 |
| Default Lifetime | 30 minutes |
| Lifetime Unit | 60 seconds |

---

## Appendix C: CoAP Resource Directory

### C.1. Registration

```
POST coap://[6lbr]/rd?ep=node-001&lt=86400
Content-Format: application/link-format
</sensors/temp>;rt="temperature";if="sensor"
</sensors/humidity>;rt="humidity";if="sensor"
```

### C.2. Lookup

```
GET coap://[6lbr]/rd-lookup/res?rt=temperature

Response:
<coap://[node-001]/sensors/temp>;rt="temperature"
<coap://[node-042]/sensors/temp>;rt="temperature"
```

---

## Appendix D: Comparison with Existing Protocols

| Feature | LICHEN | Meshtastic | MeshCore | LoRaWAN |
|---------|--------|------------|----------|---------|
| Topology | Mesh (RPL) | Mesh (flood) | Mesh (path) | Star |
| IP Support | Full IPv6 | None | None | IPv6 (SCHC) |
| Max Hops | Unlimited* | 7 | 63 | 1 |
| Header Overhead | 6-15 bytes | 16 bytes | 6 bytes | 13 bytes |
| Authentication | Ed25519 | None/Ed25519 | HMAC | AES-CMAC |
| Encryption | OSCORE | AES-256-CTR | AES-128-ECB | AES-128 |
| Forward Secrecy | No** | No | No | No |
| Standard | IETF | Proprietary | Proprietary | LoRa Alliance |
| CoAP Support | Native | No | No | Via SCHC |
| Internet Routing | Yes | Via gateway | Via gateway | Yes |

*Limited by network diameter and duty cycle
**Can add EDHOC for session keys

---

## Appendix E: Example Network

```
                         Internet
                             |
                    +--------+--------+
                    |  Border Router  |
                    | 2001:db8::1/64  |
                    | DODAG Root      |
                    +--------+--------+
                             |
            +----------------+----------------+
            |                                 |
    +-------+-------+                 +-------+-------+
    |   Router A    |                 |   Router B    |
    | 2001:db8::a   |                 | 2001:db8::b   |
    +-------+-------+                 +-------+-------+
            |                                 |
      +-----+-----+                     +-----+-----+
      |           |                     |           |
  +---+---+   +---+---+             +---+---+   +---+---+
  | Leaf 1|   | Leaf 2|             | Leaf 3|   | Leaf 4|
  | ::101 |   | ::102 |             | ::103 |   | ::104 |
  +-------+   +-------+             +-------+   +-------+

  Leaf 1: Temperature sensor, CoAP server
  Leaf 2: Humidity sensor, CoAP server
  Leaf 3: MQTT-SN client, publishes to broker
  Leaf 4: Actuator, CoAP client
```

**Traffic flow:**

1. Leaf 1 → Border Router: CoAP response with temperature (upward via RPL)
2. Cloud → Leaf 4: CoAP request to actuator (downward via source routing)
3. Leaf 3 → MQTT Broker: MQTT-SN PUBLISH (via gateway at border router)

---

## Appendix F: SenML Sensor Profile

This appendix defines the standard SenML (RFC 8428) representation for common
sensor data in the mesh. Using SenML ensures interoperability and enables
generic data collection.

### F.1. Overview

All sensor data SHOULD be encoded as SenML over CoAP:

- Content-Format: `application/senml+cbor` (112)
- Observable resources for streaming data
- Base name derived from node identity
- Timestamps relative to base time when possible (saves bytes)

### F.2. Base Name Convention

```
urn:dev:mac:<EUI-64>:
```

Example: `urn:dev:mac:0011223344556677:`

This allows globally unique sensor identification across meshes.

### F.3. Location

Resource: `/sensors/location`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "alt", "u": "m", "v": 10.5},
  {"n": "hacc", "u": "m", "v": 5.0},
  {"n": "vacc", "u": "m", "v": 10.0},
  {"n": "speed", "u": "m/s", "v": 1.2},
  {"n": "heading", "u": "deg", "v": 45.0}
]
```

| Name | Unit | Description |
|------|------|-------------|
| lat | lat | Latitude (WGS84 degrees, + = N) |
| lon | lon | Longitude (WGS84 degrees, + = E) |
| alt | m | Altitude above sea level |
| hacc | m | Horizontal accuracy (CEP) |
| vacc | m | Vertical accuracy |
| speed | m/s | Ground speed |
| heading | deg | Heading (0 = N, 90 = E) |

Minimal location (lat/lon only): ~25 bytes CBOR.

### F.4. Battery

Resource: `/sensors/battery`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "pct", "u": "%RH", "v": 87},
  {"n": "mv", "u": "mV", "v": 3950},
  {"n": "charging", "vb": false}
]
```

| Name | Unit | Description |
|------|------|-------------|
| pct | %RH | State of charge (0-100) |
| mv | mV | Battery voltage |
| charging | (bool) | Currently charging |
| mah | mAh | Remaining capacity (optional) |

### F.5. Temperature

Resource: `/sensors/temp`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "temp", "u": "Cel", "v": 23.5}
]
```

| Name | Unit | Description |
|------|------|-------------|
| temp | Cel | Temperature in Celsius |

For Fahrenheit sources, convert to Celsius for wire format.

### F.6. Humidity

Resource: `/sensors/humidity`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "rh", "u": "%RH", "v": 65.2}
]
```

### F.7. Pressure

Resource: `/sensors/pressure`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "press", "u": "Pa", "v": 101325}
]
```

Use Pa (Pascals) as the base unit. 1 hPa = 100 Pa, 1 mbar = 100 Pa.

### F.8. Accelerometer / IMU

Resource: `/sensors/accel`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "ax", "u": "m/s2", "v": 0.05},
  {"n": "ay", "u": "m/s2", "v": -0.12},
  {"n": "az", "u": "m/s2", "v": 9.78}
]
```

Gyroscope (if present): `/sensors/gyro` with `gx`, `gy`, `gz` in `rad/s`.
Magnetometer: `/sensors/mag` with `mx`, `my`, `mz` in `T` (Tesla).

### F.9. Air Quality

Resource: `/sensors/air`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "co2", "u": "ppm", "v": 412},
  {"n": "pm25", "u": "ug/m3", "v": 12.5},
  {"n": "pm10", "u": "ug/m3", "v": 18.0},
  {"n": "voc", "u": "ppb", "v": 150}
]
```

| Name | Unit | Description |
|------|------|-------------|
| co2 | ppm | CO2 concentration |
| pm25 | ug/m3 | PM2.5 particulates |
| pm10 | ug/m3 | PM10 particulates |
| voc | ppb | Volatile organic compounds |
| aqi | (none) | Air quality index (0-500) |

### F.10. Radio Telemetry

Resource: `/sensors/radio`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "rssi", "u": "dBm", "v": -85},
  {"n": "snr", "u": "dB", "v": 7.5},
  {"n": "txpwr", "u": "dBm", "v": 20},
  {"n": "sf", "v": 9},
  {"n": "freq", "u": "MHz", "v": 906.875},
  {"n": "duty", "u": "%", "v": 2.3}
]
```

### F.11. Composite Sensor Pack

For devices with multiple sensors, a single resource MAY return all readings:

Resource: `/sensors`

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "temp", "u": "Cel", "v": 23.5},
  {"n": "rh", "u": "%RH", "v": 65.2},
  {"n": "batt/pct", "u": "%RH", "v": 87}
]
```

Use hierarchical names (e.g., `batt/pct`) for namespacing.

### F.12. Timestamps

**Base time (bt):** Absolute Unix timestamp (seconds since 1970-01-01T00:00:00Z).

**Relative time (t):** Offset from base time in seconds.

```cbor
[
  {"bn": "...", "bt": 1716742800},
  {"n": "temp", "u": "Cel", "v": 23.5, "t": 0},
  {"n": "temp", "u": "Cel", "v": 23.6, "t": 60},
  {"n": "temp", "u": "Cel", "v": 23.4, "t": 120}
]
```

This efficiently encodes time series (3 readings, shared base time).

### F.13. CoAP Integration

**Discovery:**

```
GET /.well-known/core?rt=senml

</sensors/location>;rt="senml";if="sensor";obs,
</sensors/battery>;rt="senml";if="sensor";obs,
</sensors/temp>;rt="senml";if="sensor";obs
```

**Observe for streaming:**

```
GET /sensors/location
Observe: 0

<-- 2.05 Content (initial)
<-- 2.05 Content (notification on move)
<-- 2.05 Content (notification on move)
```

**Batch retrieval:**

```
GET /sensors
Accept: application/senml+cbor

<-- 2.05 Content (all sensor readings)
```

### F.14. SCHC Compression for SenML

Common SenML fields compress well with SCHC:

| Field | Compression |
|-------|-------------|
| bn (base name) | Elide if same as L2 source |
| bt (base time) | Delta from previous |
| n (name) | Dictionary encoding |
| u (unit) | Dictionary encoding |
| v (value) | Value-sent |

A dedicated SCHC rule for SenML payloads can reduce typical sensor reports
from ~50 bytes to ~15-20 bytes.

### F.15. Resource Directory Registration

Nodes SHOULD register SenML resources with the Resource Directory:

```
POST coap://[6lbr]/rd?ep=node-0011223344556677&lt=86400
Content-Format: application/link-format

</sensors/location>;rt="senml";if="sensor";geo="*",
</sensors/temp>;rt="senml";if="sensor",
</sensors/battery>;rt="senml";if="sensor"
```

The `geo="*"` attribute indicates location-providing resources.

---

*This document is a design sketch, not a finalized specification. Implementation
will require detailed engineering of timing, buffer management, and edge cases
not covered here.*
