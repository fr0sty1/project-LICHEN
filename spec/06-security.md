<!-- Part of LICHEN Protocol Specification -->

# Security

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
| Schnorr signature (48B) | AES-128-CCM (optional)  |
+---------------------------------------------------+
```

### 8.3. Link-Layer Signatures

Every originated frame carries a Schnorr signature for sender authentication.

**Signature Scheme: Schnorr (e₁₂₈, s) — 48 bytes**

Standard Ed25519 signatures are 64 bytes, prohibitive for LoRa. We use a
well-known Schnorr variant with truncated challenge, providing 128-bit security
in 48 bytes.

**Signing (at origin):**
```
r = random scalar (or deterministic: H(privkey || msg))
R = r · B                           // B is curve basepoint
e = H(R || pubkey || msg)           // full 256-bit hash
s = r + e · privkey (mod L)         // L is curve order
signature = e[0:16] || s            // 16 + 32 = 48 bytes
```

**Verification:**
```
e_received = signature[0:16]
s = signature[16:48]
R' = s · B - e_received · pubkey    // recover R (extended with zeros)
e' = H(R' || pubkey || msg)
valid = (e'[0:16] == e_received)
```

**Hash function:** SHA-512, truncated per Ed25519 convention.

### 8.4. Signed vs Relay-Mutable Fields

Signatures cover the **immutable** portion of the packet. Relays modify
routing headers without re-signing.

**Signed (immutable):**
| Field | Notes |
|-------|-------|
| Source IPv6 address | Origin identity |
| Destination IPv6 address | Final destination |
| Payload | Application data |
| Sequence number | Replay protection |
| LLSec flags | Security parameters |

**Unsigned (relay-mutable):**
| Field | Notes |
|-------|-------|
| Hop Limit / TTL | Decremented per hop |
| 6LoRH source routing headers | Inserted/consumed by relays |
| Link-layer destination | Changes each hop |
| Link-layer source | Relay's address |

**Implication:** Relays forward packets without re-signing. The original
signature remains valid because signed fields are unchanged.

### 8.5. Signature Caching

To reduce verification overhead:

1. **First-hop verification:** Verify signature when packet first arrives
2. **Cache result:** Mark packet as "verified from <IID>" in forwarding state
3. **Relay without re-verify:** Subsequent hops trust first-hop verification
4. **Cache keyed by:** (source IID, sequence number) with TTL

Cache entries expire after 2× expected mesh traversal time (default: 30 seconds).

**Security note:** A compromised relay could inject unverified packets. In
high-security deployments, enable per-hop verification (costs CPU, not bytes).

### 8.6. Key Management

**Design Principles:**
- No pre-shared network keys (each node has its own keypair)
- No mandatory CA infrastructure
- Trust is per-peer, not per-network
- Packet overhead must not increase for verified peers

**Bootstrap:**
1. Device generates Ed25519 keypair at first boot
2. Public key bound to node identifier (EUI-64 -> IPv6 IID)
3. Private key stored securely, never transmitted

**Trust Establishment (Layered):**

Implementations MUST support TOFU. Other methods are OPTIONAL.

| Method | Infrastructure | Trust Level | Use Case |
|--------|---------------|-------------|----------|
| TOFU | None | Pinned | Default, works offline |
| DANE | DNSSEC | Verified | Internet-connected nodes |
| PKIX | CA | Verified | Enterprise deployments |

**1. TOFU (Trust On First Use) -- Baseline**

- On first contact, accept peer's public key and pin it
- Bind key to peer's IPv6 IID (derived from EUI-64)
- On subsequent contacts, verify key matches pinned value
- Key change -> reject and alert (potential MITM or hardware swap)
- Works entirely offline, no external infrastructure

```
Key Store Entry:
  IID: 1234:5678:9abc:def0
  PubKey: <32 bytes>
  TrustLevel: TOFU
  FirstSeen: <timestamp>
  LastSeen: <timestamp>
```

**2. DANE (RFC 6698) -- Optional Upgrade**

When a node has a DNS name and internet connectivity:

- Derive DNS name from IPv6 address or explicit configuration
- Query TLSA record: `_25519._mesh.<node-name>`
- Verify public key matches DNSSEC-signed record
- Upgrade trust level from TOFU to DANE-verified
- Cache result; re-verify periodically or on key change

DANE verification happens out-of-band (via border router), not over LoRa.
No additional per-packet overhead.

**3. PKIX/ACME -- Optional Upgrade**

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

**Out-of-Band Verification -- Optional**

For high-security pairing without infrastructure:

- Display public key fingerprint (e.g., QR code, hex string)
- Manual comparison or scanning
- Upgrade trust level to "Verified"

**Key Compromise and Rotation:**

- Nodes SHOULD support key rotation announcements
- Key change with valid signature from old key -> accept new key
- Key change without signature -> reject, require re-verification
- Revocation: remove from local key store; no global revocation list

### 8.7. OSCORE (RFC 8613)

Object Security for Constrained RESTful Environments provides end-to-end
security for CoAP:

| Feature | OSCORE Provides |
|---------|-----------------|
| Confidentiality | AES-CCM-16-64-128 |
| Integrity | AEAD tag |
| Replay protection | Sequence number |
| Key derivation | HKDF from master secret |

**OSCORE Overhead:** 8-13 bytes (Partial IV + Tag)

### 8.8. RPL Secure Mode

RPL defines three security modes:

| Mode | Authentication | Confidentiality |
|------|----------------|-----------------|
| Unsecured | None | None |
| Preinstalled | Shared key | Optional |
| Authenticated | Per-node keys | Optional |

Recommended: **Preinstalled mode** with network-wide key for control plane,
OSCORE for data plane.

---

## 15. Security Considerations

### 15.1. Cryptographic Strength

| Primitive | Security Level | Notes |
|-----------|----------------|-------|
| Schnorr (e₁₂₈, s) | 128 bits | 48-byte signatures |
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

[← Previous: Routing](05-routing.md) | [Index](README.md) | [Next: Transport and Application →](07-transport-app.md)
