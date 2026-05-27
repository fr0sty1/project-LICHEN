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

[← Previous: Routing](05-routing.md) | [Index](README.md) | [Next: Transport and Application →](07-transport-app.md)
