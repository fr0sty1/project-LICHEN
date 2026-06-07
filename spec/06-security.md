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

*Self-Provisioned (default):*
1. Device generates Ed25519 keypair at first boot
2. Public key bound to node identifier (EUI-64 -> IPv6 IID)
3. Private key stored securely, never transmitted

*BR-Provisioned (optional):*
1. Device boots in commissioning mode (no keypair)
2. Border router provisions keypair via secure channel
3. IID may be assigned by border router (not derived from EUI-64)

See "BR-Provisioned" section below for full provisioning flow.

**Trust Establishment (Layered):**

Implementations MUST support TOFU. Other methods are OPTIONAL.

| Method | Infrastructure | Trust Level | Use Case |
|--------|---------------|-------------|----------|
| TOFU | None | Pinned | Default, works offline |
| BR-Provisioned | Border Router | Delegated | Managed fleets, enterprise |
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

**2. BR-Provisioned -- Optional**

For managed deployments, the border router MAY provision keypairs to nodes
during commissioning. This enables central control over network membership.

**Provisioning Flow:**

1. Node boots in commissioning mode (no keypair yet)
2. Node connects to border router via secure channel (USB, BLE, or LCI)
3. Border router generates Ed25519 keypair for node
4. Border router assigns IID (may differ from EUI-64)
5. Border router transmits keypair to node over secure channel
6. Node stores keypair; exits commissioning mode
7. Border router records (IID, PubKey) in its trust anchor list
8. Border router distributes trust anchor to other managed nodes

**Security Requirements:**

- Provisioning channel MUST be encrypted (TLS, DTLS, or physical isolation)
- Private key MUST be deleted from border router after successful transfer
- Node MUST NOT accept provisioning after initial setup (factory reset required)
- Border router SHOULD log all provisioning events

**Trust Anchor Distribution:**

The border router maintains an authoritative list of provisioned nodes:

```
Trust Anchor List:
  - IID: 1234:5678:9abc:def0, PubKey: <32 bytes>, Provisioned: <timestamp>
  - IID: 1234:5678:9abc:def1, PubKey: <32 bytes>, Provisioned: <timestamp>
```

Managed nodes MAY fetch this list via CoAP:

```
GET coap://[border-router]/.well-known/trust-anchors
Content-Format: application/cbor

[
  [h'12345678...', h'<pubkey>'],  ; [IID, PubKey]
  [h'12345678...', h'<pubkey>']
]
```

Nodes receiving trust anchors from the border router trust those keys
without TOFU. This enables instant mesh formation without first-contact
verification delays.

**Revocation:**

The border router can revoke a node by:

1. Removing it from the trust anchor list
2. Pushing updated list to all managed nodes
3. Optionally broadcasting a revocation message (signed by BR)

Revocation takes effect when nodes receive the updated trust anchor list.
Nodes SHOULD fetch updates periodically (e.g., every hour) or on BR announcement.

**Mixed Mode:**

A mesh MAY contain both self-provisioned (TOFU) and BR-provisioned nodes.
BR-provisioned nodes trust each other via the trust anchor list. They
interact with TOFU nodes normally (pinning on first contact). This allows
gradual migration or mixed autonomous/managed deployments.

**3. DANE (RFC 6698) -- Optional**

When a node has a DNS name and internet connectivity:

- Derive DNS name from IPv6 address or explicit configuration
- Query TLSA record: `_25519._mesh.<node-name>`
- Verify public key matches DNSSEC-signed record
- Upgrade trust level from TOFU to DANE-verified
- Cache result; re-verify periodically or on key change

DANE verification happens out-of-band (via border router), not over LoRa.
No additional per-packet overhead.

**4. PKIX/ACME -- Optional**

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

### 8.8. EDHOC (RFC 9528)

Ephemeral Diffie-Hellman Over COSE provides lightweight authenticated key
exchange for establishing OSCORE security contexts.

**Why EDHOC:**
- Ed25519 keypairs (link-layer) are for signatures, not key agreement
- OSCORE requires symmetric master secrets
- Pre-shared keys don't scale; out-of-band provisioning is fragile
- EDHOC provides authenticated key exchange in 3 messages (~200 bytes total)

**Key Agreement:**

Each node derives an X25519 keypair from its Ed25519 seed (RFC 8032 compatible):
```
x25519_private = SHA-512(ed25519_seed)[0:32]
x25519_public  = X25519(x25519_private, basepoint)
```

EDHOC uses these for ephemeral-static or ephemeral-ephemeral DH.

**Protocol Flow:**

```
Initiator                              Responder
    |                                      |
    |  --- EDHOC Message 1 (METHOD, G_X) ->|
    |                                      |
    |<-- EDHOC Message 2 (G_Y, CIPHERTEXT) |
    |                                      |
    |  --- EDHOC Message 3 (CIPHERTEXT) -->|
    |                                      |
  [OSCORE Master Secret derived]       [OSCORE Master Secret derived]
```

**Authentication:**

EDHOC Message 2 and 3 include signatures using Ed25519 (or the Schnorr
variant). The initiator and responder authenticate each other using their
existing link-layer keypairs—no additional certificates needed.

**OSCORE Context Export:**

After EDHOC completes, both parties derive:
```
OSCORE Master Secret = EDHOC-Exporter("OSCORE Master Secret", h'', 16)
OSCORE Master Salt   = EDHOC-Exporter("OSCORE Master Salt", h'', 8)
```

**When to Run EDHOC:**

- **Lazy establishment:** On first OSCORE-protected request to a peer
- **Explicit:** Via `POST coap://[peer]/.well-known/edhoc`
- **Periodic refresh:** Re-run every 24 hours or on sequence number exhaustion

**EDHOC Cipher Suite:**

| Suite | AEAD | Hash | ECDH Curve | Signature |
|-------|------|------|------------|-----------|
| 2 | AES-CCM-16-64-128 | SHA-256 | X25519 | Ed25519 |

Suite 2 is RECOMMENDED for LICHEN (matches OSCORE cipher suite).

**Constrained Nodes:**

EDHOC is designed for constrained devices:
- ~200 bytes total message overhead
- Can run over CoAP (reliable block-wise) or raw UDP
- One-RTT for initiator-authenticated, two-RTT for mutual auth

Nodes unable to run EDHOC MAY use pre-shared OSCORE contexts provisioned
out-of-band (see 8.6 Key Management).

### 8.9. RPL Security

RPL control messages (DIO, DAO, DIS) are protected by **link-layer signatures**
as the baseline. RPL's native secure modes are OPTIONAL for additional
defense-in-depth.

**Baseline: Link-Layer Signatures (REQUIRED)**

All RPL control messages are frames, and all frames carry Schnorr signatures.
This provides:
- **Sender authentication:** DIO originates from claimed node
- **Integrity:** Message not modified in transit
- **Replay protection:** Epoch + seqnum prevents replay

This is sufficient for most deployments. Attackers cannot forge DIOs or
inject fake routing information without a valid keypair.

**Limitation of link-layer signatures:**

A compromised node with valid keys CAN:
- Advertise false rank (attract then drop traffic)
- Trigger unnecessary re-convergence (battery drain)
- Inject itself as preferred parent

Link-layer signatures prove "who sent this" but not "is this routing info honest."

**Optional: RPL Preinstalled Mode (Defense-in-Depth)**

For high-security deployments, RPL preinstalled mode adds a network-wide PSK
for control plane messages. This provides:
- **Network membership proof:** Only nodes with PSK can participate in routing
- **Additional MAC:** Redundant integrity check

| Mode | When to Use |
|------|-------------|
| Unsecured + link sigs | Default, sufficient for most deployments |
| Preinstalled + link sigs | Adversarial environments, critical infrastructure |

**Configuration:**

```
CONFIG_LICHEN_RPL_SECURE_MODE=n       # Default: rely on link-layer sigs
CONFIG_LICHEN_RPL_SECURE_MODE=y       # Enable preinstalled mode
CONFIG_LICHEN_RPL_PSK="<32-byte-hex>" # Network-wide key (if enabled)
```

**Note on "No PSK" Principle:**

The design principle "no pre-shared network keys" applies to the **data plane**.
An optional control plane PSK for RPL is an acceptable tradeoff:
- Does not affect per-peer trust model
- Does not encrypt user data
- Is not required for operation
- Adds defense-in-depth where needed

Authenticated mode (per-node keys + KDC) is NOT recommended due to
infrastructure complexity.

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
| Link | 8-bit epoch + 16-bit SeqNum (24-bit logical counter) |
| OSCORE | Partial IV / Sequence Number |
| RPL | Link-layer seqnum (baseline), secure mode counters (optional) |

**Link-Layer Replay Window:**

Receivers track per-sender (epoch, seqnum) state with a 32-entry sliding
window for out-of-order tolerance. Epoch persisted to flash; increments
on wrap or reboot. See section 4.4 in Physical and Link Layers.

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
