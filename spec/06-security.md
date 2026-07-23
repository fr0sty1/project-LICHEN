<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Security

## 8. Security Architecture

### 8.1. Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | OSCORE encryption (CoAP), DTLS (MQTT-SN) |
| Spoofing | Link-layer signatures (Ed25519) |
| Replay | Sequence numbers, OSCORE replay window |
| Routing attacks | Link-layer signatures REQUIRED on all RPL control frames (DIO/DAO/DIS); RPL secure mode optional |
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

Every originated frame carries a Schnorr signature for sender authentication (full spec and test vectors in draft-lichen-schnorr-00.md; security considerations cross-checked in its §6).

**Signature Scheme: Schnorr (e₁₂₈, s) -- 48 bytes**

Standard Ed25519 signatures are 64 bytes, prohibitive for LoRa. We use a
well-known Schnorr variant with 16-byte truncated challenge providing 128-bit
security (EUF-CMA per draft §6.1). Deterministic nonce (RFC 6979) REQUIRED.

**Signing (at origin):**
```
r = H(privkey || msg) mod L         // deterministic per RFC6979
R = r · B                           // B is curve basepoint
e = H(R || pubkey || msg)           // full hash
s = (r + e · privkey) mod L
signature = e[0:16] || s[0:32]      // 16+32=48 bytes
```

**Verification:**
```
e_received = signature[0:16]
s = signature[16:48]
R' = s · B - e_received · pubkey    // recover R (extended with zeros)
e' = H(R' || pubkey || msg)
valid = (e'[0:16] == e_received)
```

**Hash function:** SHA-512 (see draft-lichen-schnorr-00.md:3.2,6 for truncation, security level, nonce, limitations vs Ed25519).

### 8.4. Signed vs Relay-Mutable Fields

The LICHEN link signature is hop-by-hop. It covers the current link-layer
destination and payload as specified by the link-layer draft. A receiver MUST
verify that signature and update the authenticated peer's link replay window
before processing the payload. A forwarding node then applies permitted
mutations, creates a new link frame for the next hop, allocates its own replay
counter, and signs the complete new frame. Hop Limit changes, RFC 6554 address
swaps, source-routing-header updates, and link-address changes therefore never
occur under an unchanged link signature.

An end-to-end origin signature is a separate object. DAOs carry the DAO Origin
Signature Option defined in Routing Section 8.6. It signs a domain-separated
SHA-512 transcript containing the preserved source, effective DODAGID,
persistent 64-bit origin sequence, and exact unsigned DAO bytes. Relays MUST
preserve the source and DAO bytes; only Hop Limit and the enclosing hop-by-hop
link frame and signature may change.

**Unsigned (relay-mutable):**
| Field | Notes |
|-------|-------|
| Hop Limit / TTL | Decremented per hop |
| 6LoRH source routing headers | Inserted/consumed by relays |

**Relay-mutable fields in practice (link-layer):**
| Field | Changes each hop |
|-------|------------------|
| Link-layer destination | Yes |
| Link-layer source | Yes (to relay's address) |

The root MUST validate in this order: structural framing and active
instance/DODAG context; pinned key, IID, transcript, and origin signature;
per-key replay classification; semantic parsing; exact self `/128` Target
validation; persistence of a fresh replay floor; and atomic in-memory route mutation.
Structural failure therefore wins over replay, while a structurally and
cryptographically valid replay wins over semantic or Target-validation failure.
Missing, corrupt, or unavailable replay persistence fails closed. Signature
validity establishes provenance only; `.44.7` accepts exactly one `/128` Target
whose 16 octets equal the preserved Source Address. General prefix delegation
remains future `.44.9` work.

### 8.5. Unified Ed25519 Identity Derivation

All node identity derives from **a single Ed25519 keypair**. This unifies link-layer Schnorr-48 signatures, X25519 (for EDHOC/OSCORE per §8.9), stable IID, and primary 02xx::/7 Yggdrasil address. No separate keys or ULA. See normative steps and full key management in §8.7, `rust/lichen-link/src/identity.rs:14-48` (`iid_from_pubkey`, `yggdrasil_addr_from_pubkey`), `python/src/lichen/crypto/identity.py:116-198` (`_pubkey_to_iid`, `yggdrasil_address`), `test/vectors/yggdrasil-derivation.json`, 04-network.md:§6.2, and 03-addressing.md.

**Overview (MUST match §8.7 and test vectors exactly):**

1. 32-byte seed → Ed25519 keypair (deterministic per draft-lichen-schnorr-00).
2. IID = SHA-256(pubkey)[0:8]; `iid[0] &= 0b1111_1101` (U/L bit **cleared** per RFC 4291; previous `|=0x02` incorrect).
3. 02xx addr = `[0x02] + SHA-512(pubkey)[0:7] + IID` (lower 64 bits bind key to address; prevents substitution).
4. X25519 priv = clamp(SHA-512(seed)[0:32]) for OSCORE/EDHOC.
5. TOFU pins pubkey to derived IID/02xx (cryptographically enforced).

1. Generate Ed25519 keypair (32-byte priv, 32-byte pub)
2. hash = SHA-256(pubkey) (32 bytes, no truncation beyond IID)
3. IID = hash[0:8]; IID[0] &= 0b11111101 (U/L bit cleared per RFC 4291; see 04-network.md:6.2)
4. Yggdrasil address = 0x02 || SHA-512(pubkey)[0:7] || IID (lower 64 bits MUST match IID for cryptographic binding per 8.7; prevents substitution attacks)
5. Link pubkey = the Ed25519 pubkey
6. TOFU pins the (IID, 02xx address, PubKey) tuple (unified single-key derivation)

See normative derivation in §8.7 (MUST match test/vectors/yggdrasil-derivation.json exactly), python/src/lichen/crypto/identity.py:116, rust/lichen-link/src/identity.rs:27 and :40. Single Ed25519 keypair for signatures, OSCORE (via X25519 from seed), IID, and Yggdrasil 02xx routing. This eliminates ULA/GUA entirely (see 04-network.md). Link-local fe80::/10 reserved for control only.

This unifies all identity material from one 32-byte seed.

**Benefits:**
- Cryptographic binding across all uses (no key/address divergence)
- Single key management (self-provisioned or BR)
- Seamless Yggdrasil global routing without NAT/ULA
- Strengthened TOFU via verifiable derivation

### 8.6. Signature Caching

To reduce verification overhead:
1. **First-hop verification:** Verify signature when packet first arrives
2. **Cache result:** Mark packet as "verified from <IID>" in forwarding state
3. **Relay without re-verify:** Subsequent hops trust first-hop verification
4. **Cache keyed by:** (source IID, sequence number) with TTL

Cache entries expire after 2× expected mesh traversal time (default: 30 seconds).

**Security note:** A compromised relay could inject unverified packets. In
high-security deployments, enable per-hop verification (costs CPU, not bytes).

### 8.7. Key Management


A single 32-byte seed produces all material for signatures (Schnorr48), X25519 (for EDHOC/OSCORE), stable IID, and primary 02xx Yggdrasil address. Single key for all purposes. Supports simplified no-ULA model (fe80::IID + 02xx::/7 primary only) per 04-network.md §6.1, 05-routing.md. Matches test/vectors/yggdrasil-derivation.json exactly; see `python/src/lichen/crypto/identity.py:60` (from_seed), `rust/lichen-link/src/identity.rs:100` (Identity::from_seed).

**Normative Derivation (MUST match test vectors exactly):**

1. **Keypair**: `privkey, pubkey = derive_keypair(seed)` per draft-lichen-schnorr-00.md:97 (h=SHA-512(seed); privkey=clamp(h[0:32]); pubkey=basepoint_mult). Matches schnorr48.py:107 and Rust exactly.
2. **IID**: `hash=SHA-256(pubkey); iid=hash[0:8]; iid[0] &= 0b1111_1101` (U/L bit clear per RFC 4291). See 04-network.md:53, identity.rs:22.
3. **02xx Address**: `addr=[0x02] + SHA-512(pubkey)[0:7] + IID` (MUST: lower 64 bits == IID to bind key to address and prevent substitution attacks; upper 7 bytes from SHA-512(pubkey) for Yggdrasil 0200::/7 dispersion). No ULA. See identity.rs:40 (yggdrasil_addr_from_pubkey), test/vectors/yggdrasil-derivation.json.
 4. **X25519**: `x25519_priv=clamp(SHA-512(seed)[0:32])` per RFC 7748 §5 for EDHOC static DH (see 8.9). Matches Python identity.py:109, standards/crypto.md:79.


Self-provisioned (RECOMMENDED) or BR-provisioned nodes derive identically. TOFU pins pubkey to derived IID/02xx (cryptographic consistency per 04/05). Mismatch rejects (MITM protection).

**Design Principles:**
- No pre-shared network keys (each node has its own keypair)
- No mandatory CA infrastructure
- Trust is per-peer, not per-network
- Packet overhead must not increase for verified peers

**Bootstrap and Key Derivation:**

All nodes generate (or are provisioned) a single Ed25519 keypair at first boot. **One key for all purposes** (see 8.5):

*Self-Provisioned (default, RECOMMENDED):*
1. Device generates Ed25519 keypair at first boot
2. Derives stable IID and 02xx address from public key
3. Private key stored securely (never transmitted)

*BR-Provisioned (optional for managed fleets):*
1. Node boots in commissioning mode
2. Border router provisions keypair via secure out-of-band channel
3. Node derives IID/02xx from the provisioned key (BR does not assign IID)

**Trust Establishment (Layered):**

Implementations MUST support TOFU. DANE/PKIX optional upgrades.

| Method | Infrastructure | Trust Level | Use Case |
|--------|---------------|-------------|----------|
| TOFU | None | Pinned per-IID | Default, fully offline |
| BR-Provisioned | Border Router | Delegated | Managed deployments |
| DANE | DNSSEC + TLSA | Verified | When internet available |
| PKIX/ACME | CA | Verified | Enterprise |

**1. TOFU Baseline (updated for no-ULA unified identity)**

- On first contact (via any address), accept peer's public key and pin it to the 02xx/IID
- The key *must* match the one that derives the observed IID/02xx address
- On subsequent contacts, verify signature and key match pinned value
- Key change or IID mismatch -> reject and alert (MITM or key compromise)
- Fully offline, cryptographically bound by derivation

```
Key Store Entry:
  IID: 1234:5678:9abc:def0
  PubKey: <32 bytes>
  TrustLevel: TOFU
  FirstSeen: <timestamp>
  LastSeen: <timestamp>
```

**2. BR-Provisioned -- Optional**

For managed fleets, border router can provision keypairs. Nodes still derive IID and 02xx address from the provisioned Ed25519 public key.

**Provisioning Flow:**

1. Node boots in commissioning mode
2. Connects to BR via secure channel (USB/BLE/LCI)
3. BR generates Ed25519 keypair
4. BR transmits private key + pubkey (node derives IID/02xx/Yggdrasil addr from pubkey)
5. Node stores keypair, derives addresses, exits commissioning
6. BR records (derived IID, PubKey) in trust anchor list
7. BR distributes anchors to other nodes via CoAP

**Security Requirements:**

- Channel MUST be encrypted and authenticated
- Private key deleted from BR immediately after transfer
- Node rejects further provisioning (factory reset to reset)
- All derived addresses (02xx, IID) MUST match key

**Trust Anchor Distribution:** (unchanged, uses derived IID)

Nodes trust anchors from BR without TOFU. The derivation ensures key matches the 02xx/IID observed in traffic.

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
- An authenticated new key creates fresh per-peer replay state; counters from
  the old key MUST NOT constrain the new key
- Key change without signature -> reject, require re-verification
- Revocation: remove from local key store; no global revocation list

### 8.8. OSCORE (RFC 8613)

Object Security for Constrained RESTful Environments provides end-to-end
security for CoAP:

| Feature | OSCORE Provides |
|---------|-----------------|
| Confidentiality | AES-CCM-16-64-128 |
| Integrity | AEAD tag |
| Replay protection | Sequence number |
| Key derivation | HKDF from master secret |

**OSCORE Overhead:** 8-13 bytes (Partial IV + Tag)

### 8.9. EDHOC (RFC 9528)

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
x25519_private = clamp(SHA-512(ed25519_seed)[0:32])
x25519_public  = X25519(x25519_private, basepoint)
```
Clamping per RFC 7748 §5 is REQUIRED for security (subgroup confinement).
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
existing link-layer keypairs--no additional certificates needed.

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
| 0 | AES-CCM-16-64-128 | SHA-256 | X25519 | Ed25519 |

Suite 0 is REQUIRED for LICHEN. This matches the link-layer's use of Ed25519
(Schnorr48 signatures) and allows deriving X25519 keys from Ed25519 seeds.

**Constrained Nodes:**

EDHOC is designed for constrained devices:
- ~200 bytes total message overhead
- Can run over CoAP (reliable block-wise) or raw UDP
- One-RTT for initiator-authenticated, two-RTT for mutual auth

Nodes unable to run EDHOC MAY use pre-shared OSCORE contexts provisioned
out-of-band (see 8.7 Key Management).

### 8.10. RPL Security

RPL control messages (DIO, DAO, DIS) are protected by **link-layer signatures**
as the baseline. RPL's native secure modes are OPTIONAL for additional
defense-in-depth.

**Baseline: Link-Layer Signatures (REQUIRED)**

All RPL control messages (DIO, DAO, DIS) MUST carry valid Schnorr signatures per draft-lichen-link-01 section 4.2. Receivers MUST reject unsigned RPL frames; there is no normative permissive mode for production use (test-only). This provides:
- **Sender authentication:** DIO originates from claimed node
- **Integrity:** Message not modified in transit
- **Replay protection:** Epoch + seqnum prevents replay

This is sufficient for most deployments. Attackers cannot forge DIOs or
inject fake routing information without a valid keypair. See draft-lichen-link-01 for receiver normative behavior.

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
| Unsecured + required link/origin sigs | Default, sufficient for most deployments |
| Preinstalled + required link/origin sigs | Adversarial environments, critical infrastructure |

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
on wrap or reboot. See 02-physical-link.md:4.4 (and draft-lichen-link-01.md:5.2).

### 15.4. Known Limitations

1. **No perfect forward secrecy:** Static ECDH keys
2. **Truncated signatures:** 128-bit security (acceptable for most uses)
3. **DoS possible:** Radio jamming cannot be prevented
4. **Metadata visible:** Link-layer headers unencrypted

### 15.5. Privacy: No Address Randomization

LICHEN does not implement address randomization or IPv6 privacy extensions
(RFC 4941, RFC 7217). All IIDs and 02xx addresses are stable and
cryptographically derived from the Ed25519 public key (section 6.2 in Network Layer).

**It would break the protocol:**

- Root election uses lowest IID (pubkey-derived, section 6.1 in 04-network.md).
  Rotation would destabilize DODAG.
- Short-address assignment uses `hash_32(EUI-64 bytes, 8)` (FNV-1a32 per updated `02a-coordinated-capacity.md`; see DAD retry note+strategy in `02-physical-link.md:215` addressing hash_32(EUI-64,0) collision risk via seed mixing). Signature/replay caches keyed on stable IID.
   Rotation causes constant DAD churn and cache invalidation on LoRa.
- All security bindings (TOFU pinning, OSCORE, Schnorr signatures) rely on
  the deterministic key-to-address mapping.

**It would not provide privacy anyway:**

- Link signatures and OSCORE bind every frame to the long-term public key.
  The key (not the address) is the stable identifier.
- RF-layer traffic analysis and direction finding work regardless of IPv6 address.

Privacy is achieved via application-layer controls (position beacons, access control,
payload encryption) rather than address randomization. See 12-apps.md and routing spec.

### 15.6. Recommendations

1. Rotate keys annually or on suspected compromise
2. Use OSCORE for all CoAP traffic
3. Enable RPL secure mode in adversarial environments
4. Monitor for routing anomalies

---

[← Previous: Routing](05-routing.md) | [Index](README.md) | [Next: Transport and Application →](07-transport-app.md)
