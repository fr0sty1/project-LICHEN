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

All node identity derives from **a single Ed25519 keypair**. This unifies link-layer Schnorr-48 signatures, X25519 (for EDHOC/OSCORE per §8.9), stable IID, and primary 0200::/8 native address. No separate keys or ULA. See normative steps and full key management in §8.7, `rust/lichen-link/src/identity.rs:14-48` (`iid_from_pubkey`, `yggdrasil_addr_from_pubkey`), `python/src/lichen/crypto/identity.py:116-198` (`_pubkey_to_iid`, `yggdrasil_address`), `test/vectors/yggdrasil-derivation.json`, 04-network.md:§6.2, and 03-addressing.md.

**Overview (MUST match §8.7 and test vectors exactly):**

1. 32-byte seed → Ed25519 keypair (deterministic per draft-lichen-schnorr-00).
2. IID = SHA-512(pubkey)[0:8]; `iid[0] &= 0b1111_1101` (U/L bit **cleared** per RFC 4291; previous `|=0x02` incorrect). **MUST be SHA-512, not SHA-256**. The native address profile fixes the first address byte to `0x02` (0200::/8).
3. 02xx addr = `[0x02] + SHA-512(pubkey)[0:7] + IID` (lower 64 bits bind key to address; prevents substitution).
4. X25519 priv = clamp(SHA-512(seed)[0:32]) for OSCORE/EDHOC.
5. TOFU pins pubkey to derived IID/02xx (cryptographically enforced).

Link-local `fe80::/10` is for control only. The key-derived 0200::/8 primary address is for all routable traffic. Global Yggdrasil participation, when enabled, is a separate identity-preserving profile. See test vectors for exact byte/bit positions and oracles. This binds signatures, OSCORE, and addressing into one key, eliminating mismatch attacks.

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


A single 32-byte seed produces all material for signatures (Schnorr48), X25519 (for EDHOC/OSCORE), stable IID, and the primary 0200::/8 native address. Single key for all purposes. Supports the simplified no-ULA model (fe80::IID + 0200::/8 primary only) per 04-network.md §6.1 and 05-routing.md. Matches test/vectors/yggdrasil-derivation.json exactly; see `python/src/lichen/crypto/identity.py:60` (from_seed), `rust/lichen-link/src/identity.rs:100` (Identity::from_seed).

**Normative Derivation (MUST match test vectors exactly):**

1. **Keypair**: `privkey, pubkey = derive_keypair(seed)` per draft-lichen-schnorr-00.md:97 (h=SHA-512(seed); privkey=clamp(h[0:32]); pubkey=basepoint_mult). Matches schnorr48.py:107 and Rust exactly.
2. **IID**: `hash=SHA-512(pubkey); iid=hash[0:8]; iid[0] &= 0b1111_1101` (U/L bit clear per RFC 4291). **MUST be SHA-512** — Yggdrasil `AddrForKey` compatibility. See 04-network.md:53, identity.rs:22.
3. **0200::/8 Address**: `addr=[0x02] + SHA-512(pubkey)[0:7] + IID` (MUST: lower 64 bits == IID to bind key to address and prevent substitution attacks; bytes 1 through 7 are from SHA-512(pubkey)). No ULA. See identity.rs:40 (yggdrasil_addr_from_pubkey), test/vectors/yggdrasil-derivation.json.
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
- A rotation signature is made by the old key over the exact transcript:

  ```
  "LICHEN-KEY-ROTATION-v1" || 0x00 || old_pubkey(32) ||
  old_key_derived_iid(8) || new_pubkey(32) || rotation_sequence(8, network byte order)
  ```

  The rotation sequence is strictly increasing, starts above zero, and never
  wraps. A signature from another protocol domain or over a different old IID,
  key, or sequence MUST be rejected.
- Key change with a valid domain-separated signature from the old key -> accept new key
- An authenticated new key creates fresh per-peer replay state; counters from
  the old key MUST NOT constrain the new key
- Key change without signature -> reject, require re-verification
- Revocation: remove from local key store; no global revocation list

Persisted trust entries MUST be treated as untrusted serialized input on every
load. Implementations MUST enforce an exact versioned schema and bounds,
recompute the IID and primary 0200::/8 address from each public key, reject
non-finite timestamps and invalid enums or counters, and expose immutable
detached entries to callers. Trust and private-key stores MUST use owned private
directories, non-following regular-file opens, interprocess locks, unique
mode-0600 temporary files, atomic replacement, and file plus directory `fsync`.
Concurrent writers MUST use an exact revision comparison and fail rather than
silently overwrite a newer trust state. Key generations and rotation sequences
MUST fail closed at their integer maximum instead of wrapping.

#### 8.7.4. Key Rotation Attestation

Key rotation announcements use COSE_Sign1 to provide a verifiable attestation
that a new public key is the legitimate successor to an old key. The OLD key
signs the attestation, proving continuity of identity across the rotation.

**Threat Model:**

Without cryptographic attestation, an attacker could claim to be a rotated
identity of a legitimate node. The old-key signature proves the rotation was
authorized by the holder of the previous private key.

**COSE_Sign1 Structure:**

```
COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<old-iid>'},      ; unprotected: {kid: old key's 8-byte IID}
  h'<payload>',           ; see Payload below
  h'<48-byte signature>'  ; Schnorr48 signature (by OLD key)
]
```

The signature is computed using the OLD private key, attesting to the validity
of the NEW public key.

**Payload Structure (CBOR map):**

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 1 | old_pubkey | bstr(32) | Ed25519 public key being retired |
| 2 | new_pubkey | bstr(32) | Ed25519 public key being activated |
| 3 | rotation_seq | uint | Monotonic sequence, strictly increasing |
| 4 | expiry | uint | Unix timestamp when attestation expires |

```cbor
{
  1: h'<32 bytes>',       ; old_pubkey
  2: h'<32 bytes>',       ; new_pubkey
  3: <uint>,              ; rotation_seq
  4: <unix timestamp>     ; expiry
}
```

Integer keys minimize payload size. The payload is the serialized CBOR map.

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for COSE_Sign1:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(old_privkey, SHA256(CBOR(Sig_structure)))
```

The OLD Ed25519 private key signs the canonical CBOR encoding of Sig_structure.

**Receiver Validation:**

On receiving a key rotation attestation:

1. Decode COSE_Sign1 structure
2. Extract `kid` from unprotected header; this identifies the old key's IID
3. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
4. Lookup old pubkey from trust store using `kid`
5. Verify `old_pubkey` in payload matches the stored pubkey for this IID
6. Reconstruct Sig_structure per RFC 9052 and verify signature using old pubkey
7. Verify `expiry` > now
8. Verify `rotation_seq` > cached rotation_seq for this IID, or no cached entry
9. Derive new IID from `new_pubkey` per section 8.7
10. Update trust store: pin `new_pubkey` to the new IID, preserve rotation_seq
11. Clear per-key replay state; the new key starts with fresh counters

On validation failure, reject the rotation and retain the existing trust entry.

**Rotation Sequence Persistence:**

| Requirement | Behavior |
|-------------|----------|
| Storage | rotation_seq MUST be persisted to non-volatile storage |
| Increment | rotation_seq MUST increment on each rotation |
| Initial value | First rotation MUST use rotation_seq > 0 |
| Maximum | At UINT64_MAX, rotation MUST fail closed (no wrap) |
| Missing storage | If persistence unavailable, rotation MUST fail |

Implementations MUST NOT accept a rotation with rotation_seq <= cached value.
A node that has exhausted its rotation_seq space cannot rotate keys; it must
be decommissioned and re-provisioned with a fresh identity.

**Delivery Mechanisms:**

Rotation attestations MAY be delivered via:
- CoAP POST to `/.well-known/key-rotation` (OSCORE-protected)
- Piggyback on DIO/DAO with attestation option (for mesh-wide propagation)
- Out-of-band provisioning channel

The delivery mechanism is deployment-specific. Regardless of mechanism, the
attestation MUST be verified before updating trust state.

**Security Considerations:**

| Consideration | Behavior |
|--------------|----------|
| Old key compromise | Attacker can forge rotation; use expiry + monitoring |
| Replay | rotation_seq prevents replay of old attestations |
| Downgrade | Cannot rotate back to old key (seq must increase) |
| Clock skew | Expiry validation requires reasonable time sync |
| Trust continuity | New IID is cryptographically derived; cannot be spoofed |

**Interaction with TOFU:**

For TOFU-pinned peers, a valid rotation attestation is the ONLY way to change
the pinned key. Key changes without attestation MUST be rejected and logged
as potential MITM attempts.

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

#### 8.10.1. Root DIO Signature

Root DIOs MAY carry an additional COSE_Sign1 signature as optional
defense-in-depth over the link-layer baseline. This provides cryptographic
proof that a DIO originates from the current DODAG root, not merely a node
that received and forwarded it.

**Threat Model:**

Link-layer signatures prove "who forwarded this DIO" but not "who originated
it." A compromised relay could modify rank, version, or MoP fields before
re-signing at the link layer. The Root DIO Signature binds these fields to
the root's Ed25519 key.

**COSE_Sign1 Structure:**

```
COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<root-iid>'},     ; unprotected: {kid: root 8-byte IID}
  h'<payload>',           ; see Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

The signature is carried in an RPL DIO Option (type TBD) appended to the DIO.

**Payload Structure (CBOR map):**

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 1 | dodag_id | bstr(16) | DODAGID (128-bit IPv6 address) |
| 2 | instance | uint | RPLInstanceID |
| 3 | version | uint | DODAGVersionNumber |
| 4 | rank | uint | Root rank (normally 256 / ROOT_RANK) |
| 5 | expiry | uint | Unix timestamp when signature expires |
| 6 | root_seq | uint | Monotonic sequence, increments each DIO |
| 7 | mop | uint | Mode of Operation (0-7) |

```cbor
{
  1: h'<16 bytes>',       ; dodag_id
  2: <uint>,              ; instance
  3: <uint>,              ; version
  4: <uint>,              ; rank
  5: <unix timestamp>,    ; expiry
  6: <uint>,              ; root_seq
  7: <uint>               ; mop
}
```

Integer keys minimize payload size. The payload is the serialized CBOR map.

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for COSE_Sign1:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(root_privkey, SHA256(CBOR(Sig_structure)))
```

Root's Ed25519 private key signs the canonical CBOR encoding of Sig_structure.

**Receiver Validation:**

On receiving a DIO with Root Signature Option:

1. Extract `kid` from unprotected header; verify matches DIO source address IID
2. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
3. Lookup root pubkey from trust store (TOFU or provisioned)
4. Reconstruct Sig_structure per RFC 9052 and verify signature
5. Decode payload; verify `dodag_id`, `instance`, `version`, `rank`, `mop` match DIO fields
6. Verify `expiry` > now
7. Verify `root_seq` > cached root_seq for this DODAG, or no cached entry
8. Cache root_seq keyed by (dodag_id, instance)
9. Mark DIO as "root-authenticated"

**Graceful Degradation:**

If root pubkey is not cached (e.g., fresh node joining mesh):

1. Accept DIO with link-layer signature only (baseline security)
2. Cache root IID from DIO for later TOFU pinning
3. Once root pubkey is learned (via EDHOC or first authenticated DIO), validate subsequent DIOs

Nodes MUST NOT reject DIOs solely due to missing root signature validation
capability. The signature is defense-in-depth, not a hard requirement.

**Security Notes:**

| Consideration | Behavior |
|--------------|----------|
| Root re-election | Clear cached root_seq; new root starts fresh |
| root_seq wrap | MUST NOT wrap; uint64 provides ~500 years at 1/sec |
| Signature absence | Fall back to link-layer baseline (still secure) |
| Expired signature | Treat as unsigned; accept with link-layer auth only |

**When to Include:**

Root SHOULD include the signature option when:
- Operating in adversarial environments (CONFIG_LICHEN_RPL_ROOT_SIG=y)
- Mesh spans untrusted relay infrastructure
- Defense-in-depth is required by deployment policy

Root MAY omit the signature in trusted single-hop or small mesh deployments
where link-layer signatures provide sufficient security.

### 8.11. Tunnel Authorization (Egress Binding)

When a source-routed tunnel terminates at an egress node (border router),
the egress MUST verify the tunnel was authorized by the current DODAG root
before decapsulating and forwarding to external networks.

**Threat Model:**

Without authorization, any authenticated mesh node could craft source-routed
packets using the egress as unauthorized transit to external destinations.

**COSE Algorithm Registration:**

LICHEN uses Schnorr48 signatures (truncated Schnorr over Ed25519). This is
registered as a private-use COSE algorithm:

| Name | Value | Description |
|------|-------|-------------|
| Schnorr48-Ed25519 | -65537 | Schnorr signature, Ed25519 curve, 48-byte output |

This algorithm ID is used in COSE_Sign1 protected headers throughout LICHEN.

**Authorization Delivery:**

Root delivers tunnel authorization via CoAP as a COSE_Sign1 structure:

```
POST coap://[egress]/.well-known/tunnel-auth
Content-Format: application/cose; cose-type="cose-sign1" (TBD)
OSCORE: <root-egress pairwise context>

COSE_Sign1 = [
  h'a1013a00010000',      ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<root-iid>'},     ; unprotected: {kid: root 8-byte IID}
  h'<payload>',           ; see Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

Message is OSCORE-protected using the pairwise context between root and
egress (established via EDHOC). Delivery uses standard source-routing.

**Payload Structure (CBOR map):**

```cbor
{
  1: h'<prefix bytes>',   ; target: prefix_len/8 bytes, zero-padded
  2: <0-128>,             ; prefix_len: uint
  3: h'<16 bytes>',       ; route_hash: see Route Hash Computation
  4: <uint>,              ; path_seq: from triggering DAO
  5: <unix timestamp>,    ; expiry: uint
  6: h'<8-byte IID>'      ; egress_iid: binds authorization to this egress
}
```

Integer keys minimize payload size. The payload is the serialized CBOR map.

**Route Hash Computation:**

```
route_bytes = concat(hop[0].iid, hop[1].iid, ..., hop[n].iid)
route_hash  = SHA-256(route_bytes)[0:16]
```

Each `hop[i].iid` is the 8-byte IID from the transit node's address, in
source-route order (first hop to last hop / egress). This matches the
order in the IPv6 Source-Route Header.

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for COSE_Sign1:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(root_privkey, SHA256(CBOR(Sig_structure)))
```

Root's Ed25519 private key signs the canonical CBOR encoding of Sig_structure.

**Egress Validation:**

On receiving tunnel-auth POST:

1. Verify OSCORE protection (authenticates root as sender)
2. Decode COSE_Sign1 structure
3. Extract `kid` from unprotected header; verify matches current DODAG root IID (from DIO)
4. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
5. Reconstruct Sig_structure per RFC 9052 and verify signature using root pubkey
6. Decode payload; verify `egress_iid` matches own IID
7. Verify `expiry` > now
8. Verify `path_seq` > cached path_seq for this (target, route_hash), or no cached entry
9. Cache authorization keyed by (target_prefix, route_hash)
10. Respond 2.04 Changed

On validation failure, respond 4.03 Forbidden and do not cache.

On receiving source-routed data packet for decapsulation:

1. Compute route_hash from Source-Route Header
2. Lookup (inner_src.prefix, route_hash) in authorization table
3. If missing or expired: drop, log "unauthorized tunnel"
4. If valid: decapsulate and forward

**Authorization Table:**

Implementations MUST bound the authorization table. Recommended: 256 entries
with LRU eviction. Exceeding capacity evicts least-recently-used entry.

**Trigger Conditions:**

Root SHOULD send tunnel-auth when:
- A new route via an egress is installed (DAO received)
- An existing route's path changes
- Approaching expiry of a valid route (refresh)

Root SHOULD NOT send tunnel-auth for routes that do not traverse an egress.
Egress capability MAY be signaled via DAO option or out-of-band configuration;
the mechanism is implementation-defined in this version.

**Refresh and Expiry:**

| Event | Behavior |
|-------|----------|
| Route unchanged, nearing expiry | Root re-sends with fresh expiry |
| Route changes | Root sends new authorization with new route_hash |
| Node leaves mesh | Authorization expires naturally (no explicit revoke) |
| Root re-election | All authorizations invalid; rebuild with mesh reconvergence |

**Root Re-election:**

When DODAG root changes, all cached authorizations become invalid (signed by
old root). Egress MUST clear the authorization table on detecting a new root
identity in DIO. Tunnel authorization rebuilds as part of normal mesh
reconvergence--new root receives DAOs and issues new authorizations. No grace
period; the security boundary is the current root's signature.

**Interaction with Trust Boundaries:**

Consistent with section 18.8.2 Trust Boundaries (12-apps.md) and section 15.3
OSCORE Replay Window, tunnel authorization is mesh-lifetime state. Egress
restart clears the authorization table; authorizations rebuild via CoAP as
routes re-establish.

**COSE in LICHEN:**

Tunnel authorization establishes COSE_Sign1 (RFC 9052) as the standard format
for signed control messages in LICHEN. Benefits:

- Standardized envelope with algorithm and key ID in headers
- Interoperable with COSE libraries (no custom parsing)
- Consistent with OSCORE/EDHOC CBOR ecosystem
- Extensible (additional headers, algorithms) without format changes

Future signed control messages (e.g., capability announcements, delegation
tokens) SHOULD use COSE_Sign1 with the Schnorr48-Ed25519 algorithm (-65537)
unless a different algorithm is explicitly required.

### 8.12. Capability Announcements

Mesh nodes announce their capabilities to the DODAG root via COSE_Sign1 signed
messages. The root uses these announcements to determine which nodes can serve
as egress points or delegate prefixes, enabling tunnel-auth (8.11) authorization.

**Relationship to Tunnel Authorization:**

Capability announcements flow node-to-root; tunnel authorizations flow root-to-egress.
A node first announces its capabilities; the root then authorizes tunnels through
nodes that announced egress capability.

```
Node (announces)  -->  Root (authorizes)  -->  Egress (validates)
     [8.12]                                        [8.11]
```

**Capability Bits:**

| Bit | Name | Description |
|-----|------|-------------|
| 0 | egress | Node can decapsulate and forward to external networks |
| 1 | prefix-delegation | Node can delegate prefixes to downstream nodes |
| 2-7 | reserved | Reserved for future use; MUST be zero |

**Announcement Delivery:**

Nodes deliver capability announcements via CoAP as a COSE_Sign1 structure:

```
POST coap://[root]/.well-known/capability-announce
Content-Format: application/cose; cose-type="cose-sign1" (TBD)
OSCORE: <announcer-root pairwise context>

COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<announcer-iid>'}, ; unprotected: {kid: announcer 8-byte IID}
  h'<payload>',           ; see Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

Message is OSCORE-protected using the pairwise context between announcer and
root (established via EDHOC).

**Payload Structure (CBOR map):**

```cbor
{
  1: <uint>,              ; capabilities: bitmask (see Capability Bits)
  2: h'<prefix bytes>',   ; prefix: prefix_len/8 bytes, zero-padded
  3: <0-128>,             ; prefix_len: uint
  4: <unix timestamp>,    ; expiry: uint
  5: <uint>,              ; seq: monotonically increasing sequence number
  6: h'<8-byte IID>'      ; announcer_iid: binds announcement to this node
}
```

| Key | Field | Type | Description |
|-----|-------|------|-------------|
| 1 | capabilities | uint | Bitmask of announced capabilities |
| 2 | prefix | bytes | Prefix this announcement applies to |
| 3 | prefix_len | uint | Prefix length in bits (0-128) |
| 4 | expiry | uint | Unix timestamp when announcement expires |
| 5 | seq | uint | Sequence number for replay protection |
| 6 | announcer_iid | bytes | 8-byte IID of the announcing node |

Integer keys minimize payload size. The payload is the serialized CBOR map.

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for COSE_Sign1:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(announcer_privkey, SHA256(CBOR(Sig_structure)))
```

Announcer's Ed25519 private key signs the canonical CBOR encoding of Sig_structure.

**Root Validation:**

On receiving capability-announce POST:

1. Verify OSCORE protection (authenticates announcer as sender)
2. Decode COSE_Sign1 structure
3. Extract `kid` from unprotected header; verify it matches the OSCORE sender ID
4. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
5. Reconstruct Sig_structure per RFC 9052 and verify signature using announcer pubkey
6. Decode payload; verify `announcer_iid` matches `kid` from unprotected header
7. Verify `expiry` > now
8. Verify `seq` > cached seq for this announcer_iid, or no cached entry
9. Verify reserved capability bits (2-7) are zero
10. Cache announcement keyed by announcer_iid
11. Respond 2.04 Changed

On validation failure, respond 4.03 Forbidden and do not cache.

**Capability Table:**

Root maintains a capability table mapping announcer IIDs to their capabilities:

| Field | Description |
|-------|-------------|
| announcer_iid | 8-byte IID of the capable node |
| capabilities | Bitmask of announced capabilities |
| prefix | Associated prefix (for prefix-delegation) |
| prefix_len | Length of associated prefix |
| expiry | When this capability expires |
| seq | Last accepted sequence number |

Implementations MUST bound the capability table. Recommended: 256 entries
with LRU eviction. Exceeding capacity evicts least-recently-used entry.

**Trigger Conditions:**

Nodes SHOULD send capability announcements when:
- Joining the mesh (after EDHOC with root completes)
- Capabilities change (e.g., gaining or losing external connectivity)
- Approaching expiry of previous announcement (refresh)
- After root re-election (new root needs announcements)

**Interaction with Tunnel Authorization:**

When root receives a DAO indicating a route through a node:

1. Check capability table for that node's IID
2. If node has egress capability (bit 0 set) and prefix matches:
   - Send tunnel-auth (8.11) to authorize the tunnel
3. If node lacks egress capability:
   - Do not send tunnel-auth; route is internal-only

**Root Re-election:**

When DODAG root changes, capability announcements to the old root are invalid.
Nodes MUST re-announce capabilities to the new root after detecting root change
in DIO. The new root builds its capability table from fresh announcements.

**Security Considerations:**

- Announcements are signed by the announcing node, preventing spoofing
- OSCORE provides confidentiality (capabilities not visible to relays)
- Sequence numbers prevent replay of stale announcements
- Expiry ensures stale capabilities do not persist indefinitely
- Root validates announcer_iid matches the cryptographic identity

### 8.13. Node Credentials

Nodes MAY hold signed credentials asserting facts about the node. Credentials
are issued by authorities (CAs, gateways, fleet operators) and presented to
verifiers when needed.

**COSE_Sign1 Structure:**

```
COSE_Sign1 = [
  h'a10139ffff',              ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {
    4: h'<issuer-iid>',       ; kid: issuer 8-byte IID
    33: [<x509-chain>]        ; x5chain: optional cert chain (RFC 9360)
  },
  h'<payload>',               ; see Payload below
  h'<48-byte signature>'
]
```

**Payload (CBOR map):**

```cbor
{
  1: h'<subject-iid>',        ; who this credential is about
  2: "<claim-type>",          ; namespaced claim identifier
  3: <claim-value>,           ; any CBOR type
  4: <expiry>,                ; unix timestamp
  5: <seq>                    ; for revocation/supersede
}
```

**Claim Namespaces:**

| Prefix | Registry | Examples |
|--------|----------|----------|
| `lichen:` | This spec | `lichen:fleet`, `lichen:egress`, `lichen:relay` |
| `oidc:` | OIDC Core §5.1 | `oidc:name`, `oidc:email`, `oidc:phone_number` |
| `vcard:` | RFC 6350 | `vcard:tel`, `vcard:org`, `vcard:geo` |
| `jwt:` | IANA JWT Claims | `jwt:iss`, `jwt:aud` |
| URI | Custom | `https://example.com/claims/employee_id` |

**LICHEN-Defined Claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `lichen:fleet` | tstr | Fleet membership identifier |
| `lichen:gateway_access` | [bstr] | Array of authorized gateway IIDs |
| `lichen:egress` | bool | Permitted to route externally |
| `lichen:relay` | bool | Permitted to relay others' traffic |
| `lichen:emergency` | bool | Gateway relays to emergency services |
| `lichen:emergency_callback` | tstr | Verified callback for PSAP |
| `lichen:role` | tstr | ICS/operational role |

**Trust Anchors:**

Verifiers maintain a list of trusted issuer public keys. Trust MAY be
established via:
- TOFU (first-use pinning)
- Pre-configured trust anchors
- X.509 chain to trusted root CA
- Out-of-band verification

**Default CA:**

LICHEN provides an optional public CA service for credential issuance.
Deployments MAY use the default CA, self-operate a CA, or use any PKI.
Trust anchor configuration is implementation-defined.

**Verification:**

1. Decode COSE_Sign1; verify algorithm is -65537
2. If x5chain present: validate chain to trust anchor
3. Else: lookup issuer pubkey by kid in trust store
4. Verify signature per RFC 9052
5. Verify subject-iid matches presenting node
6. Verify expiry > now
7. Verify seq > cached seq (if superseding prior credential)

**Revocation:**

Credentials are superseded by issuing a new credential with higher seq.
No explicit revocation message. Short expiry (7-30 days) limits exposure.
Gateways MAY cache and distribute CRLs; mechanism is out of scope.

**Presentation:**

Nodes present credentials when requested or when accessing protected
resources. Presentation protocol is application-defined; typical pattern:

```
GET coap://[gateway]/.well-known/auth
  -> 4.01 Unauthorized, "credential required: lichen:fleet"

POST coap://[gateway]/.well-known/auth
Content-Format: application/cose
{credential COSE_Sign1}
  -> 2.04 Changed (credential cached for session)
```

#### 8.13.1. Local Facts (Gateway-Issued)

Gateways issue local facts for nodes in their mesh. No PKI required; trust is
implicit (node trusts its gateway). Facts are valid within the mesh or
federation that recognizes the issuing gateway.

**Issuance:**

```
POST coap://[gateway]/.well-known/local-fact
OSCORE: <node-gateway context>
{"request": "relay"}

Response: 2.01 Created
Content-Format: application/cose
{COSE_Sign1 with lichen:relay=true}
```

Gateway decides policy (who gets what facts) out of band.

**Local Fact Claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `lichen:emergency` | bool | Gateway will relay to emergency services |
| `lichen:emergency_callback` | tstr | Verified callback number for PSAP |
| `lichen:relay` | bool | May relay others' traffic |
| `lichen:priority` | uint | Traffic priority (0=low, 3=emergency) |
| `lichen:channel` | [tstr] | Authorized channel/group IDs |
| `lichen:quota` | uint | Monthly bytes (0=unlimited) |
| `lichen:sponsored` | tstr | "Traffic sponsored by X" |

**Emergency Services Authorization:**

The `lichen:emergency` local fact asserts the issuing gateway will route
emergency traffic to the regional emergency services (911, 112, 999, etc.).
This is a gateway capability assertion — the gateway has the PSAP/emergency
center connection and accepts responsibility for relay.

Nodes with `lichen:emergency=true` MAY display "emergency services available"
in UI. Nodes without this fact SHOULD warn users that emergency services are
unavailable via this mesh.

The optional `lichen:emergency_callback` provides a verified phone number the
emergency center can call back. Gateway verifies ownership (SMS, voice OTP)
before issuing.

**Federation Facts:**

For multi-gateway deployments, facts MAY be co-signed by multiple gateways
or issued by a federation coordinator. Verifiers accept facts signed by any
federated gateway they trust.

```cbor
; Single gateway
{4: h'<gateway-iid>'}

; Federation (multiple signers via COSE_Sign)
COSE_Sign with multiple COSE_Signature entries
```

**Validity:**

Local facts are mesh-lifetime. Gateway restart or root re-election
invalidates cached facts; nodes re-request from new gateway.

#### 8.13.2. CA Credentials (Portable)

CA credentials (section 8.13 main text) are portable across meshes. They
require PKI trust (x5chain or pre-configured anchor). Use for:

- Identity (name, email, phone)
- 911 authorization
- Fleet membership (valid at any fleet gateway)
- Organizational role

Local facts and CA credentials can coexist. A node might have:
- CA credential: `oidc:name = "Mark Atwood"` (portable identity)
- Local fact: `lichen:priority = 2` (this mesh only)

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

**OSCORE Replay Window:**

When an OSCORE Security Context is reused after a restart, its sender sequence
reservations, recipient replay window, and response replay/correlation state
MUST remain valid across that restart. Implementations MUST persist this
mutable state in a versioned, authenticated record bound to the exact Security
Context, including its algorithms, Sender ID, Recipient ID, ID Context, and
derived key/IV identity. A sender reservation MUST be committed before its
nonce can be used, and newly accepted request or response replay state MUST be
committed before plaintext or a successful result is released.

Persistent OSCORE state MUST be protected by an independent monotonic
rollback-and-deletion authority and updated atomically. Missing, corrupt, torn,
stale, rolled-back, mismatched, or unavailable state MUST fail closed. If an
endpoint cannot restore that state, it MUST NOT reuse the affected Security
Context; it MUST establish a fresh context with distinct key/nonce material
before processing further traffic. Clearing a replay window while retaining
the old context is not a re-keying event and MUST NOT make previously accepted
messages acceptable again. These requirements implement RFC 8613 Sections 7.2
and 7.5: an AEAD nonce is never reused with the same key, and recovered context
state neither reuses a prior Sender Sequence Number nor accepts a prior
message.

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
- Short-address assignment uses `crc32_ieee(EUI-64, key=0x4c494348454e)` (CRC32-IEEE with initial value derived from ASCII "LICHEN", see DAD retry strategy in `02-physical-link.md:172`). Signature/replay caches keyed on stable IID.
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
