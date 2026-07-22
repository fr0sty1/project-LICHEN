<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

<<<<<<< HEAD
LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. The human-readable node address provides a memorable, collision-resistant name for nodes.

## Human-Readable Node Address

**Format:** 13 characters from Crockford's Base32 alphabet (0123456789ABCDEFGHJKMNPQRSTVWXYZ), grouped with dashes as `XXXX-XXXX-XXXXX`.

**Derivation (MUST be identical across implementations):**

1. Ed25519 public key (32 bytes)
2. SHA-256(pubkey) → 32-byte digest
3. Take first 8 bytes as IID (clear U/L bit per RFC 4291: `iid[0] &= 0b11111101`)
4. Encode the 64-bit IID as Crockford Base32 (13 characters, big-endian, no padding)
5. Insert dashes after 4th and 8th characters

**Example:**

For a sample pubkey, the address might be `KCVN-MRPX-QWERT`.

This address is:

* Short enough to speak, type, and remember (13 chars)
* Collision probability acceptable up to 5B nodes (~0.5 expected collisions)
* Cryptographically bound to the Ed25519 pubkey used for signatures and OSCORE
* Compatible with IPv6 IID for routing (the IID is used in fe80::/10 and ULA addresses)

On first contact, nodes exchange full pubkey; TOFU pins the binding. Collisions (rare) are resolved by context, GPS, or full key verification.

See test/vectors/node_address.json for canonical test vectors. All Rust, C, and Python implementations MUST match these vectors exactly.

## Integration with IPv6 and RPL

The IID from above is used as the Interface Identifier in all IPv6 addresses (link-local, ULA, GUA). See 04-network.md for address construction.

Announces and routing messages use the IID or short address derived from it.

## Test Vectors

See `test/vectors/node_address.json`. Implementations must:

- Produce the exact `human_address` for given `pubkey`/`seed`
- Round-trip: human -> IID parse must recover original IID bytes (optional but recommended)

Updates to 04-network.md, 06-security.md, and 08-nodes.md to reference this section.
=======
Human-readable node addresses provide short, memorable identifiers bound to each node's cryptographic identity.

## 3.1. Human-Readable Node Address Format

**Format:** 13 uppercase Crockford base32 characters with dashes every 4 characters (XXXX-XXXX-XXXXX).

**Alphabet:** `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (excludes I, L, O, U for reduced visual confusion).

**Derivation:**

```
Ed25519 pubkey (32 bytes)
         |
     SHA-256 (32 bytes)
         |
    first 8 bytes (64 bits)
         |
   Crockford base32 (13 chars)
         |
   insert dashes -> "KCVN-MRPX-QWERT"
```

The same SHA-256 hash is used for IPv6 IID derivation (first 8 bytes with U/L bit cleared per RFC 4291).

This ensures the human address, IID, and public key are cryptographically bound.

## 3.2. Collision Resistance

See oxul analysis: acceptable collision probability even at 5B nodes (~0.5 expected collisions).

On collision, disambiguate via full pubkey verification on first contact (TOFU + DANE/PKIX optional).

## 3.3. Usage

- UI displays (TUI, apps): primary identifier
- Voice/radio: "node kilo charlie victor november"
- LCI and CoAP resources for lookup
- Test vectors in test/vectors/node-addresses.json MUST be matched by all implementations

## 3.4. Test Vectors

See `test/vectors/node-addresses.json` for canonical examples that Rust, C, and Python implementations must match exactly.

Cross-reference with IID in spec/04-network.md section 12 and lichen_pubkey_to_iid / human_address_from_pubkey.

Update to spec/README.md TOC and cross references in 04-network.md to point to this document for full addressing design.

---
[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
>>>>>>> origin/integration/worker2-20260722
