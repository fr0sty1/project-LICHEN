<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

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

See `test/vectors/node_address.json` for canonical test vectors. All Rust, C, and Python implementations MUST match these vectors exactly. (Note: reconcile with node-addresses.json per oxul epic.)

## Integration with IPv6 and RPL

The IID from above is used as the Interface Identifier in all IPv6 addresses (link-local, ULA, GUA). See 04-network.md for address construction.

Announces and routing messages use the IID or short address derived from it.

## Test Vectors

See `test/vectors/node_address.json`. Implementations must:

- Produce the exact `human_address` for given `pubkey`/`seed`
- Round-trip: human -> IID parse must recover original IID bytes (optional but recommended)

Updates to 04-network.md, 06-security.md, and 08-nodes.md to reference this section. Cross-reference with `human_address_from_pubkey` in Rust and `lichen_pubkey_to_human_address` in C.

---
[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
