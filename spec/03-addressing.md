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

`KCVN-MRPX-QWERT`

This address is short enough to speak, type, and remember. It has acceptable collision probability up to 5B nodes (~0.5 expected collisions), is cryptographically bound to the Ed25519 pubkey (used for signatures, OSCORE, and IPv6 IID), and compatible with IPv6 addressing.

On first contact, nodes exchange the full pubkey; TOFU pins the binding. Collisions are resolved via context, GPS, or full key verification (DANE/PKIX optional).

The derivation is used for both human-readable address and IPv6 IID (see spec/04-network.md).

## Test Vectors

See `test/vectors/node_address.json` and `test/vectors/node-addresses.json`. All implementations MUST match the canonical vectors exactly. Functions like `lichen_pubkey_to_iid` and human address derivation must be consistent across Rust, C, and Python.

Cross-references updated in 04-network.md, 06-security.md, 08-nodes.md, spec/README.md, and related drafts. Updates to referencing sections completed per multi-worker merge.

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
