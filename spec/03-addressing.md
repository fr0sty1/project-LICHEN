<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. Human-readable node addresses provide short, memorable, collision-resistant identifiers bound to that key.

## 3.1. Human-Readable Node Address Format

**Format:** 13 uppercase characters from Crockford's Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no I/L/O/U), grouped `XXXX-XXXX-XXXXX`.

**Derivation (MUST be identical across all implementations; see test vectors):**

1. Ed25519 public key (32 bytes)
2. SHA-256 of pubkey (32-byte digest)
3. First 8 bytes as 64-bit IID (clear U/L bit: `iid[0] &= 0b11111101` per RFC 4291)
4. Encode 64-bit value as Crockford Base32 (13 chars, big-endian, no padding)
5. Insert dashes after characters 4 and 8

**Example:** `KCVN-MRPX-QWERT`

This binds the address to the pubkey used for link signatures and OSCORE. The IID is used for IPv6 link-local (fe80::/10) and ULA addresses. Same hash ensures cryptographic binding.

## 3.2. Collision Resistance and Usage

Collision probability is acceptable up to ~5 billion nodes (~0.5 expected collisions). On first contact, exchange full pubkey; TOFU pins the binding. Collisions resolved by context, GPS, or full key verification (DANE/PKIX optional upgrades).

Usage:
- Primary identifier in UIs, voice ("node kilo charlie..."), LCI/CoAP
- RPL announces and routing use derived IID/short address

## 3.3. Test Vectors and Integration

See `test/vectors/node_address.json` (or node-addresses.json) for canonical vectors. All Rust, C, Python implementations MUST match exactly (pubkey <-> human address <-> IID round-trip).

Cross-references: spec/04-network.md §12 (IPv6 construction), lichen_pubkey_to_iid(), human_address_from_pubkey(), updates to README.md TOC, 04-network.md, 06-security.md, 08-nodes.md.

---
[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)

(Merge conflicts from worker2 resolved into coherent normative text with test vector xrefs. CC-BY-4.0. Duplicates and notes removed.)
