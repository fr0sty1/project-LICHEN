<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. Human-readable node addresses provide short, memorable, collision-resistant identifiers bound to that key.


## 3.1. Human-Readable Node Address Format

**Format:** 13 uppercase characters from Crockford's Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no I/L/O/U), grouped with dashes as `XXXX-XXXX-XXXXX`.

**Derivation (MUST be identical across all implementations; see test vectors):**

1. Ed25519 public key (32 bytes)
2. SHA-256 of the pubkey produces a 32-byte digest.
3. Take the first 8 bytes as the 64-bit IID; clear the U/L bit per RFC 4291 (`iid[0] &= 0b11111101`).
4. Encode the 64-bit IID as Crockford Base32 (13 characters, big-endian, no padding).
5. Insert dashes after the 4th and 8th characters.

**Example:** `68T3-TNQW-65FBQ` (from test vector with zero seed)

This address is short enough to speak, type, and remember. It has acceptable collision probability up to 5B nodes (~0.5 expected collisions). It is cryptographically bound to the Ed25519 public key used for signatures, OSCORE, and IPv6 Interface Identifiers. The same IID is used for link-local (`fe80::/10`) and primary 02xx::/7 addresses (see 04-network.md). See 06-security.md for unified derivation with Yggdrasil 02xx::/7 compatibility.

On first contact, nodes exchange the full pubkey; TOFU pins the binding. Collisions (rare) are resolved by context, GNSS, or full key verification (DANE/PKIX optional).

It serves as the primary identifier in UIs, voice communication ("node kilo charlie..."), LCI/CoAP resources (`/keys`, `/status`), RPL/Announce messages (using derived IID or short address). It is compatible with OSCORE and link signatures.

## 3.2. Integration with IPv6 and RPL

The IID derived above is used as the Interface Identifier in all IPv6 addresses. Announces and routing messages use the IID or short address derived from it. See 04-network.md for full address construction details (including §6.1, §6.2, §12) and 06-security.md §8.5.

## 3.3. Test Vectors and Implementation Requirements

See `test/vectors/node_address.json` for canonical test vectors (reconciled from node-addresses.json under oxul epic). All implementations (Rust `human_address_from_pubkey`, C `lichen_pubkey_to_human_address`, Python `iid_to_human_address` / `Identity.human_address`) MUST produce identical outputs. Test vectors serve as the independent oracle for pubkey/IID/human-address round-trips.

Implementations must:
- Produce the exact `human_address` for a given `pubkey` or `seed`
- Support round-trip: human address parsing to IID must recover the original bytes (recommended)

Cross-references to this section: 04-network.md, 06-security.md, 08-nodes.md, spec/README.md and related I-Ds. Align with `human_address_from_pubkey` (Rust), `lichen_pubkey_to_human_address` (C), and `lichen_pubkey_to_iid()`.

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
