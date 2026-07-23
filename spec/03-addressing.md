<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

<<<<<<< HEAD
LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. The human-readable node address provides a memorable, collision-resistant name for nodes.
=======
LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. Human-readable node addresses provide short, memorable, collision-resistant identifiers bound to that identity.
>>>>>>> origin/worktree-worker23

## 3.1. Human-Readable Node Address

**Format:** 13 uppercase characters from the Crockford Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), grouped as `XXXX-XXXX-XXXXX`.

**Normative Derivation (MUST be identical across all implementations):**

1. Input: Ed25519 public key (32 bytes)
2. Compute SHA-256 digest (32 bytes)
3. Take first 8 bytes as 64-bit value; clear the U/L bit per RFC 4291 (`iid[0] &= 0b11111101`)
4. Encode the 64-bit value as Crockford Base32 (13 characters, big-endian, no padding)
5. Insert dashes after the 4th and 8th characters

**Example output:** `KCVN-MRPX-QWERT`

<<<<<<< HEAD
`KCVN-MRPX-QWERT`

This address is short enough to speak, type, and remember. It has acceptable collision probability up to 5B nodes (~0.5 expected collisions), is cryptographically bound to the Ed25519 pubkey (used for signatures, OSCORE, and IPv6 IID), and compatible with IPv6 addressing.

On first contact, nodes exchange the full pubkey; TOFU pins the binding. Collisions are resolved via context, GPS, or full key verification (DANE/PKIX optional).

The derivation is used for both human-readable address and IPv6 IID (see spec/04-network.md).

## Test Vectors

See `test/vectors/node_address.json` and `test/vectors/node-addresses.json`. All implementations MUST match the canonical vectors exactly. Functions like `lichen_pubkey_to_iid` and human address derivation must be consistent across Rust, C, and Python.

Cross-references updated in 04-network.md, 06-security.md, 08-nodes.md, spec/README.md, and related drafts. Updates to referencing sections completed per multi-worker merge.

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
=======
This binding ensures the address, IPv6 IID, and public key are cryptographically linked. The same IID is used for IPv6 link-local (`fe80::/10`), ULA, and GUA addresses (see 04-network.md). On first contact, full pubkey is exchanged; TOFU pins the binding. Rare collisions are resolved by full key verification, context, or GNSS.

## 3.2. Usage and Integration

- Primary identifier in UIs, voice ("kilo charlie victor november"), LCI/CoAP resources (/keys, /status)
- RPL/Announce messages use derived IID or short address
- Compatible with OSCORE and link signatures

## 3.3. Test Vectors and Oracles

See `test/vectors/node_address.json` (and node-addresses.json) for canonical test vectors. All implementations (Rust, C, Python, Zephyr) MUST produce identical outputs for given pubkey/seed inputs. Vectors serve as independent oracles; round-trip (human address <-> IID) validation is required where applicable. Cross-references updated in 04-network.md, 06-security.md, draft-lichen-rpl-lora-00.md, and spec/README.md.

---
[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)

>>>>>>> origin/worktree-worker23
