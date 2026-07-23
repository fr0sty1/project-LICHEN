<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair. Human-readable node addresses provide short, memorable, collision-resistant identifiers bound to that identity.

## 3.1. Human-Readable Node Address

**Format:** 13 uppercase characters from the Crockford Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), grouped as `XXXX-XXXX-XXXXX`.

**Normative Derivation (MUST be identical across all implementations):**

1. Input: Ed25519 public key (32 bytes)
2. Compute SHA-256 digest (32 bytes)
3. Take first 8 bytes as 64-bit value; clear the U/L bit per RFC 4291 (`iid[0] &= 0b11111101`)
4. Encode the 64-bit value as Crockford Base32 (13 characters, big-endian, no padding)
5. Insert dashes after the 4th and 8th characters

**Example output:** `KCVN-MRPX-QWERT`

This address is short enough to speak, type, and remember. It has acceptable collision probability up to 5B nodes (~0.5 expected collisions). The derivation cryptographically binds the address to the Ed25519 public key (used for signatures, OSCORE, and IPv6 IID). The same IID is used for link-local, ULA, and optional GUA addresses (see spec/04-network.md).

On first contact nodes exchange the full pubkey; TOFU pins the binding. Collisions resolved via context, GNSS, or full key verification (DANE/PKIX optional).

## Usage

- Primary identifier in UIs, voice communication, LCI/CoAP resources (/keys, /status)
- Used in RPL/Announce messages (derived IID or short address)
- Compatible with OSCORE and link signatures

## Test Vectors

See `test/vectors/node_address.json` and `test/vectors/node-addresses.json`. All implementations MUST produce identical outputs. Test vectors serve as independent oracles.

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
