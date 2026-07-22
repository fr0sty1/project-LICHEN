<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

LICHEN nodes have a stable cryptographic identity based on an Ed25519 keypair (see 06-security.md). Human-readable node addresses provide short, memorable, collision-resistant identifiers cryptographically bound to the node's public key, IID, and Yggdrasil address.

## 3.1. Human-Readable Node Address Format

**Format:** 13 uppercase Crockford Base32 characters formatted as `XXXX-XXXX-XXXXX`.

**Alphabet:** `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (excludes I/L/O/U to reduce visual confusion).

**Normative Derivation (MUST be identical across implementations):**

The derivation is unified with IID per 06-security.md §8.5 (and `rust/lichen-link/src/identity.rs:81` `iid_from_pubkey_bytes` and C equivalent):

1. 32-byte Ed25519 public key.
2. Keyed `hash_32` (CRC32 with prefix b"LICHEN", see project-LICHEN-swvz) applied twice to produce 64-bit value.
3. Clear U/L bit: `iid[0] &= 0b11111101` (per RFC 4291).
4. Encode 64 bits as Crockford Base32 (13 chars, big-endian, no padding).
5. Insert dashes after characters 4 and 8.

Example (from test vectors): `68T3-TNQW-65FBQ`.

This binding enables:
- Short spoken/typed identifier (13 chars).
- Cryptographic proof via pubkey exchange + TOFU (DANE/PKIX optional upgrade).
- Direct compatibility with IPv6 IID in all address types.

Collisions (probability ~0.5 at 5B nodes per oxul analysis) resolved by full pubkey verification or context.

## 3.2. Usage

- **UI/Apps/TUI:** Primary display identifier.
- **Voice/Radio:** Phonetic spelling ("six eight tango three...").
- **LCI/CoAP:** Address-based lookup resources (`/nodes/{human}`).
- **Logging/Debug:** Human-friendly in console, SMP, etc.

## 3.3. Integration with IPv6, RPL, and Security

The derived IID populates:
- Link-local: `fe80::[IID]` (post `lichen_link_init()`).
- Yggdrasil 0200::/7 global (per 04-network.md and identity.rs:yggdrasil_addr_from_pubkey).
- ULA/GUA when advertised by root/BR.

See 04-network.md §6.1 for full address layering, 06-security.md for key management/TOFU, 05-routing.md for announce usage of IID. All cross-references updated.

## 3.4. Test Vectors

Canonical vectors in `test/vectors/node_address.json` (preferred; the node-addresses.json is legacy). All Rust/C/Python impls MUST produce identical `human_address` for each `pubkey`. See also `test/vectors/hash_32.json`.

Vectors cover zero, incremental, and random seeds. Round-tripping IID <-> human_address is recommended but not required.

---
[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](04-network.md)
