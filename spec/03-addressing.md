<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 3. Addressing

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
