# Cryptographic Standards

Cryptographic primitives and standards used in LICHEN.

## NIST Standards

| Document | Title | LICHEN Use |
|----------|-------|------------|
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | Secure Hash Standard | SHA-256, SHA-512 |
| [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) | AES | AES-128 encryption |
| [SP 800-38C](https://csrc.nist.gov/publications/detail/sp/800-38c/final) | CCM Mode | AES-CCM authenticated encryption |
| [SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) | Key Establishment | ECDH key agreement |

## IRTF CFRG

Crypto Forum Research Group specifications:

| Document | Title | LICHEN Use |
|----------|-------|------------|
| [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) | X25519/X448 | ECDH key exchange |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | EdDSA (Ed25519/Ed448) | Digital signatures |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HKDF | Key derivation |

## Algorithm Summary

### Signatures

| Algorithm | Key Size | Sig Size | Security | Use |
|-----------|----------|----------|----------|-----|
| Ed25519 | 32B pub | 64B | 128-bit | Standard EdDSA |
| Schnorr-48 | 32B pub | 48B | 128-bit | Link layer (LICHEN) |

**Schnorr-48** is a LICHEN-specific variant:
- Same curve as Ed25519 (Curve25519)
- Truncated challenge: 16 bytes (vs 32)
- Format: `e[0:16] || s` = 48 bytes
- 25% smaller than Ed25519, same security level

### Encryption

| Algorithm | Key | Nonce | Tag | Use |
|-----------|-----|-------|-----|-----|
| AES-128-CCM | 16B | 13B | 8B | Link layer (optional) |
| AES-CCM-16-64-128 | 16B | 13B | 8B | OSCORE default |

### Key Exchange

| Algorithm | Public | Shared | Use |
|-----------|--------|--------|-----|
| X25519 | 32B | 32B | EDHOC, OSCORE |

### Hashing

| Algorithm | Output | Use |
|-----------|--------|-----|
| SHA-256 | 32B | HKDF, OSCORE |
| SHA-512 | 64B | Ed25519, Schnorr |

## Security Levels

LICHEN targets **128-bit security** throughout:

| Component | Algorithm | Bits |
|-----------|-----------|------|
| Signatures | Ed25519/Schnorr | 128 |
| Encryption | AES-128 | 128 |
| Key Exchange | X25519 | ~128 |
| Hashing | SHA-256 | 128 |

## Implementation Notes

### Ed25519 → X25519 Key Conversion

LICHEN uses the same seed for both:
```
seed = random(32 bytes)
ed25519_private = SHA512(seed)[0:32]
ed25519_public = ed25519_basepoint * ed25519_private
x25519_private = clamp(SHA512(seed)[0:32])
x25519_public = x25519_basepoint * x25519_private
```

### Deterministic Signatures

Both Ed25519 and Schnorr-48 use deterministic nonces:
```
nonce = SHA512(prefix || private_key || message)
```

This prevents catastrophic nonce reuse.
