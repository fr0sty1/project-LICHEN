<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Schnorr Signatures with Truncated Challenge for Constrained Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-schnorr-00                                         May 2026
Intended status: Experimental
Expires: November 2026
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

## Abstract

This document specifies a Schnorr signature variant that produces 48-byte
signatures while maintaining 128-bit security. The scheme is designed for
constrained networks such as LoRa mesh where bandwidth is severely limited.
It uses Curve25519 (via Ed25519 keys) with a truncated challenge, trading
signature size for a modest reduction in security margin.

## Table of Contents

1. Introduction
2. Terminology
3. Cryptographic Primitives
4. Signature Scheme
5. Implementation Considerations
6. Security Considerations
7. IANA Considerations
8. References

## 1. Introduction

Standard Ed25519 signatures (RFC 8032) are 64 bytes. In constrained networks
like LoRa mesh, where typical payloads are 50-200 bytes, 64 bytes of signature
overhead is prohibitive.

This document specifies a Schnorr signature variant that reduces signature
size to 48 bytes by truncating the challenge hash. The construction is
well-known in the cryptographic literature and provides 128-bit security
against forgery.

### 1.1. Design Goals

- **Small signatures:** 48 bytes (25% smaller than Ed25519)
- **Standard keys:** Compatible with Ed25519 keypairs
- **Proven security:** Based on well-studied Schnorr construction
- **Simple implementation:** Minor modification to Ed25519 libraries

### 1.2. Use Case

This scheme is designed for the LICHEN protocol (LoRa IPv6 CoAP Hybrid
Extended Network), where every transmitted frame carries a signature for
sender authentication. At LoRa data rates (300 bps - 27 kbps), 16 bytes
saved per packet is significant.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **B:** The Ed25519 base point
- **L:** The order of the Ed25519 group (2^252 + 27742317777372353535851937790883648493)
- **H():** SHA-512 hash function
- **privkey:** 32-byte Ed25519 private key (scalar)
- **pubkey:** 32-byte Ed25519 public key (compressed point)

## 3. Cryptographic Primitives

### 3.1. Curve Parameters

This scheme uses Curve25519 in the Edwards form (Ed25519):

- Prime: p = 2^255 - 19
- Order: L = 2^252 + 27742317777372353535851937790883648493
- Base point: B (as defined in RFC 8032)

### 3.2. Hash Function

SHA-512 as specified in FIPS 180-4. The hash output is 64 bytes, interpreted
as a little-endian integer and reduced modulo L when used as a scalar.

### 3.3. Key Generation

Keys are generated per RFC 8032 Section 5.1.5:

```
seed = random(32 bytes)
h = SHA-512(seed)
privkey = clamp(h[0:32])
pubkey = privkey * B
```

Existing Ed25519 keypairs MAY be used directly.

## 4. Signature Scheme

### 4.1. Notation

- `||` denotes concatenation
- `[a:b]` denotes bytes a through b-1 (0-indexed)
- `mod L` denotes reduction modulo the group order

### 4.2. Signing

Input:
- privkey: 32-byte private key
- pubkey: 32-byte public key
- msg: message to sign (arbitrary length)

Process:

```
1. Generate nonce:
   r = H(privkey || msg) mod L

   Note: Deterministic nonce generation prevents catastrophic
   failure from nonce reuse.

2. Compute commitment:
   R = r * B

3. Compute challenge:
   e_full = H(R || pubkey || msg)
   e = e_full[0:16]                    // Truncate to 128 bits
   e_scalar = e || zeros(16)           // Pad to 32 bytes, little-endian

4. Compute response:
   s = (r + e_scalar * privkey) mod L

5. Output signature:
   signature = e || s                   // 16 + 32 = 48 bytes
```

### 4.3. Verification

Input:
- pubkey: 32-byte public key
- msg: message that was signed
- signature: 48-byte signature

Process:

```
1. Parse signature:
   e_received = signature[0:16]         // 16 bytes
   s = signature[16:48]                 // 32 bytes

2. Recover commitment:
   e_extended = e_received || zeros(16) // Extend to 32 bytes
   e_scalar = interpret_as_scalar(e_extended)
   R' = s * B - e_scalar * pubkey

3. Recompute challenge:
   e'_full = H(R' || pubkey || msg)
   e' = e'_full[0:16]

4. Verify:
   if e' == e_received:
       return VALID
   else:
       return INVALID
```

### 4.4. Signature Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Challenge e (16 bytes)                     |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                                                               |
|                                                               |
|                    Response s (32 bytes)                      |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total: 48 bytes
```

## 5. Implementation Considerations

### 5.1. Scalar Interpretation

When interpreting the truncated challenge for scalar multiplication:

- Extend e_received (16 bytes) to 32 bytes by appending zeros
- Interpret as little-endian integer
- This value is already less than L (since 2^128 < L)

### 5.2. Point Recovery

The verification computes R' = s*B - e*pubkey. This requires:
- One fixed-base scalar multiplication (s*B)
- One variable-base scalar multiplication (e*pubkey)
- One point subtraction

Most Ed25519 libraries provide these primitives.

### 5.3. Constant-Time Implementation

Implementations MUST use constant-time operations for:
- Scalar multiplication
- Signature comparison

Variable-time operations MAY leak private key material through timing
side channels.

### 5.4. Batch Verification

This scheme supports batch verification with the standard Schnorr
batch technique. Given n signatures:

1. Choose random scalars z_1, ..., z_n
2. Compute: sum(z_i * s_i) * B == sum(z_i * R_i) + sum(z_i * e_i * pubkey_i)

Batch verification is approximately 2x faster than individual verification
for large batches.

### 5.5. Application Profiles

An application profile MAY pass a fixed-length, domain-separated digest as
`msg`. The application specification, not this document, defines that digest
and transcript. In particular, the LICHEN DAO Origin Signature profile passes
the complete 64-byte SHA-512 digest defined by its RPL profile; Schnorr48 MUST
sign those 64 bytes directly and MUST NOT hash, truncate, decode, or append a
NUL to the application transcript before applying the signing procedure in
Section 4.2. The SHA-512 operation intrinsic to Section 4.2 still applies.

## 6. Security Considerations

### 6.1. Security Level

The truncated challenge provides 128-bit security against existential
forgery under chosen message attack (EUF-CMA).

An attacker must find a collision in the 128-bit challenge space, which
requires approximately 2^64 operations (birthday bound). However, each
"guess" requires computing a discrete log, making the attack infeasible.

### 6.2. Comparison to Ed25519

| Property | Ed25519 | This Scheme |
|----------|---------|-------------|
| Signature size | 64 bytes | 48 bytes |
| Security level | ~128 bits | ~128 bits |
| Challenge size | 256 bits (truncated internally) | 128 bits |
| Key compatibility | Native | Compatible |

### 6.3. Nonce Generation

This scheme uses deterministic nonce generation (RFC 6979 style):

```
r = H(privkey || msg) mod L
```

This prevents catastrophic failure from nonce reuse. If the same message
is signed twice with the same key, the same signature is produced (safe).

Random nonce generation is NOT RECOMMENDED because nonce reuse with
different messages reveals the private key.

### 6.4. Known Limitations

1. **Not a standard:** This scheme is not specified in an existing RFC.
   Implementations must follow this document precisely.

2. **Truncation security:** The 128-bit security is theoretical. No
   known attacks exist, but the scheme has less margin than Ed25519.

3. **Not quantum-resistant:** Like all elliptic curve schemes, this
   is vulnerable to quantum computers running Shor's algorithm.

### 6.5. Recommendations

1. Use this scheme only when the 16-byte savings is significant
2. Prefer Ed25519 when bandwidth is not constrained
3. Implement batch verification when processing multiple signatures
4. Use hardware secure elements for key storage when available

## 7. IANA Considerations

This document has no IANA actions.

Future versions may request allocation of an algorithm identifier if
this scheme is adopted for use in COSE (RFC 8152) or similar frameworks.

## 8. References

### 8.1. Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.

- [RFC 8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
  Signature Algorithm (EdDSA)", RFC 8032, January 2017.

- [FIPS 180-4] National Institute of Standards and Technology, "Secure
  Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

### 8.2. Informative References

- [Schnorr91] Schnorr, C.P., "Efficient Signature Generation by Smart
  Cards", Journal of Cryptology, 1991.

- [RFC 6979] Pornin, T., "Deterministic Usage of the Digital Signature
  Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm
  (ECDSA)", RFC 6979, August 2013.

- [LICHEN] LICHEN Protocol Specification, 2026.
  https://github.com/MarkAtwood/project-LICHEN

## Appendix A. Test Vectors

Machine-readable vectors: `test/vectors/schnorr48.json`

### A.1. Valid Signatures

**Vector 1: Empty message**
```
seed:       0000000000000000000000000000000000000000000000000000000000000000
private:    5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156
public:     3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
message:    (empty)
signature:  26f70691bbde0c1e8becc00e7e7663cb6b72364b6ea208fdabef226c5b0d07ce
            c9c661fd69671981ca40277598ea9c01
```

**Vector 2: Simple message "test"**
```
seed:       deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe
private:    50b8c29238a8403e0ac69e23d47b9184c371a92460d518351b099944bbdfa867
public:     9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d
message:    74657374
signature:  c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8
            706676c26685a806d6e0d74f345e2009
```

**Vector 3: Pangram**
```
seed:       0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
private:    b0829ce3ccf1d8edd5da1132d46271b0169f58b6414fd263d3c98da627170f5e
public:     207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6
message:    54686520717569636b2062726f776e20666f78206a756d7073206f766572
            20746865206c617a7920646f67
signature:  e15b69ed5bd6fccc6c624431eb1bb08341ba571158da31249ac72a28af7f77ea
            0534b94cc1f8650dead98ccae16ec803
```

### A.2. Invalid Signatures

These MUST be rejected by conforming implementations:

1. **Wrong message**: Vector 2 signature with message "wrong" (77726f6e67)
2. **Tampered challenge**: Flip bit 40 of Vector 2 signature
3. **Tampered response**: Flip bit 160 of Vector 2 signature
4. **Wrong public key**: Vector 2 signature with Vector 3's public key
5. **Truncated signature**: Vector 2 signature with last byte removed (47 bytes)
6. **Zero signature**: 48 zero bytes

## Appendix B. Reference Implementation

Python reference: `python/src/lichen/crypto/schnorr48.py`

Uses pynacl (libsodium bindings) for Ed25519 primitives.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
