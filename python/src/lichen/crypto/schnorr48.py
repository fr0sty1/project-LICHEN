"""LICHEN 48-byte Schnorr signatures per draft-lichen-schnorr-00.

Curve25519/Ed25519, SHA-512, 16-byte truncated challenge + 32-byte response.
Deterministic nonce prevents catastrophic failure from reuse.
"""

from hashlib import sha512

from nacl.bindings import (
    crypto_core_ed25519_is_valid_point,
    crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_sub,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_ed25519_noclamp,
)

# Group order L = 2^252 + 27742317777372353535851937790883648493
L = 2**252 + 27742317777372353535851937790883648493


def _scalar_from_bytes(b: bytes) -> int:
    """Little-endian bytes to int."""
    return int.from_bytes(b, "little")


def _scalar_to_bytes(n: int) -> bytes:
    """Int to 32-byte little-endian."""
    return (n % L).to_bytes(32, "little")


def _hash_to_scalar(data: bytes) -> tuple[bytes, int]:
    """SHA-512, reduce mod L, return both raw hash and scalar."""
    h = sha512(data).digest()
    # crypto_core_ed25519_scalar_reduce takes 64 bytes, returns 32
    reduced = crypto_core_ed25519_scalar_reduce(h)
    return h, _scalar_from_bytes(reduced)


def _point_mult_base(scalar: int) -> bytes:
    """scalar * B (base point)."""
    s_bytes = _scalar_to_bytes(scalar)
    return crypto_scalarmult_ed25519_base_noclamp(s_bytes)


def _point_mult(scalar: int, point: bytes) -> bytes:
    """scalar * point."""
    s_bytes = _scalar_to_bytes(scalar)
    return crypto_scalarmult_ed25519_noclamp(s_bytes, point)


def _point_sub(a: bytes, b: bytes) -> bytes:
    """a - b (point subtraction)."""
    return crypto_core_ed25519_sub(a, b)


def _clamp(scalar_bytes: bytes) -> bytes:
    """Apply Ed25519 clamping to scalar."""
    s = bytearray(scalar_bytes)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return bytes(s)


def derive_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive Ed25519 keypair from 32-byte seed.

    Returns (private_scalar, public_point).
    """
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes")
    h = sha512(seed).digest()
    privkey = _clamp(h[:32])
    pubkey = _point_mult_base(_scalar_from_bytes(privkey))
    return privkey, pubkey


def sign(privkey: bytes, pubkey: bytes, msg: bytes) -> bytes:
    """Sign message, return 48-byte signature (e || s).

    Args:
        privkey: 32-byte Ed25519 private scalar (clamped)
        pubkey: 32-byte Ed25519 public key (compressed point)
        msg: message bytes

    Returns:
        48-byte signature: 16-byte challenge + 32-byte response
    """
    if len(privkey) != 32 or len(pubkey) != 32:
        raise ValueError("Keys must be 32 bytes")

    # 1. Deterministic nonce: r = H(privkey || msg) mod L
    # Use the full privkey for nonce derivation (not just scalar)
    _, r = _hash_to_scalar(privkey + msg)

    # 2. Commitment: R = r * B
    R = _point_mult_base(r)  # noqa: N806 - Schnorr point notation

    # 3. Challenge: e = H(R || pubkey || msg)[0:16]
    e_full_hash = sha512(R + pubkey + msg).digest()
    e = e_full_hash[:16]  # truncated challenge
    # Use truncated value as scalar (must match verification)
    e_scalar = _scalar_from_bytes(e + b'\x00' * 16)

    # 4. Response: s = (r + e_scalar * privkey) mod L
    priv_scalar = _scalar_from_bytes(privkey)
    s = (r + e_scalar * priv_scalar) % L

    return e + _scalar_to_bytes(s)


def verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify 48-byte signature.

    Args:
        pubkey: 32-byte Ed25519 public key
        msg: message bytes
        sig: 48-byte signature

    Returns:
        True if valid, False otherwise
    """
    if len(pubkey) != 32 or len(sig) != 48:
        return False

    if not crypto_core_ed25519_is_valid_point(pubkey):
        return False

    # 1. Parse signature
    e_received = sig[:16]
    s_bytes = sig[16:48]
    if len(s_bytes) != 32:
        return False
    s = _scalar_from_bytes(s_bytes)
    # Reject s == 0 or s >= L (non-canonical)
    if s == 0 or s >= L:
        return False

    # 2. Extend e to scalar (pad with zeros)
    e_extended = e_received + b'\x00' * 16
    e_scalar = _scalar_from_bytes(e_extended)

    # 3. Recover commitment: R' = s*B - e*pubkey
    sB = _point_mult_base(s)  # noqa: N806 - Schnorr point notation
    ePK = _point_mult(e_scalar, pubkey)  # noqa: N806 - Schnorr point notation
    R_prime = _point_sub(sB, ePK)  # noqa: N806 - Schnorr point notation

    # 4. Recompute challenge
    e_full_hash, _ = _hash_to_scalar(R_prime + pubkey + msg)
    e_prime = e_full_hash[:16]

    # 5. Compare (constant-time would be better, but Python...)
    return e_prime == e_received
