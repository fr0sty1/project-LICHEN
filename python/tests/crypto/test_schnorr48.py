# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test schnorr48 against canonical vectors."""

import json
from pathlib import Path

import pytest

from lichen.crypto.schnorr48 import (
    LOW_ORDER_POINTS,
    _is_low_order_point,
    derive_keypair,
    sign,
    verify,
)

VECTORS_PATH = (
    Path(__file__).parent.parent.parent.parent / "spec" / "test-vectors" / "schnorr48.json"
)


@pytest.fixture
def vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)["vectors"]


def test_vectors_exist():
    assert VECTORS_PATH.exists(), f"Test vectors not found at {VECTORS_PATH}"


def test_valid_signatures(vectors):
    """Valid vectors must verify and produce identical signatures."""
    for v in vectors:
        if not v["valid"]:
            continue

        pubkey = bytes.fromhex(v["public_key"])
        msg = bytes.fromhex(v["message"])
        sig = bytes.fromhex(v["signature"])

        # Must verify
        assert verify(pubkey, msg, sig), f"Failed to verify: {v['description']}"

        # If seed provided, re-signing must produce identical signature
        if "seed" in v:
            seed = bytes.fromhex(v["seed"])
            priv, pub = derive_keypair(seed)
            assert pub == pubkey, f"Key derivation mismatch: {v['description']}"

            new_sig = sign(priv, pub, msg)
            assert new_sig == sig, f"Signature mismatch: {v['description']}"


def test_invalid_signatures(vectors):
    """Invalid vectors must not verify."""
    for v in vectors:
        if v["valid"]:
            continue

        pubkey = bytes.fromhex(v["public_key"])
        msg = bytes.fromhex(v["message"])
        sig = bytes.fromhex(v["signature"])

        assert not verify(pubkey, msg, sig), f"Should reject: {v['description']}"


def test_deterministic():
    """Same inputs always produce same signature."""
    seed = bytes(32)
    priv, pub = derive_keypair(seed)
    msg = b"determinism test"

    sig1 = sign(priv, pub, msg)
    sig2 = sign(priv, pub, msg)
    assert sig1 == sig2


def test_signature_length():
    """Signatures are exactly 48 bytes."""
    seed = bytes(32)
    priv, pub = derive_keypair(seed)
    sig = sign(priv, pub, b"test")
    assert len(sig) == 48


def test_reject_invalid_pubkey_length():
    """Reject pubkeys that aren't 32 bytes."""
    assert not verify(b"short", b"msg", b"0" * 48)
    assert not verify(b"x" * 33, b"msg", b"0" * 48)


def test_reject_invalid_signature_length():
    """Reject signatures that aren't 48 bytes."""
    seed = bytes(32)
    _, pub = derive_keypair(seed)
    assert not verify(pub, b"msg", b"0" * 47)
    assert not verify(pub, b"msg", b"0" * 49)


def test_reject_zero_challenge():
    """Reject signatures with zero challenge to prevent DoS attacks.

    SECURITY: A zero challenge (16 zero bytes) is cryptographically impossible
    in a valid signature since it's derived from SHA-512 hash. Attackers can
    cheaply construct zero-challenge signatures to waste CPU on expensive
    point multiplications. Early rejection prevents this DoS vector.
    Per draft-lichen-schnorr-00.md Appendix A.2 case 6.
    """
    seed = bytes(32)
    _, pub = derive_keypair(seed)

    # Zero challenge with arbitrary non-zero s (would pass s != 0 check)
    zero_e = bytes(16)
    nonzero_s = bytes([1] + [0] * 31)  # s = 1
    zero_challenge_sig = zero_e + nonzero_s

    assert not verify(pub, b"any message", zero_challenge_sig), (
        "Should reject zero-challenge signature"
    )

    # Also test with a more realistic-looking s value
    realistic_s = bytes.fromhex(
        "706676c26685a806d6e0d74f345e200900000000000000000000000000000000"
    )
    zero_challenge_sig2 = zero_e + realistic_s

    assert not verify(pub, b"test", zero_challenge_sig2), (
        "Should reject zero-challenge signature with realistic s"
    )


def test_reject_low_order_pubkeys():
    """Reject low-order public keys to prevent signature forgery.

    Low-order points (order dividing 8) can be used in forgery attacks:
    if pubkey is identity, e*pubkey = 0 for any e, allowing forgery.
    """
    # Use a plausible-looking signature (proper length, nonzero e and s)
    # to ensure rejection is due to low-order pubkey, not zero challenge
    nonzero_e = bytes([1] + [0] * 15)
    nonzero_s = bytes([1] + [0] * 31)
    fake_sig = nonzero_e + nonzero_s

    for low_order_point in LOW_ORDER_POINTS:
        assert not verify(low_order_point, b"test message", fake_sig), (
            f"Should reject low-order point: {low_order_point.hex()}"
        )


def test_is_low_order_point_constant_time():
    """Verify _is_low_order_point identifies all low-order points.

    SECURITY: The implementation uses hmac.compare_digest for each comparison
    and iterates all points regardless of match to maintain constant time
    per spec section 5.3.
    """
    # All low-order points should be identified
    for low_order_point in LOW_ORDER_POINTS:
        assert _is_low_order_point(low_order_point), (
            f"Should identify low-order point: {low_order_point.hex()}"
        )

    # A valid Ed25519 public key should not be identified as low-order
    seed = bytes(32)
    _, pub = derive_keypair(seed)
    assert not _is_low_order_point(pub), "Valid pubkey should not be low-order"

    # Random bytes (not a valid point) should not match any low-order point
    random_bytes = bytes(range(32))
    assert not _is_low_order_point(random_bytes)
