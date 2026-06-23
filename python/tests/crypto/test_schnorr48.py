"""Test schnorr48 against canonical vectors."""

import json
from pathlib import Path

import pytest

from lichen.crypto.schnorr48 import derive_keypair, sign, verify

VECTORS_PATH = Path(__file__).parent.parent.parent.parent / "test" / "vectors" / "schnorr48.json"


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
