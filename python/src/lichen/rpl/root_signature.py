# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Root Signature oracle (spec section 8.2, 8.4, draft-lichen-rpl-lora-00).

Root signature verification ensures a node only joins a DODAG controlled by
a legitimate root. Per the spec, root legitimacy is established through:

1. Link-layer Schnorr48 signature on all RPL messages (MUST per 8.2)
2. DODAGID == AddrForKey(root_pubkey) cryptographic binding (8.4)
3. Root pubkey is TOFU-pinned or pre-provisioned

The DODAGID binding ensures the root's public key derives to the advertised
DODAGID (which is a key-derived native 0200::/8 address). An attacker cannot forge a
DIO for a DODAGID they don't control because they lack the private key.

This module provides reference implementations (oracles) for cross-implementation
validation. Canonical vectors live in test/vectors/root_signature.json; their
expected results are fixed literals derived independently (see
test/vectors/reference_schnorr48.py), never from this module.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum, auto
from ipaddress import IPv6Address
from typing import Any

from lichen.crypto.identity import yggdrasil_address
from lichen.crypto.schnorr48 import verify as schnorr_verify


class RootSignatureError(Enum):
    """Root signature verification failure reasons."""

    SIGNATURE_INVALID = auto()  # Schnorr48 signature failed verification
    DODAGID_MISMATCH = auto()  # DODAGID != AddrForKey(pubkey)
    PUBKEY_INVALID = auto()  # Pubkey is malformed (wrong length)


@dataclass
class RootSignatureResult:
    """Result of root signature verification.

    Attributes:
        valid: True if both signature and DODAGID binding verified.
        error: Failure reason if valid=False, None otherwise.
        derived_dodagid: The DODAGID derived from the pubkey (for diagnostics).
    """

    valid: bool
    error: RootSignatureError | None = None
    derived_dodagid: IPv6Address | None = None


def verify_dodagid_binding(pubkey: bytes, dodagid: IPv6Address | bytes) -> bool:
    """Verify that DODAGID == AddrForKey(pubkey).

    Per spec section 8.4: "Nodes SHOULD verify root legitimacy by checking
    that DODAGID equals AddrForKey(root_pubkey)." This cryptographic binding
    ensures the root controls the private key for the advertised DODAGID.

    The AddrForKey function computes the native 0200::/8 address from the
    Ed25519 public key (see identity.yggdrasil_address).

    Args:
        pubkey: 32-byte Ed25519 public key of the root.
        dodagid: 16-byte DODAGID from the DIO message.

    Returns:
        True if pubkey derives to the given DODAGID.
    """
    if len(pubkey) != 32:
        return False

    dodagid_bytes = dodagid.packed if isinstance(dodagid, IPv6Address) else dodagid

    if len(dodagid_bytes) != 16:
        return False

    derived = yggdrasil_address(pubkey).packed
    # SECURITY: Constant-time comparison prevents timing attacks
    return hmac.compare_digest(derived, dodagid_bytes)


def verify_root_signature(
    pubkey: bytes,
    message: bytes,
    signature: bytes,
    dodagid: IPv6Address | bytes,
) -> RootSignatureResult:
    """Verify a root's signature and DODAGID binding.

    This is the primary oracle function for root signature verification.
    It combines Schnorr48 signature verification with DODAGID binding check.

    Per spec section 8.2 (draft-lichen-rpl-lora-00):
    - All RPL control messages MUST be signed with Schnorr48
    - Receivers MUST reject unsigned RPL frames

    Per spec section 8.4:
    - Nodes SHOULD verify that DODAGID == AddrForKey(root_pubkey)

    Args:
        pubkey: 32-byte Ed25519 public key of the root.
        message: The signed message bytes (frame excluding signature).
        signature: 48-byte Schnorr48 signature.
        dodagid: 16-byte DODAGID from the DIO message.

    Returns:
        RootSignatureResult with verification outcome.
    """
    # Validate pubkey length
    if len(pubkey) != 32:
        return RootSignatureResult(
            valid=False,
            error=RootSignatureError.PUBKEY_INVALID,
            derived_dodagid=None,
        )

    # Compute derived DODAGID for diagnostics
    derived = yggdrasil_address(pubkey)

    # Verify DODAGID binding (spec 8.4)
    if not verify_dodagid_binding(pubkey, dodagid):
        return RootSignatureResult(
            valid=False,
            error=RootSignatureError.DODAGID_MISMATCH,
            derived_dodagid=derived,
        )

    # Verify Schnorr48 signature (spec 8.2)
    if not schnorr_verify(pubkey, message, signature):
        return RootSignatureResult(
            valid=False,
            error=RootSignatureError.SIGNATURE_INVALID,
            derived_dodagid=derived,
        )

    return RootSignatureResult(
        valid=True,
        error=None,
        derived_dodagid=derived,
    )


def derive_dodagid_from_pubkey(pubkey: bytes) -> IPv6Address:
    """Derive the DODAGID that a root with this pubkey should use.

    Per spec section 8.4: DODAGID == AddrForKey(root_pubkey).
    This function implements AddrForKey, which returns the Yggdrasil
    0200::/8 address derived from the Ed25519 public key.

    Args:
        pubkey: 32-byte Ed25519 public key.

    Returns:
        IPv6Address to use as DODAGID.

    Raises:
        ValueError: If pubkey is not 32 bytes.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
    return yggdrasil_address(pubkey)


# Canonical-schema vector helpers (test/vectors format_version 2).
#
# The committed vectors in test/vectors/root_signature.json are fixed
# literals derived independently (see test/vectors/reference_schnorr48.py).
# These helpers exist for tooling that synthesizes or re-checks compatible
# vector dicts; they are not the oracle for the committed files.

_ERROR_BY_NAME = {
    RootSignatureError.SIGNATURE_INVALID.name: RootSignatureError.SIGNATURE_INVALID,
    RootSignatureError.DODAGID_MISMATCH.name: RootSignatureError.DODAGID_MISMATCH,
    RootSignatureError.PUBKEY_INVALID.name: RootSignatureError.PUBKEY_INVALID,
}

_HEX_LEN_PUBKEY = 64  # 32-byte Ed25519 public key
_HEX_LEN_DODAGID = 32  # 16-byte DODAGID
_HEX_LEN_SIGNATURE = 96  # 48-byte Schnorr48 signature

# Keys that may not coexist with ``binding_valid`` (binding-only vectors
# carry no signature-expectation fields).
_BINDING_EXCLUSIVE_KEYS = ("valid", "error", "message", "signature")


def _hex_field(vector: dict[str, Any], key: str, hex_len: int | None = None) -> bytes:
    """Extract a hex-encoded field, rejecting malformed values cheaply.

    Length is validated on the string before decoding so absurdly large
    inputs are rejected before allocation. ``hex_len=None`` accepts any
    even-length hex string.
    """
    value = vector[key]
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise ValueError(f"{key} must be an even-length hex string")
    if hex_len is not None and len(value) != hex_len:
        raise ValueError(f"{key} must be {hex_len} hex chars, got {len(value)}")
    return bytes.fromhex(value)


def generate_root_signature_vector(
    seed: bytes,
    message: bytes = b"test DIO message",
) -> dict[str, str | bool | None]:
    """Generate a vector dict matching the canonical root_signature.json schema.

    Args:
        seed: 32-byte seed for deterministic key generation.
        message: Message to sign.

    Returns:
        Dict with hex-encoded byte fields, ``valid`` set, and ``error``
        set to None (generated vectors are always positive), per the
        canonical schema used by test/vectors/*.json. The description is
        deliberately seed-free: the seed derives private key material and
        must not leak into free-text fields that may end up in logs.
    """
    from lichen.crypto.identity import Identity
    from lichen.crypto.schnorr48 import sign

    identity = Identity.from_seed(seed)
    signature = sign(identity.privkey, identity.pubkey, message)
    dodagid = yggdrasil_address(identity.pubkey)

    return {
        "description": "Generated root-signature vector",
        "seed": seed.hex(),
        "pubkey": identity.pubkey.hex(),
        "message": message.hex(),
        "signature": signature.hex(),
        "dodagid": dodagid.packed.hex(),
        "dodagid_str": str(dodagid),
        "valid": True,
        "error": None,
    }


def verify_root_signature_vector(vector: dict[str, Any]) -> bool:
    """Check a canonical-schema root signature vector against this oracle.

    Args:
        vector: Dict with canonical vector keys. Full vectors carry
            ``message``, ``signature`` and ``valid`` (plus a non-null
            ``error`` name exactly when invalid). Binding-only vectors
            carry ``binding_valid`` and must omit the signature-expectation
            fields (``valid``, ``error``, ``message``, ``signature``).

    Returns:
        True if the oracle's outcome (validity and failure reason) matches
        the vector's expectations exactly.

    Raises:
        ValueError: On malformed fields, wrong lengths, or contradictory
            key combinations (e.g. ``binding_valid`` alongside ``valid``).
        KeyError: On missing required keys.
    """
    if "binding_valid" in vector:
        present = [k for k in _BINDING_EXCLUSIVE_KEYS if k in vector]
        if present:
            raise ValueError(
                f"binding_valid is mutually exclusive with: {', '.join(present)}"
            )
        pubkey = _hex_field(vector, "pubkey", _HEX_LEN_PUBKEY)
        dodagid = _hex_field(vector, "dodagid", _HEX_LEN_DODAGID)
        return bool(verify_dodagid_binding(pubkey, dodagid) == vector["binding_valid"])

    # Full vectors exercise the whole pipeline: both fields are required.
    pubkey = _hex_field(vector, "pubkey", _HEX_LEN_PUBKEY)
    dodagid = _hex_field(vector, "dodagid", _HEX_LEN_DODAGID)
    message = _hex_field(vector, "message")
    signature = _hex_field(vector, "signature", _HEX_LEN_SIGNATURE)

    expected_valid = vector.get("valid", True)
    error_name = vector.get("error")

    result = verify_root_signature(pubkey, message, signature, dodagid)
    if result.valid != expected_valid:
        return False
    if not result.valid:
        if error_name is None:
            return False
        expected_error = _ERROR_BY_NAME.get(error_name)
        if expected_error is None or result.error is not expected_error:
            return False
    elif error_name is not None:
        # A success expectation cannot also declare a failure reason.
        return False
    return True
