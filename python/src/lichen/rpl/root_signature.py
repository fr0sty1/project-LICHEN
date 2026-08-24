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

This module provides reference implementations (oracles) for test vector
generation and cross-implementation validation.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum, auto
from ipaddress import IPv6Address

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


# Test vector generation support

def generate_root_signature_vector(
    seed: bytes,
    message: bytes = b"test message",
) -> dict:
    """Generate a test vector for root signature verification.

    Args:
        seed: 32-byte seed for deterministic key generation.
        message: Message to sign.

    Returns:
        Dict with all fields needed for cross-implementation testing.
    """
    from lichen.crypto.identity import Identity
    from lichen.crypto.schnorr48 import sign

    identity = Identity.from_seed(seed)
    signature = sign(identity.privkey, identity.pubkey, message)
    dodagid = yggdrasil_address(identity.pubkey)

    return {
        "seed_hex": seed.hex(),
        "pubkey_hex": identity.pubkey.hex(),
        "message_hex": message.hex(),
        "signature_hex": signature.hex(),
        "dodagid_hex": dodagid.packed.hex(),
        "dodagid_str": str(dodagid),
        "expected_valid": True,
    }


def verify_root_signature_vector(vector: dict) -> bool:
    """Verify a root signature test vector.

    Args:
        vector: Dict with pubkey_hex, message_hex, signature_hex, dodagid_hex.

    Returns:
        True if verification result matches expected_valid.
    """
    pubkey = bytes.fromhex(vector["pubkey_hex"])
    message = bytes.fromhex(vector["message_hex"])
    signature = bytes.fromhex(vector["signature_hex"])
    dodagid = bytes.fromhex(vector["dodagid_hex"])
    expected_valid = vector.get("expected_valid", True)

    result = verify_root_signature(pubkey, message, signature, dodagid)
    return result.valid == expected_valid
