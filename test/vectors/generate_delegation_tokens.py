#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate COSE_Sign1 Delegation Token test vectors.

Per spec section 18.8.6, Delegation Tokens use COSE_Sign1 with Schnorr48-Ed25519
(algorithm -65537), RFC 9052 Sig_structure, and integer-keyed payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import cbor2

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

# Algorithm ID for Schnorr48-Ed25519 per spec
ALG_SCHNORR48 = -65537

# COSE header parameter labels
COSE_ALG = 1
COSE_KID = 4

# Delegation token payload keys (integer-keyed per spec)
KEY_DELEGATE = 1
KEY_SCOPE = 2
KEY_RESOURCE = 3
KEY_EXPIRY = 4
KEY_SEQ = 5

# Scope bits per spec section 18.8.6
SCOPE_INVITE = 0x01
SCOPE_REMOVE = 0x02
SCOPE_DISTRIBUTE_KEY = 0x04
SCOPE_REKEY = 0x08
SCOPE_READ_MEMBERS = 0x10

# Valid scope mask (bits 0-4)
VALID_SCOPE_MASK = 0x1F

FORMAT_VERSION = 1
OUTPUT = VECTORS_DIR / "delegation_tokens.json"
SEED_DELEGATOR = bytes.fromhex("0123456789abcdef" * 4)
SEED_DELEGATE = bytes.fromhex("fedcba9876543210" * 4)


def _build_protected_header() -> bytes:
    """Encode protected header {1: -65537} as CBOR bytes."""
    return cbor2.dumps({COSE_ALG: ALG_SCHNORR48})


def _build_unprotected_header(iid: bytes) -> dict[int, bytes]:
    """Build unprotected header {4: <iid>}."""
    return {COSE_KID: iid}


def _build_payload(
    delegate: bytes,
    scope: int,
    resource: str,
    expiry: int,
    seq: int,
) -> bytes:
    """Encode delegation token payload as CBOR map with integer keys."""
    payload_map = {
        KEY_DELEGATE: delegate,
        KEY_SCOPE: scope,
        KEY_RESOURCE: resource,
        KEY_EXPIRY: expiry,
        KEY_SEQ: seq,
    }
    return cbor2.dumps(payload_map)


def _build_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build COSE Sig_structure per RFC 9052.

    Sig_structure = [
        "Signature1",     ; context string
        protected,        ; protected header bytes
        h'',              ; external_aad (empty)
        payload           ; payload bytes
    ]
    """
    sig_structure = ["Signature1", protected, b"", payload]
    return cbor2.dumps(sig_structure)


def _build_cose_sign1(
    protected: bytes,
    unprotected: dict[int, bytes],
    payload: bytes,
    signature: bytes,
) -> bytes:
    """Encode COSE_Sign1 structure as CBOR array.

    Note: Per RFC 9052, the tag 18 is optional. The implementation uses
    untagged encoding for compactness in constrained environments.
    """
    cose_sign1 = [protected, unprotected, payload, signature]
    return cbor2.dumps(cose_sign1)


def _scope_bits_dict(scope: int) -> dict[str, bool]:
    """Return human-readable scope bit breakdown."""
    return {
        "invite": bool(scope & SCOPE_INVITE),
        "remove": bool(scope & SCOPE_REMOVE),
        "distribute_key": bool(scope & SCOPE_DISTRIBUTE_KEY),
        "rekey": bool(scope & SCOPE_REKEY),
        "read_members": bool(scope & SCOPE_READ_MEMBERS),
    }


def _vector(
    name: str,
    description: str,
    *,
    scope: int,
    resource: str,
    expiry: int,
    seq: int,
    delegator_seed: bytes = SEED_DELEGATOR,
    delegate_seed: bytes = SEED_DELEGATE,
    expected_valid: bool = True,
    expected_scope_valid: bool = True,
) -> dict[str, object]:
    """Generate a single delegation token vector."""
    delegator = ReferenceIdentity.from_seed(delegator_seed)
    delegate = ReferenceIdentity.from_seed(delegate_seed)

    # Build COSE components
    protected = _build_protected_header()
    unprotected = _build_unprotected_header(delegator.iid)
    payload = _build_payload(delegate.iid, scope, resource, expiry, seq)

    # Compute signature per RFC 9052
    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(delegator, sig_structure_hash)

    # Build complete COSE_Sign1
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": name,
        "description": description,
        "coverage": "delegation_token_cose_sign1",
        # Identity inputs
        "delegator_seed": delegator_seed.hex(),
        "delegator_pubkey": delegator.pubkey.hex(),
        "delegator_iid": delegator.iid.hex(),
        "delegate_seed": delegate_seed.hex(),
        "delegate_pubkey": delegate.pubkey.hex(),
        "delegate_iid": delegate.iid.hex(),
        # Payload fields
        "scope": scope,
        "scope_bits": _scope_bits_dict(scope),
        "resource": resource,
        "expiry": expiry,
        "seq": seq,
        # COSE structure
        "protected_header": protected.hex(),
        "protected_header_decoded": {
            "alg": ALG_SCHNORR48,
            "alg_name": "Schnorr48-Ed25519",
        },
        "unprotected_header_decoded": {
            "kid": delegator.iid.hex(),
        },
        "payload_cbor": payload.hex(),
        "payload_decoded": {
            "1_delegate": delegate.iid.hex(),
            "2_scope": scope,
            "3_resource": resource,
            "4_expiry": expiry,
            "5_seq": seq,
        },
        # Signature computation
        "sig_structure": sig_structure.hex(),
        "sig_structure_layout": {
            "context": "Signature1",
            "protected": protected.hex(),
            "external_aad": "",
            "payload": payload.hex(),
        },
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        # Complete COSE_Sign1
        "cose_sign1": cose_sign1.hex(),
        # Verification expectations
        "expected": {
            "signature_valid": expected_valid,
            "algorithm_valid": True,
            "scope_bits_valid": expected_scope_valid,
        },
    }


def _invalid_scope_vector() -> dict[str, object]:
    """Generate vector with reserved scope bits set (invalid)."""
    return _vector(
        "delegation_invalid_scope_bits",
        "Delegation token with reserved scope bits 5-7 set (MUST fail validation).",
        scope=0xFF,  # All bits set, including reserved 5-7
        resource="/groups/test-group",
        expiry=1735689600,
        seq=1,
        expected_valid=True,  # Signature is valid
        expected_scope_valid=False,  # But scope bits are invalid
    )


def _owner_scope_from_admin_vector() -> dict[str, object]:
    """Generate vector where admin attempts owner-only delegation."""
    delegator = ReferenceIdentity.from_seed(SEED_DELEGATOR)
    delegate = ReferenceIdentity.from_seed(SEED_DELEGATE)

    # Admin attempting to delegate distribute_key (owner-only capability)
    scope = SCOPE_DISTRIBUTE_KEY | SCOPE_INVITE

    protected = _build_protected_header()
    unprotected = _build_unprotected_header(delegator.iid)
    payload = _build_payload(delegate.iid, scope, "/groups/test-group", 1735689600, 1)

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(delegator, sig_structure_hash)
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": "delegation_admin_exceeds_scope",
        "description": (
            "Admin attempts to delegate distribute_key (owner-only). "
            "Signature is valid but MUST fail authorization check."
        ),
        "coverage": "delegation_token_authorization",
        "delegator_seed": SEED_DELEGATOR.hex(),
        "delegator_pubkey": delegator.pubkey.hex(),
        "delegator_iid": delegator.iid.hex(),
        "delegate_iid": delegate.iid.hex(),
        "scope": scope,
        "scope_bits": _scope_bits_dict(scope),
        "owner_only_bits_present": ["distribute_key"],
        "resource": "/groups/test-group",
        "expiry": 1735689600,
        "seq": 1,
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": True,
            "scope_bits_valid": True,
            "admin_delegation_valid": False,
            "owner_delegation_valid": True,
        },
    }


def _delegate_iid_mismatch_vector() -> dict[str, object]:
    """Generate vector with delegate exercising wrong IID."""
    delegator = ReferenceIdentity.from_seed(SEED_DELEGATOR)
    delegate = ReferenceIdentity.from_seed(SEED_DELEGATE)
    wrong_delegate = ReferenceIdentity.from_seed(bytes.fromhex("abcdabcd" * 8))

    protected = _build_protected_header()
    unprotected = _build_unprotected_header(delegator.iid)
    # Token is issued to delegate.iid
    payload = _build_payload(
        delegate.iid, SCOPE_INVITE, "/groups/test-group", 1735689600, 1
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(delegator, sig_structure_hash)
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": "delegation_delegate_mismatch",
        "description": (
            "Token issued to delegate A, but exercised by node B. "
            "MUST fail delegate verification."
        ),
        "coverage": "delegation_token_validation",
        "delegator_iid": delegator.iid.hex(),
        "token_delegate_iid": delegate.iid.hex(),
        "exercising_iid": wrong_delegate.iid.hex(),
        "scope": SCOPE_INVITE,
        "resource": "/groups/test-group",
        "expiry": 1735689600,
        "seq": 1,
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": True,
            "delegate_match": False,
            "overall_valid": False,
        },
    }


def document() -> dict[str, object]:
    """Return the complete vector document."""
    return {
        "$schema": "./schema.json",
        "vector_type": "delegation_tokens",
        "format_version": FORMAT_VERSION,
        "description": (
            "COSE_Sign1 Delegation Token vectors per spec section 18.8.6. "
            "Uses Schnorr48-Ed25519 (alg -65537) with RFC 9052 Sig_structure "
            "and integer-keyed payloads."
        ),
        "oracle": {
            "basis": "LICHEN spec section 18.8.6",
            "sig_structure": '["Signature1", protected, h"", payload] per RFC 9052',
            "signature_input": "SHA256(CBOR(Sig_structure))",
            "generator_command": (
                "python3 test/vectors/generate_delegation_tokens.py"
            ),
            "cross_check": "independent PyNaCl-backed reference_schnorr48.py",
        },
        "constants": {
            "algorithm": {
                "id": ALG_SCHNORR48,
                "name": "Schnorr48-Ed25519",
                "signature_length": 48,
            },
            "scope_bits": {
                "0": "invite (0x01)",
                "1": "remove (0x02)",
                "2": "distribute_key (0x04) - owner only",
                "3": "rekey (0x08) - owner only",
                "4": "read_members (0x10)",
                "5-7": "reserved (MUST be zero)",
            },
            "owner_delegatable": "0x1F (all bits 0-4)",
            "admin_delegatable": "0x13 (bits 0, 1, 4 only)",
            "payload_keys": {
                "1": "delegate (8-byte IID)",
                "2": "scope (capability bitmask)",
                "3": "resource (group ID or path)",
                "4": "expiry (Unix timestamp)",
                "5": "seq (sequence number)",
            },
        },
        "vectors": [
            # Basic valid tokens
            _vector(
                "delegation_invite_only",
                "Owner delegates invite capability to another node.",
                scope=SCOPE_INVITE,
                resource="/groups/emergency-response",
                expiry=1735689600,  # 2025-01-01 00:00:00 UTC
                seq=1,
            ),
            _vector(
                "delegation_remove_only",
                "Owner delegates remove capability.",
                scope=SCOPE_REMOVE,
                resource="/groups/field-team-alpha",
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "delegation_admin_scope",
                "Owner grants admin-level delegation (invite + remove + read_members).",
                scope=SCOPE_INVITE | SCOPE_REMOVE | SCOPE_READ_MEMBERS,
                resource="/groups/coordination",
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "delegation_full_owner_scope",
                "Owner grants full owner-level delegation (all bits 0-4).",
                scope=VALID_SCOPE_MASK,  # 0x1F
                resource="/groups/all-hands",
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "delegation_distribute_key",
                "Owner delegates key distribution capability (owner-only).",
                scope=SCOPE_DISTRIBUTE_KEY,
                resource="/groups/secure-ops",
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "delegation_rekey",
                "Owner delegates rekey capability (owner-only).",
                scope=SCOPE_REKEY,
                resource="/groups/rotation-test",
                expiry=1735689600,
                seq=1,
            ),
            # Edge cases
            _vector(
                "delegation_seq_max",
                "Maximum 32-bit sequence number.",
                scope=SCOPE_INVITE,
                resource="/groups/test",
                expiry=1735689600,
                seq=0xFFFFFFFF,
            ),
            _vector(
                "delegation_expiry_far_future",
                "Far future expiry timestamp.",
                scope=SCOPE_INVITE,
                resource="/groups/long-term",
                expiry=4102444800,  # 2100-01-01 00:00:00 UTC
                seq=1,
            ),
            _vector(
                "delegation_short_resource",
                "Minimal resource path.",
                scope=SCOPE_INVITE,
                resource="/g",
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "delegation_long_resource",
                "Longer resource path with nested structure.",
                scope=SCOPE_READ_MEMBERS,
                resource="/groups/region-west/district-1/team-alpha",
                expiry=1735689600,
                seq=1,
            ),
            # Negative test cases
            _invalid_scope_vector(),
            _owner_scope_from_admin_vector(),
            _delegate_iid_mismatch_vector(),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
