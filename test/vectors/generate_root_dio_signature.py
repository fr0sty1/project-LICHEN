#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate COSE_Sign1 Root DIO Signature test vectors.

Per spec/06-security.md Section 8.10.1, Root DIO Signature uses COSE_Sign1
with Schnorr48-Ed25519 (algorithm -65537) and integer-keyed payloads.

Payload keys:
  1: dodag_id (bstr 16 bytes)
  2: instance (uint)
  3: version (uint)
  4: rank (uint)
  5: expiry (uint)
  6: root_seq (uint)
  7: mop (uint)
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from ipaddress import IPv6Address
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
from reference_schnorr48 import ReferenceIdentity, sign, verify  # noqa: E402

# Algorithm ID for Schnorr48-Ed25519 per spec
ALG_SCHNORR48 = -65537

# COSE header parameter labels (RFC 9052)
COSE_ALG = 1
COSE_KID = 4

# Root DIO Signature payload keys (integer-keyed per spec 8.10.1)
PAYLOAD_KEY_DODAG_ID = 1
PAYLOAD_KEY_INSTANCE = 2
PAYLOAD_KEY_VERSION = 3
PAYLOAD_KEY_RANK = 4
PAYLOAD_KEY_EXPIRY = 5
PAYLOAD_KEY_ROOT_SEQ = 6
PAYLOAD_KEY_MOP = 7

# LICHEN RPL constants
ROOT_RANK = 256
DEFAULT_MOP = 2  # Storing mode with multicast

FORMAT_VERSION = 1
OUTPUT = VECTORS_DIR / "root_dio_signature.json"

# Deterministic seeds for reproducible vectors
ROOT_SEED = bytes.fromhex("0001020304050607" * 4)
ATTACKER_SEED = bytes.fromhex("a0a1a2a3a4a5a6a7" * 4)


def _build_protected_header() -> bytes:
    """Encode protected header {1: -65537} as CBOR bytes."""
    return cbor2.dumps({COSE_ALG: ALG_SCHNORR48})


def _build_unprotected_header(iid: bytes) -> dict[int, bytes]:
    """Build unprotected header {4: <iid>}."""
    return {COSE_KID: iid}


def _build_payload(
    dodag_id: bytes,
    instance: int,
    version: int,
    rank: int,
    expiry: int,
    root_seq: int,
    mop: int,
) -> bytes:
    """Encode Root DIO Signature payload as CBOR."""
    payload_map = {
        PAYLOAD_KEY_DODAG_ID: dodag_id,
        PAYLOAD_KEY_INSTANCE: instance,
        PAYLOAD_KEY_VERSION: version,
        PAYLOAD_KEY_RANK: rank,
        PAYLOAD_KEY_EXPIRY: expiry,
        PAYLOAD_KEY_ROOT_SEQ: root_seq,
        PAYLOAD_KEY_MOP: mop,
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
    """Encode COSE_Sign1 structure as CBOR array with tag 18."""
    # COSE_Sign1 = [protected, unprotected, payload, signature]
    cose_sign1 = [protected, unprotected, payload, signature]
    return cbor2.dumps(cbor2.CBORTag(18, cose_sign1))


def _derive_dodag_id(identity: ReferenceIdentity) -> bytes:
    """Derive DODAGID from identity's Yggdrasil address (AddrForKey binding)."""
    return identity.ygg_addr


def _vector(
    name: str,
    description: str,
    *,
    identity: ReferenceIdentity,
    dodag_id: bytes | None = None,
    instance: int = 0,
    version: int = 1,
    rank: int = ROOT_RANK,
    expiry: int = 1735689600,
    root_seq: int = 1,
    mop: int = DEFAULT_MOP,
    kid_iid: bytes | None = None,
    use_wrong_algorithm: bool = False,
    expected_signature_valid: bool = True,
    expected_dodagid_valid: bool = True,
    expected_kid_valid: bool = True,
    error: str | None = None,
) -> dict[str, object]:
    """Generate a single Root DIO Signature vector."""
    # Use identity's DODAGID if not overridden
    if dodag_id is None:
        dodag_id = _derive_dodag_id(identity)

    # Use identity's IID for kid if not overridden
    if kid_iid is None:
        kid_iid = identity.iid

    # Build COSE components
    if use_wrong_algorithm:
        # Use wrong algorithm for error case
        protected = cbor2.dumps({COSE_ALG: -7})  # ES256 (wrong)
    else:
        protected = _build_protected_header()

    unprotected = _build_unprotected_header(kid_iid)
    payload = _build_payload(
        dodag_id, instance, version, rank, expiry, root_seq, mop
    )

    # Compute signature per RFC 9052
    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(identity, sig_structure_hash)

    # Build complete COSE_Sign1
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    # Cross-verify signature
    sig_verified = verify(identity.pubkey, sig_structure_hash, signature)

    # Format DODAGID as IPv6 string
    dodag_id_ipv6 = str(IPv6Address(dodag_id))
    expected_dodag_id_ipv6 = str(IPv6Address(_derive_dodag_id(identity)))

    overall_valid = (
        expected_signature_valid
        and expected_dodagid_valid
        and expected_kid_valid
        and not use_wrong_algorithm
    )

    return {
        "name": name,
        "description": description,
        "coverage": "root_dio_signature_cose_sign1",
        # Identity inputs
        "signing_seed": identity.seed.hex(),
        "public_key": identity.pubkey.hex(),
        "root_iid": identity.iid.hex(),
        # Payload fields
        "dodag_id": dodag_id.hex(),
        "dodag_id_ipv6": dodag_id_ipv6,
        "instance": instance,
        "version": version,
        "rank": rank,
        "expiry": expiry,
        "root_seq": root_seq,
        "mop": mop,
        # COSE structure
        "protected_header": protected.hex(),
        "protected_header_decoded": {
            "alg": -7 if use_wrong_algorithm else ALG_SCHNORR48,
            "alg_name": "ES256" if use_wrong_algorithm else "Schnorr48-Ed25519",
        },
        "unprotected_header_decoded": {
            "kid": kid_iid.hex(),
        },
        "payload_cbor": payload.hex(),
        "payload_decoded": {
            "1_dodag_id": dodag_id.hex(),
            "2_instance": instance,
            "3_version": version,
            "4_rank": rank,
            "5_expiry": expiry,
            "6_root_seq": root_seq,
            "7_mop": mop,
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
        "signature_components": {
            "challenge": signature[:16].hex(),
            "response": signature[16:].hex(),
        },
        # Complete COSE_Sign1
        "cose_sign1": cose_sign1.hex(),
        # Validation binding (per spec 8.10.1)
        "expected_dodag_id": _derive_dodag_id(identity).hex(),
        "expected_dodag_id_ipv6": expected_dodag_id_ipv6,
        # Verification
        "cross_verify_passed": sig_verified,
        "expected": {
            "signature_valid": expected_signature_valid,
            "dodagid_binding_valid": expected_dodagid_valid,
            "kid_iid_valid": expected_kid_valid,
            "algorithm_valid": not use_wrong_algorithm,
            "overall_valid": overall_valid,
            "error": error,
        },
    }


def _tampered_signature_vector(identity: ReferenceIdentity) -> dict[str, object]:
    """Generate vector with bit-flipped signature."""
    dodag_id = _derive_dodag_id(identity)
    protected = _build_protected_header()
    unprotected = _build_unprotected_header(identity.iid)
    payload = _build_payload(
        dodag_id, 0, 1, ROOT_RANK, 1735689600, 1, DEFAULT_MOP
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(identity, sig_structure_hash)

    # Tamper with signature (flip one bit)
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0x01
    tampered_sig = bytes(tampered_sig)

    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, tampered_sig)

    dodag_id_ipv6 = str(IPv6Address(dodag_id))

    return {
        "name": "root_dio_signature_tampered",
        "description": "Signature with one bit flipped (MUST fail verification).",
        "coverage": "root_dio_signature_security",
        "signing_seed": identity.seed.hex(),
        "public_key": identity.pubkey.hex(),
        "root_iid": identity.iid.hex(),
        "dodag_id": dodag_id.hex(),
        "dodag_id_ipv6": dodag_id_ipv6,
        "instance": 0,
        "version": 1,
        "rank": ROOT_RANK,
        "expiry": 1735689600,
        "root_seq": 1,
        "mop": DEFAULT_MOP,
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "original_signature": signature.hex(),
        "tampered_signature": tampered_sig.hex(),
        "tampered_byte_index": 0,
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": False,
            "overall_valid": False,
            "error": "signature_invalid",
        },
    }


def _impersonation_vector(
    root: ReferenceIdentity, attacker: ReferenceIdentity
) -> dict[str, object]:
    """Generate vector where attacker signs but claims root's DODAGID."""
    root_dodag_id = _derive_dodag_id(root)
    protected = _build_protected_header()
    # Attacker uses their IID for kid, but claims root's DODAGID
    unprotected = _build_unprotected_header(attacker.iid)
    payload = _build_payload(
        root_dodag_id, 0, 1, ROOT_RANK, 1735689600, 1, DEFAULT_MOP
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(attacker, sig_structure_hash)

    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": "root_dio_signature_impersonation",
        "description": (
            "Attacker signs DIO claiming victim root's DODAGID. "
            "DODAGID != AddrForKey(attacker_pubkey), so binding check MUST fail."
        ),
        "coverage": "root_dio_signature_security",
        "attacker_seed": attacker.seed.hex(),
        "attacker_pubkey": attacker.pubkey.hex(),
        "attacker_iid": attacker.iid.hex(),
        "attacker_dodag_id": _derive_dodag_id(attacker).hex(),
        "victim_dodag_id": root_dodag_id.hex(),
        "victim_dodag_id_ipv6": str(IPv6Address(root_dodag_id)),
        "claimed_dodag_id": root_dodag_id.hex(),
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": True,
            "dodagid_binding_valid": False,
            "overall_valid": False,
            "error": "dodagid_mismatch",
            "note": "Attacker's pubkey does not derive to claimed DODAGID",
        },
    }


def _kid_mismatch_vector(identity: ReferenceIdentity) -> dict[str, object]:
    """Generate vector where kid IID differs from root's IID."""
    dodag_id = _derive_dodag_id(identity)
    protected = _build_protected_header()
    # Use a different IID for kid
    wrong_iid = bytes.fromhex("0102030405060708")
    unprotected = _build_unprotected_header(wrong_iid)
    payload = _build_payload(
        dodag_id, 0, 1, ROOT_RANK, 1735689600, 1, DEFAULT_MOP
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(identity, sig_structure_hash)

    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": "root_dio_signature_kid_mismatch",
        "description": (
            "kid in unprotected header does not match root's IID. "
            "Per spec 8.10.1 step 1, kid must match DIO source address IID."
        ),
        "coverage": "root_dio_signature_validation",
        "signing_seed": identity.seed.hex(),
        "public_key": identity.pubkey.hex(),
        "correct_iid": identity.iid.hex(),
        "wrong_kid_iid": wrong_iid.hex(),
        "dodag_id": dodag_id.hex(),
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": True,
            "kid_iid_valid": False,
            "overall_valid": False,
            "error": "kid_mismatch",
        },
    }


def _zero_signature_vector(identity: ReferenceIdentity) -> dict[str, object]:
    """Generate vector with all-zero signature."""
    dodag_id = _derive_dodag_id(identity)
    protected = _build_protected_header()
    unprotected = _build_unprotected_header(identity.iid)
    payload = _build_payload(
        dodag_id, 0, 1, ROOT_RANK, 1735689600, 1, DEFAULT_MOP
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    zero_signature = bytes(48)

    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, zero_signature)

    return {
        "name": "root_dio_signature_zero",
        "description": "All-zero signature (MUST fail verification).",
        "coverage": "root_dio_signature_security",
        "signing_seed": identity.seed.hex(),
        "public_key": identity.pubkey.hex(),
        "root_iid": identity.iid.hex(),
        "dodag_id": dodag_id.hex(),
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": zero_signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": False,
            "overall_valid": False,
            "error": "signature_invalid",
        },
    }


def document() -> dict[str, object]:
    """Return the complete vector document."""
    root = ReferenceIdentity.from_seed(ROOT_SEED)
    attacker = ReferenceIdentity.from_seed(ATTACKER_SEED)

    return {
        "$schema": "./schema.json",
        "vector_type": "root_dio_signature",
        "format_version": FORMAT_VERSION,
        "description": (
            "COSE_Sign1 Root DIO Signature vectors per spec/06-security.md "
            "Section 8.10.1. Uses Schnorr48-Ed25519 (alg -65537) with RFC 9052 "
            "Sig_structure and integer-keyed payloads. Root DIOs carry optional "
            "defense-in-depth signature proving origin from DODAG root."
        ),
        "oracle": {
            "basis": "LICHEN spec/06-security.md Section 8.10.1",
            "sig_structure": (
                '["Signature1", protected, h"", payload] per RFC 9052'
            ),
            "signature_input": "SHA256(CBOR(Sig_structure))",
            "dodagid_binding": "DODAGID must equal AddrForKey(root_pubkey)",
            "generator_command": (
                "python3 test/vectors/generate_root_dio_signature.py"
            ),
            "cross_check": "independent PyNaCl-backed reference_schnorr48.py",
        },
        "constants": {
            "algorithm": {
                "id": ALG_SCHNORR48,
                "name": "Schnorr48-Ed25519",
                "signature_length": 48,
            },
            "payload_keys": {
                "1": "dodag_id (bstr 16)",
                "2": "instance (uint)",
                "3": "version (uint)",
                "4": "rank (uint)",
                "5": "expiry (uint)",
                "6": "root_seq (uint)",
                "7": "mop (uint)",
            },
            "rpl_constants": {
                "root_rank": ROOT_RANK,
                "default_mop": DEFAULT_MOP,
            },
        },
        "vectors": [
            # Valid round-trip vectors
            _vector(
                "root_dio_signature_valid_basic",
                "Valid Root DIO Signature with correct DODAGID binding.",
                identity=root,
            ),
            _vector(
                "root_dio_signature_valid_version_42",
                "Valid Root DIO Signature with non-default version number.",
                identity=root,
                version=42,
            ),
            _vector(
                "root_dio_signature_valid_instance_1",
                "Valid Root DIO Signature with non-default RPL instance.",
                identity=root,
                instance=1,
            ),
            _vector(
                "root_dio_signature_valid_seq_max",
                "Valid Root DIO Signature with maximum 32-bit root_seq.",
                identity=root,
                root_seq=0xFFFFFFFF,
            ),
            _vector(
                "root_dio_signature_valid_mop_3",
                "Valid Root DIO Signature with storing mode without multicast.",
                identity=root,
                mop=3,
            ),
            _vector(
                "root_dio_signature_valid_far_expiry",
                "Valid Root DIO Signature with far future expiry.",
                identity=root,
                expiry=4102444800,  # 2100-01-01 00:00:00 UTC
            ),
            # Edge cases
            _vector(
                "root_dio_signature_rank_non_root",
                "Root DIO Signature with non-root rank (512). Signature valid but "
                "receivers should verify rank matches expected ROOT_RANK per spec.",
                identity=root,
                rank=512,
            ),
            _vector(
                "root_dio_signature_seq_zero",
                "Root DIO Signature with root_seq=0. Valid but spec recommends >0.",
                identity=root,
                root_seq=0,
            ),
            # Error cases - signature failures
            _tampered_signature_vector(root),
            _zero_signature_vector(root),
            # Error cases - binding failures
            _impersonation_vector(root, attacker),
            _kid_mismatch_vector(root),
            # Error case - wrong algorithm
            _vector(
                "root_dio_signature_wrong_algorithm",
                "Protected header specifies ES256 instead of Schnorr48. "
                "Algorithm check MUST fail per spec 8.10.1 step 2.",
                identity=root,
                use_wrong_algorithm=True,
                expected_signature_valid=True,
                error="algorithm_invalid",
            ),
            # Different identity for determinism check
            _vector(
                "root_dio_signature_alternate_identity",
                "Second valid vector with different seed for cross-implementation "
                "determinism verification.",
                identity=attacker,
            ),
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
