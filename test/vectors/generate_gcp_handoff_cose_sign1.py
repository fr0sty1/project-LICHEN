#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independent GCP handoff COSE_Sign1 test vectors for spec section 8/GCP-7.1."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import cbor2

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from atomic_json import atomic_write_json_batch, json_bytes, read_bounded_exact  # noqa: E402
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

OUTPUT = HERE / "gcp_handoff_cose_sign1.json"
FORMAT_VERSION = 1
ALG = -65537  # Schnorr48-Ed25519
NOW = 1_900_000_000

# Deterministic identities for reproducible vectors
NODE = ReferenceIdentity.from_seed(bytes(range(32)))
OLD_GW = ReferenceIdentity.from_seed(bytes(range(32, 64)))
NEW_GW = ReferenceIdentity.from_seed(bytes(range(64, 96)))
OTHER_GW = ReferenceIdentity.from_seed(bytes(range(96, 128)))

# Request payload keys (spec GCP-7.1)
_R_NODE = 1
_R_OLD_GW = 2
_R_SEQ = 3
_R_TS = 4
_R_EXPIRY = 5
_R_RSSI = 6
_REQUEST_KEYS = {_R_NODE, _R_OLD_GW, _R_SEQ, _R_TS, _R_EXPIRY, _R_RSSI}

# Confirm payload keys (spec GCP-7.1)
_C_NODE = 1
_C_NEW_GW = 2
_C_SEQ = 3
_C_TS = 4
_C_LINK_EPOCH = 5
_C_LINK_SEQ = 6
_CONFIRM_KEYS = {_C_NODE, _C_NEW_GW, _C_SEQ, _C_TS, _C_LINK_EPOCH, _C_LINK_SEQ}


def _identity(name: str, identity: ReferenceIdentity) -> dict[str, str]:
    return {
        "name": name,
        "seed_hex": identity.seed.hex(),
        "public_key_hex": identity.pubkey.hex(),
        "iid_hex": identity.iid.hex(),
    }


def _build_cose_sign1(
    protected: bytes,
    kid: bytes,
    payload: bytes,
    signer: ReferenceIdentity,
) -> bytes:
    """Build a COSE_Sign1 using RFC 9052 Sig_structure."""
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    digest = hashlib.sha256(sig_structure).digest()
    signature = sign(signer, digest)
    return cbor2.dumps([protected, {4: kid}, payload, signature], canonical=True)


def _request_message(
    name: str,
    description: str,
    *,
    node: ReferenceIdentity = NODE,
    old_gw: ReferenceIdentity = OLD_GW,
    signer: ReferenceIdentity = NEW_GW,
    kid: bytes | None = None,
    seq: int = 1,
    ts: int = NOW,
    expiry: int = NOW + 300,
    rssi: int = -75,
    algorithm: int = ALG,
    mutation: str = "none",
) -> dict[str, object]:
    """Generate a handoff request COSE_Sign1 vector."""
    kid = signer.iid if kid is None else kid
    protected = cbor2.dumps({1: algorithm}, canonical=True)
    payload = cbor2.dumps(
        {
            _R_NODE: node.iid,
            _R_OLD_GW: old_gw.iid,
            _R_SEQ: seq,
            _R_TS: ts,
            _R_EXPIRY: expiry,
            _R_RSSI: rssi,
        },
        canonical=True,
    )

    if mutation == "duplicate_protected":
        # Non-deterministic protected header with duplicate key
        protected = bytes.fromhex("a2013a00010000013a00010000")
    elif mutation == "duplicate_payload":
        # Payload map repeats key 1
        pairs = [
            (1, node.iid),
            (1, node.iid),
            (2, old_gw.iid),
            (3, seq),
            (4, ts),
            (5, expiry),
            (6, rssi),
        ]
        payload = b"\xa7" + b"".join(cbor2.dumps(k) + cbor2.dumps(v) for k, v in pairs)
    elif mutation == "missing_node":
        payload = cbor2.dumps(
            {_R_OLD_GW: old_gw.iid, _R_SEQ: seq, _R_TS: ts, _R_EXPIRY: expiry, _R_RSSI: rssi},
            canonical=True,
        )
    elif mutation == "extra_claim":
        payload = cbor2.dumps(
            {
                _R_NODE: node.iid,
                _R_OLD_GW: old_gw.iid,
                _R_SEQ: seq,
                _R_TS: ts,
                _R_EXPIRY: expiry,
                _R_RSSI: rssi,
                99: 0,  # Unknown claim
            },
            canonical=True,
        )

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    digest = hashlib.sha256(sig_structure).digest()
    signature = sign(signer, digest)
    cose = cbor2.dumps([protected, {4: kid}, payload, signature], canonical=True)

    if mutation == "signature_bit":
        decoded = cbor2.loads(cose)
        damaged = bytearray(decoded[3])
        damaged[-1] ^= 1
        decoded[3] = bytes(damaged)
        cose = cbor2.dumps(decoded, canonical=True)
    elif mutation == "noncanonical_outer":
        cose = b"\x98\x04" + cose[1:]
    elif mutation == "trailing_data":
        cose += b"\x00"
    elif mutation == "malformed_break":
        cose = b"\xff"
    elif mutation == "truncated":
        cose = cose[:16]

    return {
        "name": name,
        "type": "request",
        "description": description,
        "mutation": mutation,
        "signer_name": "new_gw" if signer is NEW_GW else "other_gw",
        "signer_seed_hex": signer.seed.hex(),
        "signer_public_key_hex": signer.pubkey.hex(),
        "signer_iid_hex": signer.iid.hex(),
        "kid_iid_hex": kid.hex(),
        "node_iid_hex": node.iid.hex(),
        "old_gw_iid_hex": old_gw.iid.hex(),
        "seq": seq,
        "ts": ts,
        "expiry": expiry,
        "rssi": rssi,
        "algorithm": algorithm,
        "protected_hex": protected.hex(),
        "payload_hex": payload.hex(),
        "sig_structure_hex": sig_structure.hex(),
        "digest_hex": digest.hex(),
        "signature_hex": signature.hex(),
        "cose_sign1_hex": cose.hex(),
    }


def _confirm_message(
    name: str,
    description: str,
    *,
    node: ReferenceIdentity = NODE,
    new_gw: ReferenceIdentity = NEW_GW,
    signer: ReferenceIdentity = OLD_GW,
    kid: bytes | None = None,
    seq: int = 1,
    ts: int = NOW + 1,
    link_epoch: int = 5,
    link_seq: int = 12345,
    algorithm: int = ALG,
    mutation: str = "none",
) -> dict[str, object]:
    """Generate a handoff confirm COSE_Sign1 vector."""
    kid = signer.iid if kid is None else kid
    protected = cbor2.dumps({1: algorithm}, canonical=True)
    payload = cbor2.dumps(
        {
            _C_NODE: node.iid,
            _C_NEW_GW: new_gw.iid,
            _C_SEQ: seq,
            _C_TS: ts,
            _C_LINK_EPOCH: link_epoch,
            _C_LINK_SEQ: link_seq,
        },
        canonical=True,
    )

    if mutation == "missing_link_epoch":
        payload = cbor2.dumps(
            {_C_NODE: node.iid, _C_NEW_GW: new_gw.iid, _C_SEQ: seq, _C_TS: ts, _C_LINK_SEQ: link_seq},
            canonical=True,
        )
    elif mutation == "link_epoch_overflow":
        payload = cbor2.dumps(
            {
                _C_NODE: node.iid,
                _C_NEW_GW: new_gw.iid,
                _C_SEQ: seq,
                _C_TS: ts,
                _C_LINK_EPOCH: 256,  # 8-bit overflow
                _C_LINK_SEQ: link_seq,
            },
            canonical=True,
        )
    elif mutation == "link_seq_overflow":
        payload = cbor2.dumps(
            {
                _C_NODE: node.iid,
                _C_NEW_GW: new_gw.iid,
                _C_SEQ: seq,
                _C_TS: ts,
                _C_LINK_EPOCH: link_epoch,
                _C_LINK_SEQ: 65536,  # 16-bit overflow
            },
            canonical=True,
        )

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    digest = hashlib.sha256(sig_structure).digest()
    signature = sign(signer, digest)
    cose = cbor2.dumps([protected, {4: kid}, payload, signature], canonical=True)

    if mutation == "signature_bit":
        decoded = cbor2.loads(cose)
        damaged = bytearray(decoded[3])
        damaged[-1] ^= 1
        decoded[3] = bytes(damaged)
        cose = cbor2.dumps(decoded, canonical=True)

    return {
        "name": name,
        "type": "confirm",
        "description": description,
        "mutation": mutation,
        "signer_name": "old_gw" if signer is OLD_GW else "other_gw",
        "signer_seed_hex": signer.seed.hex(),
        "signer_public_key_hex": signer.pubkey.hex(),
        "signer_iid_hex": signer.iid.hex(),
        "kid_iid_hex": kid.hex(),
        "node_iid_hex": node.iid.hex(),
        "new_gw_iid_hex": new_gw.iid.hex(),
        "seq": seq,
        "ts": ts,
        "link_epoch": link_epoch,
        "link_seq": link_seq,
        "algorithm": algorithm,
        "protected_hex": protected.hex(),
        "payload_hex": payload.hex(),
        "sig_structure_hex": sig_structure.hex(),
        "digest_hex": digest.hex(),
        "signature_hex": signature.hex(),
        "cose_sign1_hex": cose.hex(),
    }


def _verification_case(
    name: str,
    message: str,
    *,
    expected_valid: bool,
    expected_denial: str,
    verifier: str = "old_gw",
    seq_floor: int = 0,
    now: int = NOW,
) -> dict[str, object]:
    """Generate a verification test case."""
    return {
        "name": name,
        "message": message,
        "verifier": verifier,
        "seq_floor": seq_floor,
        "now": now,
        "expected_valid": expected_valid,
        "expected_denial": expected_denial,
    }


def document() -> dict[str, object]:
    """Build the complete vector document."""
    messages = [
        # Valid canonical messages
        _request_message("req_valid", "Canonical handoff request from new_gw to old_gw."),
        _request_message("req_seq_2", "Request with sequence number 2.", seq=2),
        _request_message("req_seq_100", "Request with high sequence number.", seq=100),
        _request_message(
            "req_near_expiry",
            "Request expiring exactly at evaluation time.",
            expiry=NOW,
        ),
        _request_message("req_strong_rssi", "Request with strong signal.", rssi=-50),
        _request_message("req_weak_rssi", "Request with weak signal.", rssi=-110),
        # Invalid request mutations
        _request_message(
            "req_wrong_kid",
            "Signed by new_gw but carrying other_gw kid.",
            kid=OTHER_GW.iid,
        ),
        _request_message(
            "req_wrong_signer",
            "Header claims new_gw but signature uses other_gw.",
            signer=OTHER_GW,
            kid=NEW_GW.iid,
        ),
        _request_message(
            "req_wrong_algorithm",
            "Valid signature over unsupported algorithm.",
            algorithm=-65536,
        ),
        _request_message(
            "req_signature_bit",
            "One signature bit is changed.",
            mutation="signature_bit",
        ),
        _request_message(
            "req_noncanonical_outer",
            "Non-shortest outer array encoding.",
            mutation="noncanonical_outer",
        ),
        _request_message(
            "req_trailing_data",
            "Canonical object followed by trailing CBOR.",
            mutation="trailing_data",
        ),
        _request_message(
            "req_duplicate_protected",
            "Protected map repeats the alg label.",
            mutation="duplicate_protected",
        ),
        _request_message(
            "req_duplicate_payload",
            "Payload map repeats node claim 1.",
            mutation="duplicate_payload",
        ),
        _request_message(
            "req_missing_node",
            "Payload omits node claim 1.",
            mutation="missing_node",
        ),
        _request_message(
            "req_extra_claim",
            "Payload contains unassigned claim 99.",
            mutation="extra_claim",
        ),
        _request_message(
            "req_malformed_break",
            "A lone CBOR break byte.",
            mutation="malformed_break",
        ),
        _request_message("req_truncated", "Truncated COSE_Sign1.", mutation="truncated"),
        # Valid confirm messages
        _confirm_message("cfm_valid", "Canonical handoff confirm from old_gw to new_gw."),
        _confirm_message("cfm_seq_2", "Confirm echoing sequence number 2.", seq=2),
        _confirm_message("cfm_high_epoch", "Confirm with high link epoch.", link_epoch=255),
        _confirm_message("cfm_high_seq", "Confirm with high link sequence.", link_seq=65535),
        _confirm_message("cfm_zero_replay", "Confirm with zero replay state.", link_epoch=0, link_seq=0),
        # Invalid confirm mutations
        _confirm_message(
            "cfm_wrong_signer",
            "Confirm signed by wrong gateway.",
            signer=OTHER_GW,
            kid=OLD_GW.iid,
        ),
        _confirm_message(
            "cfm_signature_bit",
            "One signature bit is changed.",
            mutation="signature_bit",
        ),
        _confirm_message(
            "cfm_missing_link_epoch",
            "Payload omits link_epoch claim 5.",
            mutation="missing_link_epoch",
        ),
        _confirm_message(
            "cfm_link_epoch_overflow",
            "link_epoch exceeds 8-bit range.",
            mutation="link_epoch_overflow",
        ),
        _confirm_message(
            "cfm_link_seq_overflow",
            "link_seq exceeds 16-bit range.",
            mutation="link_seq_overflow",
        ),
    ]

    verification_cases = [
        _verification_case(
            "verify_req_valid",
            "req_valid",
            expected_valid=True,
            expected_denial="none",
        ),
        _verification_case(
            "verify_req_expired",
            "req_near_expiry",
            expected_valid=False,
            expected_denial="expired",
        ),
        _verification_case(
            "verify_req_replay",
            "req_valid",
            seq_floor=1,
            expected_valid=False,
            expected_denial="replay",
        ),
        _verification_case(
            "verify_req_seq_2_after_1",
            "req_seq_2",
            seq_floor=1,
            expected_valid=True,
            expected_denial="none",
        ),
        _verification_case(
            "verify_req_wrong_kid",
            "req_wrong_kid",
            expected_valid=False,
            expected_denial="wrong-signer",
        ),
        _verification_case(
            "verify_req_wrong_signer",
            "req_wrong_signer",
            expected_valid=False,
            expected_denial="signature",
        ),
        _verification_case(
            "verify_req_wrong_algorithm",
            "req_wrong_algorithm",
            expected_valid=False,
            expected_denial="algorithm",
        ),
        _verification_case(
            "verify_req_signature_bit",
            "req_signature_bit",
            expected_valid=False,
            expected_denial="signature",
        ),
        _verification_case(
            "verify_req_malformed",
            "req_malformed_break",
            expected_valid=False,
            expected_denial="malformed",
        ),
        _verification_case(
            "verify_cfm_valid",
            "cfm_valid",
            verifier="new_gw",
            expected_valid=True,
            expected_denial="none",
        ),
        _verification_case(
            "verify_cfm_wrong_signer",
            "cfm_wrong_signer",
            verifier="new_gw",
            expected_valid=False,
            expected_denial="signature",
        ),
        _verification_case(
            "verify_cfm_missing_claim",
            "cfm_missing_link_epoch",
            verifier="new_gw",
            expected_valid=False,
            expected_denial="malformed",
        ),
    ]

    return {
        "$schema": "./schema.json",
        "vector_type": "gcp_handoff_cose_sign1",
        "format_version": FORMAT_VERSION,
        "description": (
            "GCP-7.1 Handoff COSE_Sign1 test vectors for spec/08-gateway-coordination.md. "
            "Covers request and confirm messages with Schnorr48-Ed25519 algorithm (-65537), "
            "integer-keyed payloads, and RFC 9052 Sig_structure."
        ),
        "oracle": {
            "basis": "RFC 9052 Sig_structure plus LICHEN spec GCP-7.1",
            "implementation": (
                "independent PyNaCl reference_schnorr48.py; no lichen package imports"
            ),
            "generator_command": "python3 test/vectors/generate_gcp_handoff_cose_sign1.py",
            "freshness_command": "python3 test/vectors/generate_gcp_handoff_cose_sign1.py --check",
        },
        "constants": {
            "algorithm": ALG,
            "protected_hex": "a1013a00010000",  # {1: -65537}
            "evaluation_time": NOW,
            "request_payload_keys": list(_REQUEST_KEYS),
            "confirm_payload_keys": list(_CONFIRM_KEYS),
        },
        "identities": [
            _identity("node", NODE),
            _identity("old_gw", OLD_GW),
            _identity("new_gw", NEW_GW),
            _identity("other_gw", OTHER_GW),
        ],
        "messages": messages,
        "verification_cases": verification_cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    generated = document()
    if args.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    print(
        f"Wrote {len(generated['messages'])} messages and "
        f"{len(generated['verification_cases'])} verification cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
