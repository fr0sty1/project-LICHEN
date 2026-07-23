#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate deterministic DAO Origin Signature conformance vectors."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from lichen.crypto.schnorr48 import derive_keypair, sign

DOMAIN = b"LICHEN-DAO-ORIGIN-v1"
SEED = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
ULA_PREFIX = bytes.fromhex("fd424c494348454e")
DODAG = bytes.fromhex("fe800000000000000000000000000001")
ALT_DODAG = bytes.fromhex("fe800000000000000000000000000002")
PARENT_1 = DODAG
PARENT_2 = bytes.fromhex("fe800000000000000000000000000002")
OUTPUT = Path(__file__).with_name("dao_origin_signature.json")

PRIVATE_KEY, PUBLIC_KEY = derive_keypair(SEED)
IID = bytearray(hashlib.sha256(PUBLIC_KEY).digest()[:8])
IID[0] &= 0xFD
ORIGIN = ULA_PREFIX + bytes(IID)
ALT_PREFIX_ORIGIN = bytes.fromhex("fe80000000000000") + bytes(IID)
VICTIM = ULA_PREFIX + bytes.fromhex("0011223344556677")


def target(address: bytes, prefix_length: int = 128) -> bytes:
    return bytes([5, 18, 0, prefix_length]) + address


def transit(
    parent: bytes,
    path_sequence: int = 0xF1,
    lifetime: int = 0xFF,
    flags: int = 0,
    path_control: int = 0x80,
) -> bytes:
    return bytes([6, 20, flags, path_control, path_sequence, lifetime]) + parent


def dao(
    *options: bytes,
    d: bool = True,
    instance: int = 0,
    dao_sequence: int = 0x2A,
    dodag: bytes = DODAG,
    flags: int = 0,
    reserved: int = 0,
) -> bytes:
    base = bytes([instance, (0x40 if d else 0) | flags, reserved, dao_sequence])
    return base + (dodag if d else b"") + b"".join(options)


def digest(source: bytes, dodag: bytes, sequence: int, unsigned_dao: bytes) -> bytes:
    return hashlib.sha512(
        DOMAIN + source + dodag + sequence.to_bytes(8, "big") + unsigned_dao
    ).digest()


def transcript(
    unsigned: bytes,
    source: bytes,
    dodag: bytes,
    sequence: int,
    signature: bytes | None = None,
    option_length: int = 0x38,
) -> tuple[bytes, bytes, bytes]:
    message = digest(source, dodag, sequence, unsigned)
    signature = sign(PRIVATE_KEY, PUBLIC_KEY, message) if signature is None else signature
    option = bytes([0x12, option_length]) + sequence.to_bytes(8, "big") + signature
    return message, option, unsigned + option


def prior(source: bytes, sequence: int, signed_dao: bytes, *, route_present: bool = True) -> dict:
    return {
        "source_ipv6": source.hex(),
        "sequence": sequence,
        "signed_dao": signed_dao.hex(),
        "route_present": route_present,
    }


def vector(
    name: str,
    coverage: str,
    unsigned: bytes,
    sequence: int,
    *,
    description: str | None = None,
    source: bytes = ORIGIN,
    effective_dodag: bytes = DODAG,
    active_dodag: bytes = DODAG,
    signature: bytes | None = None,
    option_length: int = 0x38,
    signed_override: bytes | None = None,
    option_offset: int | None = None,
    key_available: bool = True,
    previous: dict | None = None,
    accepted: bool = True,
    route_changed: bool = True,
    replay_persisted: bool = True,
    envelope_valid: bool = True,
    signature_valid: bool | None = None,
    reason: str = "accepted",
    stage: str = "applied",
) -> dict:
    message, option, signed = transcript(
        unsigned, source, effective_dodag, sequence, signature, option_length
    )
    canonical = sign(PRIVATE_KEY, PUBLIC_KEY, message)
    return {
        "name": name,
        "description": description or name.replace("_", " ").capitalize() + ".",
        "coverage": coverage,
        "signing_seed": SEED.hex(),
        "public_key": PUBLIC_KEY.hex(),
        "source_ipv6": source.hex(),
        "effective_instance_id": 0,
        "active_dodag_id": active_dodag.hex(),
        "effective_dodag_id": effective_dodag.hex(),
        "sequence": sequence,
        "unsigned_dao": unsigned.hex(),
        "digest": message.hex(),
        "signature_option": option.hex(),
        "option_offset": len(unsigned) if option_offset is None else option_offset,
        "signed_dao": (signed if signed_override is None else signed_override).hex(),
        "key_available": key_available,
        "prior": previous,
        "expected": {
            "accepted": accepted,
            "route_changed": route_changed,
            "replay_persisted": replay_persisted,
            "envelope_valid": envelope_valid,
            "signature_valid": option[10:] == canonical
            if signature_valid is None
            else signature_valid,
            "reason": reason,
            "decision_stage": stage,
        },
    }


def rejected(
    name: str, coverage: str, unsigned: bytes, sequence: int, reason: str, stage: str, **kwargs
) -> dict:
    return vector(
        name,
        coverage,
        unsigned,
        sequence,
        accepted=False,
        route_changed=False,
        replay_persisted=False,
        reason=reason,
        stage=stage,
        **kwargs,
    )


def generate() -> dict:
    single = dao(target(ORIGIN), transit(PARENT_1))
    base_digest, base_option, base_signed = transcript(single, ORIGIN, DODAG, 42)
    baseline_signature = base_option[10:]
    prior_42 = prior(ORIGIN, 42, base_signed)
    _, _, signed_43 = transcript(single, ORIGIN, DODAG, 43)
    prior_43 = prior(ORIGIN, 43, signed_43)
    d0 = dao(target(ORIGIN), transit(PARENT_1), d=False)

    vectors = [
        vector("valid_d1_self_128", "d1", single, 42, description="Canonical D=1 self /128 DAO."),
        vector(
            "valid_d0_self_128",
            "d0_effective_dodag",
            d0,
            43,
            description="Canonical D=0 self /128 DAO using receiver DODAG context.",
        ),
        vector(
            "valid_withdrawal", "withdrawal", dao(target(ORIGIN), transit(PARENT_1, 0xF2, 0)), 44
        ),
        vector("valid_high_byte_sequence", "high_byte_sequence", single, 0x8001020304050607),
    ]

    mutations = [
        ("source", "source_mutation", single, ORIGIN[:7] + b"\x01" + ORIGIN[8:], DODAG),
        (
            "dodag",
            "dodag_mutation",
            dao(target(ORIGIN), transit(PARENT_1), dodag=ALT_DODAG),
            ORIGIN,
            ALT_DODAG,
        ),
        (
            "instance",
            "instance_mutation",
            dao(target(ORIGIN), transit(PARENT_1), instance=1),
            ORIGIN,
            DODAG,
        ),
        (
            "DAOSeq",
            "dao_sequence_mutation",
            dao(target(ORIGIN), transit(PARENT_1), dao_sequence=0x2B),
            ORIGIN,
            DODAG,
        ),
        ("target", "target_mutation", dao(target(VICTIM), transit(PARENT_1)), ORIGIN, DODAG),
        ("parent", "parent_mutation", dao(target(ORIGIN), transit(PARENT_2)), ORIGIN, DODAG),
        (
            "Path Sequence",
            "path_sequence_mutation",
            dao(target(ORIGIN), transit(PARENT_1, 0xF2)),
            ORIGIN,
            DODAG,
        ),
        (
            "lifetime",
            "lifetime_mutation",
            dao(target(ORIGIN), transit(PARENT_1, lifetime=0x40)),
            ORIGIN,
            DODAG,
        ),
        ("option order", "order_mutation", dao(transit(PARENT_1), target(ORIGIN)), ORIGIN, DODAG),
    ]
    for field, coverage, mutated, source, effective_dodag in mutations:
        reason = "instance_mismatch" if coverage == "instance_mutation" else "invalid_signature"
        stage = "context" if coverage == "instance_mutation" else "identity"
        vectors.append(
            rejected(
                f"reject_{coverage}",
                coverage,
                mutated,
                42,
                reason,
                stage,
                description=f"Changing {field} without re-signing is rejected.",
                source=source,
                effective_dodag=effective_dodag,
                active_dodag=effective_dodag,
                signature=baseline_signature,
            )
        )

    vectors.extend(
        [
            rejected(
                "reject_signature_mutation",
                "signature_mutation",
                single,
                42,
                "invalid_signature",
                "identity",
                signature=baseline_signature[:-1] + bytes([baseline_signature[-1] ^ 1]),
            ),
            rejected(
                "reject_duplicate_option",
                "duplicate_option",
                single,
                42,
                "duplicate_option",
                "structural",
                signed_override=base_signed + base_option,
                envelope_valid=False,
            ),
            rejected(
                "reject_nonterminal_option",
                "nonterminal_option",
                single + b"\x00",
                42,
                "nonterminal_option",
                "structural",
                signed_override=single
                + transcript(single + b"\x00", ORIGIN, DODAG, 42)[1]
                + b"\x00",
                option_offset=len(single),
                envelope_valid=False,
            ),
            rejected(
                "reject_unknown_option",
                "unknown_option",
                dao(bytes.fromhex("7e02cafe"), target(ORIGIN), transit(PARENT_1)),
                46,
                "unknown_option",
                "structural",
                envelope_valid=False,
            ),
            rejected(
                "reject_unknown_key",
                "unknown_key",
                single,
                42,
                "unknown_key",
                "identity",
                key_available=False,
            ),
            rejected(
                "reject_iid_mismatch",
                "iid_mismatch",
                single,
                42,
                "iid_mismatch",
                "identity",
                source=ORIGIN[:-1] + bytes([ORIGIN[-1] ^ 1]),
            ),
            vector(
                "accept_identical_retransmission",
                "identical_retransmission",
                single,
                42,
                previous=prior_42,
                accepted=True,
                route_changed=False,
                replay_persisted=False,
                reason="idempotent",
                stage="replay",
            ),
            vector(
                "reconcile_identical_after_crash",
                "reconcile_after_crash",
                single,
                42,
                previous=prior(ORIGIN, 42, base_signed, route_present=False),
                accepted=True,
                route_changed=True,
                replay_persisted=False,
                reason="reconciled",
                stage="semantic",
            ),
            rejected(
                "reject_same_sequence_conflict",
                "same_sequence_conflict",
                dao(target(ORIGIN), transit(PARENT_1, lifetime=0x40)),
                42,
                "sequence_conflict",
                "replay",
                previous=prior_42,
            ),
            rejected(
                "reject_lower_replay",
                "lower_replay",
                single,
                42,
                "replay",
                "replay",
                previous=prior_43,
            ),
            rejected(
                "reject_d0_instance_mismatch",
                "d0_instance_mismatch",
                dao(target(ORIGIN), transit(PARENT_1), d=False, instance=1),
                47,
                "instance_mismatch",
                "context",
            ),
            rejected(
                "reject_d0_effective_dodag_mismatch",
                "d0_dodag_mismatch",
                d0,
                43,
                "invalid_signature",
                "identity",
                signature=transcript(d0, ORIGIN, ALT_DODAG, 43)[1][10:],
            ),
            rejected(
                "reject_active_d1_dodag_mismatch",
                "d1_active_dodag_mismatch",
                dao(target(ORIGIN), transit(PARENT_1), dodag=ALT_DODAG),
                48,
                "dodag_mismatch",
                "context",
                effective_dodag=ALT_DODAG,
                active_dodag=DODAG,
            ),
            rejected(
                "reject_victim_target",
                "target_mismatch",
                dao(target(VICTIM), transit(PARENT_1)),
                48,
                "target_mismatch",
                "semantic",
                previous=prior_42,
            ),
            rejected(
                "reject_fresh_cross_prefix_target",
                "fresh_cross_prefix_target",
                dao(target(ORIGIN), transit(PARENT_1)),
                51,
                "target_mismatch",
                "semantic",
                source=ALT_PREFIX_ORIGIN,
            ),
            rejected(
                "reject_multiple_distinct_targets",
                "multiple_distinct_targets",
                dao(target(ORIGIN), target(VICTIM), transit(PARENT_1)),
                51,
                "multiple_target",
                "semantic",
            ),
            rejected(
                "reject_cross_prefix_equal_sequence",
                "cross_prefix_equal",
                single,
                42,
                "sequence_conflict",
                "replay",
                source=ALT_PREFIX_ORIGIN,
                previous=prior_42,
            ),
            rejected(
                "reject_cross_prefix_lower_sequence",
                "cross_prefix_lower",
                single,
                41,
                "replay",
                "replay",
                source=ALT_PREFIX_ORIGIN,
                previous=prior_42,
            ),
        ]
    )

    # Structural failures retain independent canonical oracle material even when
    # the option is absent.
    zero_digest, zero_option, _ = transcript(single, ORIGIN, DODAG, 0)
    del zero_digest
    malformed_short = bytes.fromhex("004000")
    malformed_dodag = bytes.fromhex("0040002a") + DODAG[:-1]
    vectors.extend(
        [
            rejected(
                "reject_missing_signature",
                "missing_signature",
                single,
                49,
                "missing_signature",
                "structural",
                signed_override=single,
                envelope_valid=False,
            ),
            rejected(
                "reject_zero_sequence",
                "zero_sequence",
                single,
                0,
                "zero_sequence",
                "structural",
                signed_override=single + zero_option,
                envelope_valid=False,
            ),
            rejected(
                "reject_bad_signature_option_length",
                "bad_option_length",
                single,
                49,
                "bad_option_length",
                "structural",
                option_length=0x37,
                envelope_valid=False,
            ),
            rejected(
                "reject_truncated_signature_option",
                "truncated_option",
                single,
                49,
                "truncated",
                "structural",
                signed_override=transcript(single, ORIGIN, DODAG, 49)[2][:-1],
                envelope_valid=False,
            ),
            rejected(
                "reject_malformed_dao_base",
                "malformed_base",
                malformed_short,
                49,
                "malformed_dao",
                "structural",
                signed_override=malformed_short,
                envelope_valid=False,
            ),
            rejected(
                "reject_truncated_dodagid",
                "truncated_dodag",
                malformed_dodag,
                49,
                "malformed_dao",
                "structural",
                signed_override=malformed_dodag,
                envelope_valid=False,
            ),
            rejected(
                "reject_unsupported_dao_flags",
                "unsupported_flags",
                dao(target(ORIGIN), transit(PARENT_1), flags=1),
                49,
                "unsupported_flags",
                "structural",
                envelope_valid=False,
            ),
            rejected(
                "reject_nonzero_reserved",
                "nonzero_reserved",
                dao(target(ORIGIN), transit(PARENT_1), reserved=1),
                49,
                "nonzero_reserved",
                "structural",
                envelope_valid=False,
            ),
        ]
    )

    vectors.extend(
        [
            rejected(
                "reject_missing_target",
                "missing_target",
                dao(transit(PARENT_1)),
                50,
                "missing_target",
                "semantic",
            ),
            rejected(
                "reject_missing_transit",
                "missing_transit",
                dao(target(ORIGIN)),
                50,
                "missing_transit",
                "semantic",
            ),
            rejected(
                "reject_duplicate_target",
                "duplicate_target",
                dao(target(ORIGIN), target(ORIGIN), transit(PARENT_1)),
                50,
                "duplicate_target",
                "semantic",
            ),
            rejected(
                "reject_inconsistent_transit_sequence",
                "inconsistent_transit_sequence",
                dao(target(ORIGIN), transit(PARENT_1, 1), transit(PARENT_2, 2)),
                50,
                "inconsistent_transit",
                "semantic",
            ),
            rejected(
                "reject_inconsistent_transit_lifetime",
                "inconsistent_transit_lifetime",
                dao(target(ORIGIN), transit(PARENT_1, 1, 10), transit(PARENT_2, 1, 11)),
                50,
                "inconsistent_transit",
                "semantic",
            ),
            rejected(
                "reject_external_flag_for_self_128",
                "unsupported_transit_e",
                dao(target(ORIGIN), transit(PARENT_1, flags=0x80)),
                50,
                "unsupported_transit_e",
                "semantic",
            ),
            rejected(
                "replay_precedes_target_mismatch",
                "replay_target_mismatch",
                dao(target(VICTIM), transit(PARENT_1)),
                41,
                "replay",
                "replay",
                previous=prior_42,
            ),
            rejected(
                "replay_precedes_missing_transit",
                "replay_malformed_semantics",
                dao(target(ORIGIN)),
                41,
                "replay",
                "replay",
                previous=prior_42,
            ),
            rejected(
                "replay_precedes_non128_target",
                "replay_non128_target",
                dao(target(ORIGIN, 64), transit(PARENT_1)),
                41,
                "replay",
                "replay",
                previous=prior_42,
            ),
            rejected(
                "structural_precedes_replay",
                "replay_structural",
                single,
                41,
                "duplicate_option",
                "structural",
                previous=prior_42,
                signed_override=transcript(single, ORIGIN, DODAG, 41)[2]
                + transcript(single, ORIGIN, DODAG, 41)[1],
                envelope_valid=False,
            ),
            rejected(
                "wrong_scope_precedes_malformed_option",
                "context_malformed_option",
                dao(target(ORIGIN), transit(PARENT_1), instance=1),
                52,
                "instance_mismatch",
                "context",
                option_length=0x37,
                envelope_valid=False,
            ),
        ]
    )

    return {
        "vector_type": "dao_origin_signature",
        "format_version": 2,
        "description": "Independent shared DAO Origin Signature conformance vectors (v2 schema).",
        "oracle_provenance": {
            "digest": "test/vectors/dao_origin_signature_oracle.c using Monocypher SHA-512",
            "signature_generation": (
                "python/src/lichen/crypto/schnorr48.py (PyNaCl/libsodium), generator only"
            ),
            "signature_cross_check": "test/vectors/dao_origin_signature_oracle.c (Monocypher)",
            "generator_command": (
                "cd python && uv run --extra dev python "
                "../test/vectors/generate_dao_origin_signature.py"
            ),
            "cross_check_command": (
                "cc -std=c11 -O2 -Wall -Wextra -Werror "
                "-DCONFIG_LICHEN_CRYPTO_MONOCYPHER "
                "-Ilichen/subsys/lichen/link/include "
                "-Ilichen/subsys/lichen/crypto "
                "test/vectors/dao_origin_signature_oracle.c "
                "lichen/subsys/lichen/link/schnorr48.c "
                "lichen/subsys/lichen/crypto/monocypher.c "
                "lichen/subsys/lichen/crypto/monocypher-ed25519.c "
                "-o /tmp/dao-origin-oracle && /tmp/dao-origin-oracle "
                "test/vectors/dao_origin_signature.json"
            ),
        },
        "vectors": vectors,
    }


if __name__ == "__main__":
    document = generate()
    if sys.argv[1:] == ["--check"]:
        if json.loads(OUTPUT.read_text()) != document:
            raise SystemExit(f"{OUTPUT.name} is not deterministically generated")
        print(f"checked {len(document['vectors'])} vectors in {OUTPUT.name}")
    elif not sys.argv[1:]:
        OUTPUT.write_text(json.dumps(document, indent=2) + "\n")
        print(f"wrote {len(document['vectors'])} vectors to {OUTPUT.name}")
    else:
        raise SystemExit("usage: generate_dao_origin_signature.py [--check]")
