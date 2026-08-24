#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate deterministic DAO Origin Signature conformance vectors."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import NotRequired, TypedDict, Unpack

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

DOMAIN = b"LICHEN-DAO-ORIGIN-v1"
SEED = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
VICTIM_SEED = bytes.fromhex("a5" * 32)
DODAG = bytes.fromhex("fe800000000000000000000000000001")
ALT_DODAG = bytes.fromhex("fe800000000000000000000000000002")
PARENT_1 = DODAG
PARENT_2 = bytes.fromhex("fe800000000000000000000000000002")
OUTPUT = Path(__file__).with_name("dao_origin_signature.json")

IDENTITY = ReferenceIdentity.from_seed(SEED)
PUBLIC_KEY = IDENTITY.pubkey
_REFERENCE_ZERO_DIGEST_SIGNATURE = bytes.fromhex(
    "fab5aa8ec31bc8e238d02e23f857a9d5"
    "eefade1fc5ee40d357a120f89abe6707"
    "7114a106aa3278aacdfa9f6cefe02e02"
)


class _RejectedOverrides(TypedDict):
    description: NotRequired[str | None]
    source: NotRequired[bytes]
    effective_dodag: NotRequired[bytes]
    active_dodag: NotRequired[bytes]
    signature: NotRequired[bytes | None]
    option_length: NotRequired[int]
    signed_override: NotRequired[bytes | None]
    option_offset: NotRequired[int | None]
    key_available: NotRequired[bool]
    previous: NotRequired[dict[str, object] | None]
    envelope_valid: NotRequired[bool]
    signature_valid: NotRequired[bool | None]


class DaoVectorDocument(TypedDict):
    vector_type: str
    format_version: int
    description: str
    oracle_provenance: dict[str, str]
    vectors: list[dict[str, object]]


def native_address(public_key: bytes) -> bytes:
    """Return the canonical key-derived LICHEN/Yggdrasil 02xx address."""
    key_digest = hashlib.sha512(public_key).digest()
    iid = bytearray(key_digest[:8])
    iid[0] &= 0xFD
    return b"\x02" + key_digest[:7] + bytes(iid)


ORIGIN = native_address(PUBLIC_KEY)
ALT_PREFIX_ORIGIN = bytes.fromhex("fe80000000000000") + ORIGIN[8:]
VICTIM_PUBLIC_KEY = ReferenceIdentity.from_seed(VICTIM_SEED).pubkey
VICTIM = native_address(VICTIM_PUBLIC_KEY)


def target(address: bytes, prefix_length: int = 128) -> bytes:
    return bytes([5, 18, 0, prefix_length]) + address


def transit(
    parent: bytes,
    path_sequence: int = 0xF1,
    lifetime: int = 0xFF,
    flags: int = 0x00,  # E=0: current profile advertises self-owned reachability
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
    signature = sign(IDENTITY, message) if signature is None else signature
    option = bytes([0x12, option_length]) + sequence.to_bytes(8, "big") + signature
    return message, option, unsigned + option


def prior(
    source: bytes, sequence: int, signed_dao: bytes, *, route_present: bool = True
) -> dict[str, object]:
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
    previous: dict[str, object] | None = None,
    accepted: bool = True,
    route_changed: bool = True,
    replay_persisted: bool = True,
    envelope_valid: bool = True,
    signature_valid: bool | None = None,
    reason: str = "accepted",
    stage: str = "applied",
) -> dict[str, object]:
    message, option, signed = transcript(
        unsigned, source, effective_dodag, sequence, signature, option_length
    )
    canonical = sign(IDENTITY, message)
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
    name: str,
    coverage: str,
    unsigned: bytes,
    sequence: int,
    reason: str,
    stage: str,
    **kwargs: Unpack[_RejectedOverrides],
) -> dict[str, object]:
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


def generate() -> DaoVectorDocument:
    if (
        bytes.fromhex(
            "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6"
        )
        != PUBLIC_KEY
    ):
        raise AssertionError("independent DAO reference key derivation KAT failed")
    if sign(IDENTITY, bytes(64)) != _REFERENCE_ZERO_DIGEST_SIGNATURE:
        raise AssertionError("independent DAO reference signature KAT failed")
    single = dao(target(ORIGIN), transit(PARENT_1))
    base_digest, base_option, base_signed = transcript(single, ORIGIN, DODAG, 42)
    baseline_signature = base_option[10:]
    prior_42 = prior(ORIGIN, 42, base_signed)
    _, _, signed_43 = transcript(single, ORIGIN, DODAG, 43)
    prior_43 = prior(ORIGIN, 43, signed_43)
    d0 = dao(target(ORIGIN), transit(PARENT_1), d=False)

    vectors: list[dict[str, object]] = [
        vector(
            "valid_d1_self_128",
            "d1",
            single,
            42,
            description="Canonical D=1 self /128 DAO.",
        ),
        vector(
            "valid_d0_self_128",
            "d0_effective_dodag",
            d0,
            43,
            description="Canonical D=0 self /128 DAO using receiver DODAG context.",
        ),
        vector(
            "valid_withdrawal",
            "withdrawal",
            dao(target(ORIGIN), transit(PARENT_1, 0xF2, 0)),
            44,
        ),
        vector(
            "valid_high_byte_sequence", "high_byte_sequence", single, 0x8001020304050607
        ),
        vector(
            "valid_max_u64_sequence",
            "max_u64_sequence",
            single,
            0xFFFFFFFFFFFFFFFF,
            description="Maximum u64 sequence number (2^64-1). MUST NOT wrap to 0.",
        ),
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
        (
            "target",
            "target_mutation",
            dao(target(VICTIM), transit(PARENT_1)),
            ORIGIN,
            DODAG,
        ),
        (
            "parent",
            "parent_mutation",
            dao(target(ORIGIN), transit(PARENT_2)),
            ORIGIN,
            DODAG,
        ),
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
        (
            "option order",
            "order_mutation",
            dao(transit(PARENT_1), target(ORIGIN)),
            ORIGIN,
            DODAG,
        ),
    ]
    for field, coverage, mutated, source, effective_dodag in mutations:
        if coverage == "instance_mutation":
            reason, stage = "instance_mismatch", "context"
        elif coverage == "source_mutation":
            reason, stage = "iid_mismatch", "identity"
        else:
            reason, stage = "invalid_signature", "identity"
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
                "reject_unsupported_transit_e",
                "unsupported_transit_e",
                dao(target(ORIGIN), transit(PARENT_1, flags=0x80)),
                47,
                "unsupported_transit_e",
                "semantic",
                description=(
                    "Transit with E=1 is rejected by the current node-owned /128 profile."
                ),
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
                "iid_mismatch",
                "identity",
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
                "iid_mismatch",
                "identity",
                source=ALT_PREFIX_ORIGIN,
                previous=prior_42,
            ),
            rejected(
                "reject_cross_prefix_lower_sequence",
                "cross_prefix_lower",
                single,
                41,
                "iid_mismatch",
                "identity",
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
                "test/vectors/reference_schnorr48.py (independent PyNaCl/libsodium oracle)"
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


def write_output(document: object) -> None:
    """Durably replace the canonical DAO vector with a complete document."""
    atomic_write_json(OUTPUT, document)


def main(argv: list[str] | None = None) -> int:
    """Generate or byte-check the canonical DAO origin vector document."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    document = generate()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(document):
            print(f"{OUTPUT.name} is not deterministically generated", file=sys.stderr)
            return 1
        print(f"checked {len(document['vectors'])} vectors in {OUTPUT.name}")
    else:
        write_output(document)
        print(f"wrote {len(document['vectors'])} vectors to {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
