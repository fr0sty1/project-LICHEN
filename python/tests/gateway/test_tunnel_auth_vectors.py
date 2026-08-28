# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the independent cross-language tunnel-authorization corpus."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from ipaddress import IPv6Address, IPv6Network
from pathlib import Path

import cbor2
from jsonschema import Draft7Validator, FormatChecker  # type: ignore[import-untyped]

from lichen.crypto.identity import Identity
from lichen.gateway.tunnel_auth import (
    TunnelAuthorizationTable,
    TunnelDirection,
    compute_route_hash,
)
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader

ROOT = Path(__file__).parents[3]
VECTORS = ROOT / "test" / "vectors"
FIXTURE = VECTORS / "tunnel_authorization.json"
SCHEMA = VECTORS / "tunnel_authorization.schema.json"

sys.path.insert(0, str(VECTORS))
from reference_schnorr48 import (  # type: ignore[import-not-found] # noqa: E402, I001
    ReferenceIdentity,
    verify as reference_verify,
)


def _load() -> dict[str, object]:
    value = json.loads(FIXTURE.read_bytes())
    assert isinstance(value, dict)
    return value


def _by_name(items: object) -> dict[str, dict[str, object]]:
    assert isinstance(items, list)
    result: dict[str, dict[str, object]] = {}
    for item in items:
        assert isinstance(item, dict)
        name = item["name"]
        assert isinstance(name, str) and name not in result
        result[name] = item
    return result


def _identity(item: dict[str, object]) -> Identity:
    seed = item["seed_hex"]
    assert isinstance(seed, str)
    identity = Identity.from_seed(bytes.fromhex(seed))
    assert identity.pubkey.hex() == item["public_key_hex"]
    assert identity.iid.hex() == item["iid_hex"]
    assert identity.ygg_addr.hex() == item["address_hex"]
    return identity


def _state(
    document: dict[str, object], active_root: str
) -> tuple[
    TunnelAuthorizationTable,
    dict[str, Identity],
    dict[str, dict[str, object]],
]:
    identity_items = _by_name(document["identities"])
    identities = {name: _identity(item) for name, item in identity_items.items()}
    table = TunnelAuthorizationTable(
        egress_iid=identities["egress"].iid,
        root_iid=identities[active_root].iid,
        root_pubkey=identities[active_root].pubkey,
    )
    return table, identities, _by_name(document["authorizations"])


def _network(message: dict[str, object]) -> IPv6Network:
    prefix = message["prefix_hex"]
    prefix_len = message["prefix_len"]
    assert isinstance(prefix, str) and isinstance(prefix_len, int)
    return IPv6Network((IPv6Address(bytes.fromhex(prefix)), prefix_len), strict=True)


def _apply_setup(
    table: TunnelAuthorizationTable,
    setup: object,
    identities: dict[str, Identity],
    messages: dict[str, dict[str, object]],
) -> None:
    assert isinstance(setup, list)
    for action in setup:
        assert isinstance(action, dict)
        kind = action["action"]
        if kind == "receive":
            message = messages[str(action["message"])]
            sender = identities[str(action["sender"])]
            body = message["cose_sign1_hex"]
            assert isinstance(body, str) and isinstance(action["now"], int)
            result = table.receive_post(
                bytes.fromhex(body),
                oscore_authenticated=True,
                oscore_sender_iid=sender.iid,
                now=action["now"],
            )
            assert result.allowed, f"setup receive unexpectedly denied: {result.denial}"
        elif kind == "revoke":
            message = messages[str(action["message"])]
            route_hash = message["route_hash_hex"]
            assert isinstance(route_hash, str) and isinstance(action["through_path_seq"], int)
            table.revoke(_network(message), bytes.fromhex(route_hash), action["through_path_seq"])
        elif kind == "change_root":
            identity = identities[str(action["identity"])]
            table.change_root(identity.iid, identity.pubkey)
        else:
            raise AssertionError(f"unknown setup action {kind!r}")


def test_tunnel_authorization_schema_and_required_coverage() -> None:
    document = _load()
    schema = json.loads(SCHEMA.read_bytes())
    errors = sorted(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.path),
    )
    assert not errors, "\n".join(error.message for error in errors)
    post_names = set(_by_name(document["post_cases"]))
    assert {
        "valid_root_egress",
        "oscore_required",
        "wrong_oscore_root",
        "wrong_kid",
        "wrong_signing_key",
        "wrong_egress",
        "expired",
        "replay_equal",
        "revoked_floor",
        "fresh_after_revoke",
        "clock_rollback",
        "old_root_after_rotation",
        "new_root_after_rotation",
        "wrong_algorithm",
        "signature_bit",
        "noncanonical_outer",
        "trailing_data",
        "duplicate_protected",
        "duplicate_payload",
        "prefix_73_bad_tail",
        "accept_prefix_0",
        "accept_prefix_73",
        "accept_prefix_128",
    } <= post_names
    decap_names = set(_by_name(document["decapsulation_cases"]))
    assert {
        "valid_first_address",
        "valid_last_address",
        "source_outside_prefix",
        "wrong_route_hash",
        "wrong_direction",
        "mesh_destination",
        "multicast_destination",
        "missing_authorization",
        "expired_at_boundary",
        "revoked_authorization",
        "root_rotation_clears_table",
        "link_local_source_rejected",
        "looped_route",
    } <= decap_names


def test_tunnel_authorization_generator_is_fresh() -> None:
    result = subprocess.run(
        [sys.executable, str(VECTORS / "generate_tunnel_authorization.py"), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_authorization_intermediates_use_independent_oracle() -> None:
    document = _load()
    messages = _by_name(document["authorizations"])
    valid = messages["valid"]
    assert valid["protected_hex"] == "a1013a00010000"
    assert cbor2.loads(bytes.fromhex(str(valid["protected_hex"]))) == {1: -65537}
    assert str(valid["cose_sign1_hex"]).startswith("8447a1013a00010000")

    for message in messages.values():
        route_hops = message["route_hops_hex"]
        assert isinstance(route_hops, list) and all(isinstance(hop, str) for hop in route_hops)
        route = [bytes.fromhex(hop) for hop in route_hops]
        assert compute_route_hash(route).hex() == message["route_hash_hex"]
        prefix_len = message["prefix_len"]
        assert isinstance(prefix_len, int)
        expected_target_octets = (prefix_len + 7) // 8
        assert len(bytes.fromhex(str(message["target_bytes_hex"]))) == expected_target_octets
        structure = bytes.fromhex(str(message["sig_structure_hex"]))
        digest = hashlib.sha256(structure).digest()
        assert digest.hex() == message["digest_hex"]
        identity = ReferenceIdentity.from_seed(bytes.fromhex(str(message["root_seed_hex"])))
        assert identity.pubkey.hex() == message["root_public_key_hex"]
        assert reference_verify(
            identity.pubkey, digest, bytes.fromhex(str(message["signature_hex"]))
        )


def test_post_cases_drive_python_production_path() -> None:
    document = _load()
    cases = _by_name(document["post_cases"])
    for case in cases.values():
        table, identities, messages = _state(document, str(case["active_root"]))
        _apply_setup(table, case["setup"], identities, messages)
        message = messages[str(case["message"])]
        body = message["cose_sign1_hex"]
        assert isinstance(body, str) and isinstance(case["now"], int)
        sender = identities[str(case["oscore_sender"])]
        result = table.receive_post(
            bytes.fromhex(body),
            oscore_authenticated=case["oscore_authenticated"] is True,
            oscore_sender_iid=sender.iid,
            now=case["now"],
        )
        expected = case["expected"]
        assert isinstance(expected, dict)
        assert result.allowed is expected["allowed"], case["name"]
        assert result.denial.value == expected["denial"], case["name"]
        assert result.response_code == expected["response_code"], case["name"]


def test_decapsulation_cases_drive_python_gateway_policy() -> None:
    document = _load()
    cases = _by_name(document["decapsulation_cases"])
    for case in cases.values():
        table, identities, messages = _state(document, str(case["active_root"]))
        _apply_setup(table, case["setup"], identities, messages)
        packet = IPv6Packet(
            IPv6Header(
                src_addr=IPv6Address(str(case["inner_source"])),
                dst_addr=IPv6Address(str(case["inner_destination"])),
                next_header=NextHeader.UDP,
            ),
            b"vector",
        )
        route_hops = case["route_hops_hex"]
        assert isinstance(route_hops, list) and all(isinstance(hop, str) for hop in route_hops)
        route = [bytes.fromhex(hop) for hop in route_hops]
        assert isinstance(case["now"], int)
        result = table.authorize_decapsulation(
            packet,
            route,
            direction=TunnelDirection(str(case["direction"])),
            now=case["now"],
        )
        expected = case["expected"]
        assert isinstance(expected, dict)
        assert result.allowed is expected["allowed"], case["name"]
        assert result.denial.value == expected["denial"], case["name"]
        assert result.response_code == expected["response_code"], case["name"]
