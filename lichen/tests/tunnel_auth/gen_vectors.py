#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Translate the canonical tunnel authorization corpus into a C fixture."""

from __future__ import annotations

import json
import sys
from ipaddress import IPv6Address
from pathlib import Path


def array(name: str, value: str) -> str:
    octets = bytes.fromhex(value)
    body = ",".join(f"0x{byte:02x}" for byte in octets)
    return f"static const uint8_t {name}[] = {{{body}}};\n"


DENIAL = {
    "none": "LICHEN_TUNNEL_DENIAL_NONE",
    "malformed": "LICHEN_TUNNEL_DENIAL_MALFORMED",
    "oscore-required": "LICHEN_TUNNEL_DENIAL_OSCORE_REQUIRED",
    "wrong-root": "LICHEN_TUNNEL_DENIAL_WRONG_ROOT",
    "signature": "LICHEN_TUNNEL_DENIAL_SIGNATURE",
    "wrong-egress": "LICHEN_TUNNEL_DENIAL_WRONG_EGRESS",
    "expired": "LICHEN_TUNNEL_DENIAL_EXPIRED",
    "replay": "LICHEN_TUNNEL_DENIAL_REPLAY",
    "revoked": "LICHEN_TUNNEL_DENIAL_REVOKED",
    "clock-regression": "LICHEN_TUNNEL_DENIAL_CLOCK_REGRESSION",
    "algorithm": "LICHEN_TUNNEL_DENIAL_ALGORITHM",
    "wrong-direction": "LICHEN_TUNNEL_DENIAL_WRONG_DIRECTION",
    "invalid-route": "LICHEN_TUNNEL_DENIAL_INVALID_ROUTE",
    "source-scope": "LICHEN_TUNNEL_DENIAL_SOURCE_SCOPE",
    "destination-scope": "LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE",
    "no-authorization": "LICHEN_TUNNEL_DENIAL_NO_AUTHORIZATION",
}


def ident(name: str) -> str:
    return name.replace("-", "_")


def setup_lines(actions: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    for action in actions:
        kind = action["action"]
        if kind == "receive":
            message = ident(str(action["message"]))
            sender = ident(str(action["sender"]))
            lines.append(
                f"z = receive_as(&ctx, wire_{message}, sizeof(wire_{message}), true, "
                f"{sender}_iid, UINT64_C({action['now']})); fixture_assert(z.allowed);"
            )
        elif kind == "revoke":
            message = ident(str(action["message"]))
            lines.append(
                f"fixture_assert(lichen_tunnel_auth_revoke(&ctx, prefix_{message}, prefix_len_{message}, "
                f"route_hash_{message}, UINT64_C({action['through_path_seq']})) == 0);"
            )
        elif kind == "change_root":
            identity = ident(str(action["identity"]))
            lines.append(
                f"fixture_assert(lichen_tunnel_auth_change_root(&ctx, {identity}_iid, {identity}_pubkey) == 0);"
            )
        else:
            raise ValueError(f"unknown setup action {kind}")
    return lines


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    data = json.loads((root / "test/vectors/tunnel_authorization.json").read_text())
    messages = {item["name"]: item for item in data["authorizations"]}
    identities = {item["name"]: item for item in data["identities"]}
    names = tuple(messages)
    out = ["/* Generated from test/vectors/tunnel_authorization.json. */\n"]
    for identity_name in ("root", "other_root", "egress", "other_egress"):
        value = identities[identity_name]
        out += [array(f"{identity_name}_seed", value["seed_hex"]),
                array(f"{identity_name}_pubkey", value["public_key_hex"]),
                array(f"{identity_name}_iid", value["iid_hex"])]
    for name in names:
        safe = ident(name)
        message = messages[name]
        out += [array(f"wire_{safe}", message["cose_sign1_hex"]),
                array(f"prefix_{safe}", message["prefix_hex"]),
                f"static const uint8_t prefix_len_{safe} = {message['prefix_len']};\n",
                array(f"route_hash_{safe}", message["route_hash_hex"]),
                array(f"route_{safe}", "".join(message["route_hops_hex"]))]
    out += ["#define valid_prefix prefix_valid\n",
            "#define valid_route_hash route_hash_valid\n",
            "#define valid_route route_valid\n"]

    out.append("static void run_fixture_post_cases(void)\n{\n")
    out.append("struct lichen_tunnel_auth_ctx ctx; struct lichen_tunnel_result z;\n")
    for case in data["post_cases"]:
        active = ident(case["active_root"])
        sender = ident(case["oscore_sender"])
        message = ident(case["message"])
        expected = case["expected"]
        out.append(f"/* {case['name']} */ ctx = fresh_with({active}_iid, {active}_pubkey);\n")
        out.extend(line + "\n" for line in setup_lines(case["setup"]))
        auth = "true" if case["oscore_authenticated"] else "false"
        out.append(
            f"z = receive_as(&ctx, wire_{message}, sizeof(wire_{message}), {auth}, {sender}_iid, "
            f"UINT64_C({case['now']})); check_result(\"{case['name']}\", z, "
            f"{'true' if expected['allowed'] else 'false'}, {DENIAL[expected['denial']]}, "
            f"{expected['response_code']});\n"
        )
    out.append("}\n")

    out.append("static void run_fixture_decap_cases(void)\n{\n")
    out.append("struct lichen_tunnel_auth_ctx ctx; struct lichen_tunnel_result z;\n")
    for index, case in enumerate(data["decapsulation_cases"]):
        active = ident(case["active_root"])
        route_name = f"decap_route_{index}"
        src_name = f"decap_src_{index}"
        dst_name = f"decap_dst_{index}"
        out.append(array(route_name, "".join(case["route_hops_hex"])))
        out.append(array(src_name, IPv6Address(case["inner_source"]).packed.hex()))
        out.append(array(dst_name, IPv6Address(case["inner_destination"]).packed.hex()))
        out.append(f"/* {case['name']} */ ctx = fresh_with({active}_iid, {active}_pubkey);\n")
        out.extend(line + "\n" for line in setup_lines(case["setup"]))
        direction = ("LICHEN_TUNNEL_MESH_TO_EXTERNAL" if case["direction"] == "mesh-to-external"
                     else "LICHEN_TUNNEL_EXTERNAL_TO_MESH")
        expected = case["expected"]
        out.append(
            f"z = lichen_tunnel_auth_decapsulate(&ctx, {src_name}, {dst_name}, {route_name}, "
            f"sizeof({route_name}) / 8U, {direction}, UINT64_C({case['now']})); "
            f"check_result(\"{case['name']}\", z, {'true' if expected['allowed'] else 'false'}, "
            f"{DENIAL[expected['denial']]}, {expected['response_code']});\n"
        )
    out.append("}\n")
    Path(sys.argv[1]).write_text("".join(out))


if __name__ == "__main__":
    main()
