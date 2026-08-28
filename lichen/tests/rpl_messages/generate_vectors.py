#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate the C fixture from test/vectors/rpl_messages.json."""

from __future__ import annotations

import json
import sys
from ipaddress import IPv6Address
from pathlib import Path

KIND = {
    "dio": "RPL_VEC_DIO",
    "dao": "RPL_VEC_DAO",
    "dis": "RPL_VEC_DIS",
    "dao_ack": "RPL_VEC_DAO_ACK",
    "option": "RPL_VEC_OPTION",
}


def c_bytes(data: bytes) -> str:
    if not data:
        return "0x00"
    return ", ".join(f"0x{byte:02x}" for byte in data)


def c_str(value: str | None) -> str:
    if not value:
        return "NULL"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def ipv6_bytes(value: str | None) -> str:
    packed = bytes(16) if not value else IPv6Address(value).packed
    return c_bytes(packed)


def render(document: dict) -> str:
    lines = [
        "/* Generated from test/vectors/rpl_messages.json. Do not edit. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "#ifndef LICHEN_RPL_MESSAGES_VECTORS_H_",
        "#define LICHEN_RPL_MESSAGES_VECTORS_H_",
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "enum rpl_vector_kind {",
        "\tRPL_VEC_DIO = 0,",
        "\tRPL_VEC_DAO,",
        "\tRPL_VEC_DIS,",
        "\tRPL_VEC_DAO_ACK,",
        "\tRPL_VEC_OPTION",
        "};",
        "",
        "struct rpl_message_vector {",
        "\tconst char *name;",
        "\tenum rpl_vector_kind kind;",
        "\tconst uint8_t *encoded;",
        "\tsize_t encoded_len;",
        "\tconst char *expect_error;",
        "\tconst char *schc_version_mode;",
        "\tconst uint8_t *options;",
        "\tsize_t options_len;",
        "\tuint8_t rpl_instance_id;",
        "\tuint8_t version;",
        "\tuint16_t rank;",
        "\tbool grounded;",
        "\tuint8_t mode_of_operation;",
        "\tuint8_t preference;",
        "\tuint8_t dtsn;",
        "\tuint8_t flags;",
        "\tuint8_t reserved;",
        "\tuint8_t dao_sequence;",
        "\tbool ack_requested;",
        "\tuint8_t status;",
        "\tuint8_t option_type;",
        "\tuint8_t prefix_length;",
        "\tuint8_t prefix[16];",
        "\tuint8_t pcs;",
        "\tbool authentication_enabled;",
        "\tbool gateway_centric;",
        "\tuint8_t dio_int_doublings;",
        "\tuint8_t dio_int_min;",
        "\tuint8_t dio_redundancy_const;",
        "\tuint16_t max_rank_increase;",
        "\tuint16_t min_hop_rank_increase;",
        "\tuint16_t ocp;",
        "\tuint8_t default_lifetime;",
        "\tuint16_t lifetime_unit;",
        "\tbool external;",
        "\tuint8_t path_control;",
        "\tuint8_t path_sequence;",
        "\tuint8_t path_lifetime;",
        "\tuint8_t parent_address[16];",
        "\tbool has_dodag_id;",
        "\tuint8_t dodag_id[16];",
        "\tbool has_solicited_information;",
        "\tuint8_t solicited_rpl_instance_id;",
        "\tuint8_t solicited_flags;",
        "\tuint8_t solicited_dodag_id[16];",
        "\tuint8_t solicited_version;",
        "};",
        "",
    ]

    arrays = []
    entries = []
    for index, vector in enumerate(document["vectors"]):
        kind = KIND[vector["type"]]
        encoded = bytes.fromhex(vector.get("encoded", ""))
        options = bytes.fromhex(vector.get("options_hex", ""))
        fields = vector.get("fields") or {}
        solicited = fields.get("solicited_information") or {}
        dodag = fields.get("dodag_id")
        has_dodag = dodag is not None
        enc_name = f"rpl_enc_{index}"
        opt_name = f"rpl_opt_{index}"
        arrays.append(
            f"static const uint8_t {enc_name}[] = {{ {c_bytes(encoded) if encoded else '0x00'} }};"
        )
        arrays.append(
            f"static const uint8_t {opt_name}[] = {{ {c_bytes(options) if options else '0x00'} }};"
        )
        entries.append(
            "\t{\n"
            f"\t\t.name = {c_str(vector['name'])},\n"
            f"\t\t.kind = {kind},\n"
            f"\t\t.encoded = {enc_name},\n"
            f"\t\t.encoded_len = {len(encoded)}U,\n"
            f"\t\t.expect_error = {c_str(vector.get('expect_error'))},\n"
            f"\t\t.schc_version_mode = {c_str(vector.get('schc_version_mode'))},\n"
            f"\t\t.options = {opt_name},\n"
            f"\t\t.options_len = {len(options)}U,\n"
            f"\t\t.rpl_instance_id = {int(fields.get('rpl_instance_id') or 0)}U,\n"
            f"\t\t.version = {int(fields.get('version') or 0)}U,\n"
            f"\t\t.rank = {int(fields.get('rank') or 0)}U,\n"
            f"\t\t.grounded = {'true' if fields.get('grounded') else 'false'},\n"
            f"\t\t.mode_of_operation = {int(fields.get('mode_of_operation') or 0)}U,\n"
            f"\t\t.preference = {int(fields.get('preference') or 0)}U,\n"
            f"\t\t.dtsn = {int(fields.get('dtsn') or 0)}U,\n"
            f"\t\t.flags = {int(fields.get('flags') or 0)}U,\n"
            f"\t\t.reserved = {int(fields.get('reserved') or 0)}U,\n"
            f"\t\t.dao_sequence = {int(fields.get('dao_sequence') or 0)}U,\n"
            f"\t\t.ack_requested = {'true' if fields.get('ack_requested') else 'false'},\n"
            f"\t\t.status = {int(fields.get('status') or 0)}U,\n"
            f"\t\t.option_type = {int(vector.get('option_type') or 0)}U,\n"
            f"\t\t.prefix_length = {int(fields.get('prefix_length') or 0)}U,\n"
            f"\t\t.prefix = {{ {ipv6_bytes(fields.get('prefix'))} }},\n"
            f"\t\t.pcs = {int(fields.get('pcs') or 0)}U,\n"
            f"\t\t.authentication_enabled = {'true' if fields.get('authentication_enabled') else 'false'},\n"
            f"\t\t.gateway_centric = {'true' if fields.get('gateway_centric') else 'false'},\n"
            f"\t\t.dio_int_doublings = {int(fields.get('dio_int_doublings') or 0)}U,\n"
            f"\t\t.dio_int_min = {int(fields.get('dio_int_min') or 0)}U,\n"
            f"\t\t.dio_redundancy_const = {int(fields.get('dio_redundancy_const') or 0)}U,\n"
            f"\t\t.max_rank_increase = {int(fields.get('max_rank_increase') or 0)}U,\n"
            f"\t\t.min_hop_rank_increase = {int(fields.get('min_hop_rank_increase') or 0)}U,\n"
            f"\t\t.ocp = {int(fields.get('ocp') or 0)}U,\n"
            f"\t\t.default_lifetime = {int(fields.get('default_lifetime') or 0)}U,\n"
            f"\t\t.lifetime_unit = {int(fields.get('lifetime_unit') or 0)}U,\n"
            f"\t\t.external = {'true' if fields.get('external') else 'false'},\n"
            f"\t\t.path_control = {int(fields.get('path_control') or 0)}U,\n"
            f"\t\t.path_sequence = {int(fields.get('path_sequence') or 0)}U,\n"
            f"\t\t.path_lifetime = {int(fields.get('path_lifetime') or 0)}U,\n"
            f"\t\t.parent_address = {{ {ipv6_bytes(fields.get('parent_address'))} }},\n"
            f"\t\t.has_dodag_id = {'true' if has_dodag else 'false'},\n"
            f"\t\t.dodag_id = {{ {ipv6_bytes(dodag)} }},\n"
            f"\t\t.has_solicited_information = {'true' if solicited else 'false'},\n"
            f"\t\t.solicited_rpl_instance_id = {int(solicited.get('rpl_instance_id') or 0)}U,\n"
            f"\t\t.solicited_flags = {int(solicited.get('flags') or 0)}U,\n"
            f"\t\t.solicited_dodag_id = {{ {ipv6_bytes(solicited.get('dodag_id'))} }},\n"
            f"\t\t.solicited_version = {int(solicited.get('version') or 0)}U\n"
            "\t}"
        )

    lines.extend(arrays)
    lines.append("")
    lines.append(f"#define RPL_MESSAGE_VECTOR_COUNT {len(document['vectors'])}U")
    lines.append("")
    lines.append("static const struct rpl_message_vector rpl_message_vectors[] = {")
    lines.append(",\n".join(entries))
    lines.append("};")
    lines.append("")
    lines.append("#endif /* LICHEN_RPL_MESSAGES_VECTORS_H_ */")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: generate_vectors.py <rpl_messages.json> <out.h>", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    document = json.loads(src.read_text(encoding="utf-8"))
    if document.get("format_version") != 2:
        raise SystemExit("rpl_messages.json must be format_version 2")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(render(document), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
