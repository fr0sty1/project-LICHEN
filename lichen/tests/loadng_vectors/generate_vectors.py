#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate C fixtures from loadng.json and loadng_messages.json."""

from __future__ import annotations

import json
import sys
from ipaddress import IPv6Address
from pathlib import Path

KIND = {"rreq": "LOADNG_VEC_RREQ", "rrep": "LOADNG_VEC_RREP", "rerr": "LOADNG_VEC_RERR"}


def c_bytes(data: bytes) -> str:
    if not data:
        return "0x00"
    return ", ".join(f"0x{byte:02x}" for byte in data)


def ipv6_bytes(value: str | None) -> str:
    packed = bytes(16) if not value else IPv6Address(value).packed
    return c_bytes(packed)


def c_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render(seq_doc: dict, msg_doc: dict) -> str:
    lines = [
        "/* Generated from test/vectors/loadng.json and loadng_messages.json. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "#ifndef LICHEN_LOADNG_VECTORS_H_",
        "#define LICHEN_LOADNG_VECTORS_H_",
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "struct loadng_seq_vector {",
        "\tconst char *name;",
        "\tuint16_t a;",
        "\tuint16_t b;",
        "\tbool b_fresher;",
        "};",
        "",
        "enum loadng_msg_kind {",
        "\tLOADNG_VEC_RREQ = 0,",
        "\tLOADNG_VEC_RREP,",
        "\tLOADNG_VEC_RERR",
        "};",
        "",
        "struct loadng_msg_vector {",
        "\tconst char *name;",
        "\tenum loadng_msg_kind kind;",
        "\tconst uint8_t *encoded;",
        "\tsize_t encoded_len;",
        "\tuint8_t flags;",
        "\tuint8_t hop;",
        "\tuint16_t seq_num;",
        "\tuint8_t addr_a[16];",
        "\tuint8_t addr_b[16];",
        "\tuint8_t error_code;",
        "};",
        "",
    ]

    seq_entries = []
    for vector in seq_doc["vectors"]:
        seq_entries.append(
            "\t{ "
            f"{c_str(vector['name'])}, "
            f"{int(vector['a'])}U, "
            f"{int(vector['b'])}U, "
            f"{'true' if vector['b_fresher'] else 'false'} "
            "}"
        )
    lines.append(f"#define LOADNG_SEQ_VECTOR_COUNT {len(seq_doc['vectors'])}U")
    lines.append("static const struct loadng_seq_vector loadng_seq_vectors[] = {")
    lines.append(",\n".join(seq_entries))
    lines.append("};")
    lines.append("")

    arrays = []
    entries = []
    for index, vector in enumerate(msg_doc["vectors"]):
        encoded = bytes.fromhex(vector["encoded"])
        fields = vector["fields"]
        enc_name = f"loadng_enc_{index}"
        arrays.append(f"static const uint8_t {enc_name}[] = {{ {c_bytes(encoded)} }};")
        kind = KIND[vector["type"]]
        hop = int(fields.get("hop_limit", fields.get("hop_count", 0)))
        seq_num = int(fields.get("seq_num", 0))
        if vector["type"] == "rerr":
            addr_a = fields["unreachable"]
            addr_b = None
            error_code = int(fields["error_code"])
        else:
            addr_a = fields["originator"]
            addr_b = fields["destination"]
            error_code = 0
        entries.append(
            "\t{\n"
            f"\t\t.name = {c_str(vector['name'])},\n"
            f"\t\t.kind = {kind},\n"
            f"\t\t.encoded = {enc_name},\n"
            f"\t\t.encoded_len = {len(encoded)}U,\n"
            f"\t\t.flags = {int(fields['flags'])}U,\n"
            f"\t\t.hop = {hop}U,\n"
            f"\t\t.seq_num = {seq_num}U,\n"
            f"\t\t.addr_a = {{ {ipv6_bytes(addr_a)} }},\n"
            f"\t\t.addr_b = {{ {ipv6_bytes(addr_b)} }},\n"
            f"\t\t.error_code = {error_code}U\n"
            "\t}"
        )

    lines.extend(arrays)
    lines.append("")
    lines.append(f"#define LOADNG_MSG_VECTOR_COUNT {len(msg_doc['vectors'])}U")
    lines.append("static const struct loadng_msg_vector loadng_msg_vectors[] = {")
    lines.append(",\n".join(entries))
    lines.append("};")
    lines.append("")
    lines.append("#endif /* LICHEN_LOADNG_VECTORS_H_ */")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: generate_vectors.py <loadng.json> <loadng_messages.json> <out.h>",
            file=sys.stderr,
        )
        return 2
    seq_doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    msg_doc = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    if seq_doc.get("format_version") != 2 or msg_doc.get("format_version") != 2:
        raise SystemExit("LOADng vector files must be format_version 2")
    dst = Path(sys.argv[3])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(render(seq_doc, msg_doc), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
