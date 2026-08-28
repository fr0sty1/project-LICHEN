#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate compact C fixtures from the canonical aiocoap-oracle vectors."""

from __future__ import annotations

import json
import pathlib
import sys


def c_bytes(data: bytes) -> str:
    return ", ".join(f"0x{byte:02x}" for byte in data) or "0x00"


def main() -> None:
    source = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    document = json.loads(source.read_text(encoding="utf-8"))
    vectors = [item for item in document["vectors"] if "encoded" in item]
    lines = [
        "/* Generated from test/vectors/coap_messages.json; do not edit. */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "struct coap_vector {",
        "    const char *name;",
        "    const uint8_t *wire; size_t wire_len;",
        "    uint8_t type; uint8_t code; uint16_t mid;",
        "    const uint8_t *token; size_t token_len;",
        "    const uint8_t *payload; size_t payload_len;",
        "};",
    ]
    for index, vector in enumerate(vectors):
        wire = bytes.fromhex(vector["encoded"])
        token = bytes.fromhex(vector.get("token", ""))
        payload = bytes.fromhex(vector.get("payload_hex", vector.get("payload", "")))
        lines.extend(
            [
                f"static const uint8_t coap_wire_{index}[] = {{ {c_bytes(wire)} }};",
                f"static const uint8_t coap_token_{index}[] = {{ {c_bytes(token)} }};",
                f"static const uint8_t coap_payload_{index}[] = {{ {c_bytes(payload)} }};",
            ]
        )
    lines.append("static const struct coap_vector coap_vectors[] = {")
    for index, vector in enumerate(vectors):
        token = bytes.fromhex(vector.get("token", ""))
        payload = bytes.fromhex(vector.get("payload_hex", vector.get("payload", "")))
        lines.append(
            "    {"
            f' "{vector["name"]}", coap_wire_{index}, sizeof(coap_wire_{index}),'
            f' {vector.get("decoded_mtype", vector["mtype"])}U,'
            f' {vector.get("decoded_code", vector["code"])}U,'
            f' {vector.get("decoded_mid", vector["mid"])}U,'
            f" coap_token_{index}, {len(token)}U,"
            f" coap_payload_{index}, {len(payload)}U"
            " },"
        )
    lines.extend(["};", ""])
    output.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
