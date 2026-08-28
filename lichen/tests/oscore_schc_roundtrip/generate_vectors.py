#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate the C fixture for the shared OSCORE/SCHC vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def array(name: str, value: bytes) -> str:
    body = ", ".join(f"0x{byte:02x}" for byte in value) or "0"
    return f"static const uint8_t {name}[] = {{ {body} }};\n"


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_vectors.py INPUT_JSON OUTPUT_HEADER")
    document = json.loads(Path(sys.argv[1]).read_text())
    output = [
        "/* Generated from test/vectors/oscore_schc_roundtrip.json. */\n",
        "#ifndef OSCORE_SCHC_VECTORS_H\n#define OSCORE_SCHC_VECTORS_H\n",
        "#include <stddef.h>\n#include <stdint.h>\n",
        "struct oscore_schc_vector {\n",
        " const char *name; const uint8_t *secret; const uint8_t *salt;\n",
        " const uint8_t *sender_id; const uint8_t *recipient_id;\n",
        " const uint8_t *plaintext_options; const uint8_t *plaintext_payload;\n",
        " const uint8_t *oscore_option; const uint8_t *ciphertext;\n",
        " const uint8_t *packet; const uint8_t *compressed;\n",
        " size_t salt_len, sender_id_len, recipient_id_len;\n",
        " size_t plaintext_options_len, plaintext_payload_len;\n",
        " size_t oscore_option_len, ciphertext_len, packet_len, compressed_len;\n",
        " uint64_t sender_seq; uint8_t plaintext_code;\n};\n",
    ]
    entries = []
    for index, vector in enumerate(document["vectors"]):
        prefix = f"v{index}"
        values = {
            "secret": bytes.fromhex(vector["master_secret"]),
            "salt": bytes.fromhex(vector["master_salt"]),
            "sender_id": bytes.fromhex(vector["sender_id"]),
            "recipient_id": bytes.fromhex(vector["recipient_id"]),
            "plaintext_options": bytes.fromhex(vector["plaintext"]["options"]),
            "plaintext_payload": bytes.fromhex(vector["plaintext"]["payload"]),
            "oscore_option": bytes.fromhex(vector["oscore_option"]),
            "ciphertext": bytes.fromhex(vector["ciphertext"]),
            "packet": bytes.fromhex(vector["ipv6_packet"]),
            "compressed": bytes.fromhex(vector["schc_rule5"]),
        }
        for key, value in values.items():
            output.append(array(f"{prefix}_{key}", value))
        lengths = {key: len(value) for key, value in values.items()}
        entries.append(
            "{"
            f' .name = "{vector["name"]}",'
            + "".join(f" .{key} = {prefix}_{key}," for key in values)
            + "".join(
                f" .{key}_len = {lengths[key]},"
                for key in (
                    "salt",
                    "sender_id",
                    "recipient_id",
                    "plaintext_options",
                    "plaintext_payload",
                    "oscore_option",
                    "ciphertext",
                    "packet",
                    "compressed",
                )
            )
            + f' .sender_seq = {vector["sender_seq"]}ULL,'
            + f' .plaintext_code = {vector["plaintext"]["code"]}'
            + " }"
        )
    output.append("static const struct oscore_schc_vector oscore_schc_vectors[] = {\n")
    output.extend(f" {entry},\n" for entry in entries)
    output.append("};\n")
    output.append(
        "#define OSCORE_SCHC_VECTOR_COUNT "
        "(sizeof(oscore_schc_vectors) / sizeof(oscore_schc_vectors[0]))\n"
    )
    output.append("#endif\n")
    Path(sys.argv[2]).write_text("".join(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
