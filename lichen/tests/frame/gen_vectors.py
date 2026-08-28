#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate the C frame-codec corpus from canonical JSON vectors."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def c_string(value: str) -> str:
    """Return an ASCII JSON string as a C string literal."""
    return json.dumps(value)


def load_vectors(paths: list[Path]) -> list[dict[str, object]]:
    """Load and minimally validate canonical format-version 2 documents."""
    vectors: list[dict[str, object]] = []
    names: set[str] = set()
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("format_version") != 2 or not isinstance(document.get("vectors"), list):
            raise ValueError(f"{path}: expected format_version 2 vector document")
        for vector in document["vectors"]:
            if not isinstance(vector, dict):
                raise ValueError(f"{path}: vector must be an object")
            name = vector.get("name")
            fields = vector.get("fields")
            encoded = vector.get("encoded")
            if not isinstance(name, str) or not isinstance(fields, dict) or not isinstance(encoded, str):
                raise ValueError(f"{path}: malformed frame vector")
            if name in names:
                raise ValueError(f"duplicate frame vector name: {name}")
            try:
                bytes.fromhex(encoded)
                for key in ("dst_addr", "payload", "mic", "signer_eui64"):
                    bytes.fromhex(fields[key])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"{path}: {name}: invalid hex field") from error
            names.add(name)
            vectors.append(vector)
    return vectors


def expected_parse(vector: dict[str, object]) -> str:
    expect = vector.get("expect", {})
    if not isinstance(expect, dict) or "error" not in expect:
        return "0"
    mapping = {
        "signed_encrypted_unsupported": "-EPROTONOSUPPORT",
        "frame_body_exceeds_254": "-EMSGSIZE",
    }
    error = expect["error"]
    if error not in mapping:
        raise ValueError(f"{vector['name']}: unsupported expected error {error!r}")
    return mapping[error]


def generate(vectors: list[dict[str, object]]) -> str:
    lines = [
        "/* Generated from canonical frame JSON vectors; do not edit. */",
        "#ifndef LICHEN_TEST_FRAME_VECTORS_H_",
        "#define LICHEN_TEST_FRAME_VECTORS_H_",
        "",
        "struct canonical_frame_vector {",
        "\tconst char *name;",
        "\tconst char *encoded_hex;",
        "\tconst char *dst_hex;",
        "\tconst char *signer_hex;",
        "\tconst char *payload_hex;",
        "\tconst char *mic_hex;",
        "\tint expected_parse;",
        "\tuint16_t seqnum;",
        "\tuint8_t epoch;",
        "\tuint8_t addr_mode;",
        "\tuint8_t mic_length;",
        "\tbool signature_present;",
        "\tbool encrypted;",
        "};",
        "",
        "static const struct canonical_frame_vector canonical_frame_vectors[] = {",
    ]
    for vector in vectors:
        fields = vector["fields"]
        assert isinstance(fields, dict)
        lines.extend(
            [
                "\t{",
                f"\t\t.name = {c_string(vector['name'])},",
                f"\t\t.encoded_hex = {c_string(vector['encoded'])},",
                f"\t\t.dst_hex = {c_string(fields['dst_addr'])},",
                f"\t\t.signer_hex = {c_string(fields['signer_eui64'])},",
                f"\t\t.payload_hex = {c_string(fields['payload'])},",
                f"\t\t.mic_hex = {c_string(fields['mic'])},",
                f"\t\t.expected_parse = {expected_parse(vector)},",
                f"\t\t.seqnum = {fields['seqnum']}U,",
                f"\t\t.epoch = {fields['epoch']}U,",
                f"\t\t.addr_mode = {fields['addr_mode']}U,",
                f"\t\t.mic_length = {fields['mic_length']}U,",
                f"\t\t.signature_present = {str(fields['signature_present']).lower()},",
                f"\t\t.encrypted = {str(fields['encrypted']).lower()},",
                "\t},",
            ]
        )
    lines.extend(
        [
            "};",
            "",
            "#define CANONICAL_FRAME_VECTOR_COUNT \\",
            "\t(sizeof(canonical_frame_vectors) / sizeof(canonical_frame_vectors[0]))",
            "",
            "#endif /* LICHEN_TEST_FRAME_VECTORS_H_ */",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("vectors", type=Path, nargs="+")
    args = parser.parse_args()
    args.output.write_text(generate(load_vectors(args.vectors)), encoding="utf-8")


if __name__ == "__main__":
    main()
