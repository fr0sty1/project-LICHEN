#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate the Zephyr range-test fixture directly from the shared JSON oracle."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

KIND_POST = 0
KIND_GET = 1
KIND_TRACEROUTE = 2

KIND_BY_TYPE = {
    "rangetest_post": KIND_POST,
    "rangetest_get": KIND_GET,
    "traceroute": KIND_TRACEROUTE,
}


def _bytes(name: str, wire: bytes | None) -> list[str]:
    if wire is None or len(wire) == 0:
        return [f"#define {name}_len 0U", ""]
    values = ", ".join(f"0x{value:02x}" for value in wire)
    return [
        f"static const uint8_t {name}[] = {{",
        f"  {values}",
        "};",
        f"#define {name}_len sizeof({name})",
        "",
    ]


def _code(code: str) -> tuple[int, int]:
    klass, detail = code.split(".")
    return int(klass), int(detail)


def _hop_arrays(vectors: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for index, vector in enumerate(vectors):
        hops = vector["provider"]["hops"]
        if not hops:
            lines.append(f"#define vec_hops_{index} NULL")
            lines.append(f"#define vec_hops_{index}_len 0U")
            lines.append("")
            continue
        lines.append(f"static const struct lichen_rangetest_hop vec_hops_{index}[] = {{")
        for hop in hops:
            addr = json.dumps(hop["addr"])
            lines.append(
                f"  {{.addr = {addr}, .rssi = {hop['rssi']!r}, "
                f".rtt_ms = {hop['rtt_ms']!r}}},"
            )
        lines.append("};")
        lines.append(f"#define vec_hops_{index}_len ARRAY_SIZE(vec_hops_{index})")
        lines.append("")
    return lines


def _expected_seq(vector: dict[str, Any]) -> int:
    records = vector["expected"].get("records")
    if isinstance(records, list) and len(records) > 1:
        return int(records[1]["2"])
    return 0


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_INC")

    source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    vectors = source["vectors"]
    provider = vectors[0]["provider"]

    for vector in vectors:
        for key in ("rssi", "snr", "sf", "freq"):
            if vector["provider"][key] != provider[key]:
                raise SystemExit(f"{vector['name']}: provider {key} mismatch")
        if vector["provider"]["node_eui64"] != provider["node_eui64"]:
            raise SystemExit(f"{vector['name']}: provider eui64 mismatch")

    lines = [
        "/* Generated from test/vectors/rangetest.json; do not edit. */",
        "",
        f"#define VEC_PROVIDER_EUI64 \"{provider['node_eui64']}\"",
        f"#define VEC_BT {vector_provider_bt(vectors)}U",
        f"#define VEC_RSSI {provider['rssi']!r}",
        f"#define VEC_SNR {provider['snr']!r}",
        f"#define VEC_SF {provider['sf']}U",
        f"#define VEC_FREQ {provider['freq']!r}",
        "",
    ]

    eui = bytes.fromhex(provider["node_eui64"])
    if len(eui) != 8:
        raise SystemExit("provider node_eui64 must be 16 hex digits")
    lines.extend(_bytes("vec_eui64", eui))

    for index, vector in enumerate(vectors):
        body = vector["request"].get("body_hex")
        body_bytes = bytes.fromhex(body) if body else None
        lines.extend(_bytes(f"vec_body_{index}", body_bytes))
        payload = vector["expected"].get("payload_hex")
        payload_bytes = bytes.fromhex(payload) if payload else None
        lines.extend(_bytes(f"vec_payload_{index}", payload_bytes))

    lines.extend(_hop_arrays(vectors))

    lines.extend(
        [
            "struct rangetest_vector {",
            "  const char *name;",
            "  int kind;",
            "  const uint8_t *body;",
            "  size_t body_len;",
            "  uint8_t code_class;",
            "  uint8_t code_detail;",
            "  uint16_t cf;",
            "  const uint8_t *payload;",
            "  size_t payload_len;",
            "  uint32_t expected_seq;",
            "  const struct lichen_rangetest_hop *hops;",
            "  size_t hop_count;",
            "};",
            "",
            "static const struct rangetest_vector rangetest_vectors[] = {",
        ]
    )
    for index, vector in enumerate(vectors):
        code_class, code_detail = _code(vector["expected"]["code"])
        cf = vector["expected"].get("content_format", 0)
        body = vector["request"].get("body_hex")
        lines.append(
            "  {"
            f".name = {json.dumps(vector['name'])}, "
            f".kind = {KIND_BY_TYPE[vector['type']]}, "
            f".body = {'vec_body_%d' % index if body else 'NULL'}, "
            f".body_len = {'vec_body_%d_len' % index if body else '0U'}, "
            f".code_class = {code_class}, "
            f".code_detail = {code_detail}, "
            f".cf = {cf}U, "
            f".payload = {'vec_payload_%d' % index if cf else 'NULL'}, "
            f".payload_len = {'vec_payload_%d_len' % index if cf else '0U'}, "
            f".expected_seq = {_expected_seq(vector)}U, "
            f".hops = vec_hops_{index}, "
            f".hop_count = vec_hops_{index}_len, "
            "},"
        )
    lines.extend(["};", ""])
    Path(sys.argv[2]).write_text("\n".join(lines), encoding="utf-8")


def vector_provider_bt(vectors: list[dict[str, Any]]) -> int:
    values = {vector["now"] for vector in vectors}
    if len(values) != 1:
        raise SystemExit("vectors disagree on 'now'")
    return values.pop()


if __name__ == "__main__":
    main()
