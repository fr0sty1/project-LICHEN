#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
import re
import sys
from pathlib import Path


def c_ident(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def hex_bytes(value):
    if value == "":
        return b""
    return bytes.fromhex(value)


def read_varint(data, pos):
    value = 0
    shift = 0
    while pos < len(data) and shift < 64:
        byte = data[pos]
        pos += 1
        if shift == 63 and byte & 0x7e:
            raise ValueError("varint overflow")
        value |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            return value, pos
        shift += 7
    raise ValueError("truncated varint")


def parse_from_radio_packet(data):
    pos = 0
    from_id = None
    packet = None
    while pos < len(data):
        key, pos = read_varint(data, pos)
        field = key >> 3
        wire = key & 0x7
        if field == 1 and wire == 0:
            from_id, pos = read_varint(data, pos)
        elif field == 2 and wire == 2:
            n, pos = read_varint(data, pos)
            packet = data[pos:pos + n]
            pos += n
        elif wire == 0:
            _, pos = read_varint(data, pos)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            n, pos = read_varint(data, pos)
            pos += n
        elif wire == 5:
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    if from_id is None or packet is None:
        raise ValueError("FromRadio packet vector lacks id or packet")
    return from_id, packet


CONFIG_SECTION_ENUMS = {
    "device": 0,
    "position": 1,
    "power": 2,
    "network": 3,
    "display": 4,
    "lora": 5,
    "bluetooth": 6,
    "security": 7,
    "device_ui": 8,
}


def bytes_array(name, data):
    if data:
        values = ", ".join(f"0x{byte:02x}" for byte in data)
    else:
        values = "0"
    return f"static const uint8_t {name}[] = {{ {values} }};"


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_H")

    source = Path(sys.argv[1])
    out = Path(sys.argv[2])
    doc = json.loads(source.read_text())
    vectors = doc["vectors"]

    arrays = []
    rows = []

    for vector in vectors:
        name = vector["name"]
        proto = vector["protobuf"]
        message = vector["message"]
        encoded = hex_bytes(vector.get("encoded", ""))
        ident = c_ident(name)

        if proto == "ToRadio" and message == "heartbeat":
            arr = f"v_{ident}_encoded"
            arrays.append(bytes_array(arr, encoded))
            rows.append((name, "MESHTASTIC_VECTOR_TO_HEARTBEAT", arr, len(encoded),
                         "NULL", 0, 0, 0, 0, 0, 0, 0))
        elif proto == "ToRadio" and message == "want_config_id":
            terminal = hex_bytes(vector["expect"]["terminal_from_radio"])
            arr = f"v_{ident}_encoded"
            out_arr = f"v_{ident}_terminal"
            arrays.append(bytes_array(arr, encoded))
            arrays.append(bytes_array(out_arr, terminal))
            rows.append((name, "MESHTASTIC_VECTOR_TO_WANT_CONFIG_ID", arr, len(encoded),
                         out_arr, len(terminal), vector["decoded"]["want_config_id"],
                         0, 0, 0, 0, 0))
        elif proto == "ToRadio" and message.startswith("packet."):
            arr = f"v_{ident}_encoded"
            arrays.append(bytes_array(arr, encoded))
            rows.append((name, "MESHTASTIC_VECTOR_TO_PACKET", arr, len(encoded),
                         "NULL", 0, 0, 0, 0, 0, 0, 0))
        elif proto == "ToRadio" and message == "invalid_stream_framing":
            arr = f"v_{ident}_encoded"
            arrays.append(bytes_array(arr, encoded))
            rows.append((name, "MESHTASTIC_VECTOR_TO_REJECT", arr, len(encoded),
                         "NULL", 0, 0, -22, 0, 0, 0, 0))
        elif proto == "ToRadio" and message == "oversized":
            arr = f"v_{ident}_encoded"
            arrays.append(bytes_array(arr, encoded))
            rows.append((name, "MESHTASTIC_VECTOR_TO_REJECT", arr, len(encoded),
                         "NULL", 0, 0, -90, 0, 0, 0, 0))
        elif proto == "FromRadio" and message == "queueStatus":
            status = vector["decoded"]["queueStatus"]
            arr = f"v_{ident}_encoded"
            arrays.append(bytes_array(arr, encoded))
            rows.append((name, "MESHTASTIC_VECTOR_FROM_QUEUE_STATUS", arr, len(encoded),
                         "NULL", 0, 0, 0, status["res"], status["free"],
                         status["maxlen"], status["mesh_packet_id"]))
        elif proto == "FromRadio" and message == "config":
            payload = hex_bytes(vector["payload"])
            section = CONFIG_SECTION_ENUMS[vector["expect"]["config_section"]["section"]]
            arr = f"v_{ident}_encoded"
            payload_arr = f"v_{ident}_payload"
            arrays.append(bytes_array(arr, encoded))
            arrays.append(bytes_array(payload_arr, payload))
            rows.append((name, "MESHTASTIC_VECTOR_FROM_CONFIG", arr,
                         len(encoded), payload_arr, len(payload), section, 0, 0, 0, 0, 0))
        elif proto == "FromRadio" and message == "moduleConfig":
            payload = hex_bytes(vector["payload"])
            arr = f"v_{ident}_encoded"
            payload_arr = f"v_{ident}_payload"
            arrays.append(bytes_array(arr, encoded))
            arrays.append(bytes_array(payload_arr, payload))
            rows.append((name, "MESHTASTIC_VECTOR_FROM_MODULE_CONFIG", arr,
                         len(encoded), payload_arr, len(payload), 0, 0, 0, 0, 0, 0))
        elif proto == "FromRadio" and message == "region_presets":
            payload = hex_bytes(vector["payload"])
            arr = f"v_{ident}_encoded"
            payload_arr = f"v_{ident}_payload"
            arrays.append(bytes_array(arr, encoded))
            arrays.append(bytes_array(payload_arr, payload))
            rows.append((name, "MESHTASTIC_VECTOR_FROM_REGION_PRESETS", arr,
                         len(encoded), payload_arr, len(payload), 0, 0, 0, 0, 0, 0))
        elif proto == "FromRadio" and message.startswith("packet."):
            from_id, packet = parse_from_radio_packet(encoded)
            arr = f"v_{ident}_encoded"
            packet_arr = f"v_{ident}_packet"
            arrays.append(bytes_array(arr, encoded))
            arrays.append(bytes_array(packet_arr, packet))
            rows.append((name, "MESHTASTIC_VECTOR_FROM_PACKET", arr, len(encoded),
                         packet_arr, len(packet), from_id, 0, 0, 0, 0, 0))

    lines = [
        "/* Generated by lichen/tests/meshtastic_codec/gen_vectors.py. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "",
        "#ifndef LICHEN_TEST_MESHTASTIC_VECTORS_H_",
        "#define LICHEN_TEST_MESHTASTIC_VECTORS_H_",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define MESHTASTIC_VECTOR_SOURCE_COUNT {len(vectors)}U",
        f"#define MESHTASTIC_VECTOR_CODEC_COUNT {len(rows)}U",
        "",
        "enum meshtastic_vector_kind {",
        "\tMESHTASTIC_VECTOR_TO_HEARTBEAT,",
        "\tMESHTASTIC_VECTOR_TO_WANT_CONFIG_ID,",
        "\tMESHTASTIC_VECTOR_TO_PACKET,",
        "\tMESHTASTIC_VECTOR_TO_REJECT,",
        "\tMESHTASTIC_VECTOR_FROM_QUEUE_STATUS,",
        "\tMESHTASTIC_VECTOR_FROM_CONFIG,",
        "\tMESHTASTIC_VECTOR_FROM_MODULE_CONFIG,",
        "\tMESHTASTIC_VECTOR_FROM_REGION_PRESETS,",
        "\tMESHTASTIC_VECTOR_FROM_PACKET,",
        "};",
        "",
        "struct meshtastic_vector {",
        "\tconst char *name;",
        "\tenum meshtastic_vector_kind kind;",
        "\tconst uint8_t *encoded;",
        "\tsize_t encoded_len;",
        "\tconst uint8_t *payload;",
        "\tsize_t payload_len;",
        "\tuint32_t value;",
        "\tint expected_error;",
        "\tuint32_t res;",
        "\tuint32_t free;",
        "\tuint32_t maxlen;",
        "\tuint32_t mesh_packet_id;",
        "};",
        "",
    ]
    lines.extend(arrays)
    lines.extend(["", "static const struct meshtastic_vector meshtastic_vectors[] = {"])
    for row in rows:
        name, kind, arr, arr_len, payload, payload_len, value, err, res, free, maxlen, mesh_id = row
        lines.append(
            f'\t{{ "{name}", {kind}, {arr}, {arr_len}U, {payload}, {payload_len}U, '
            f'{value}U, {err}, {res}U, {free}U, {maxlen}U, {mesh_id}U }},'
        )
    lines.extend(["};", "", "#endif /* LICHEN_TEST_MESHTASTIC_VECTORS_H_ */", ""])
    out.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
