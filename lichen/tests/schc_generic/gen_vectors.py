#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
import hashlib
import sys
import zlib
from pathlib import Path

CATEGORIES = {
    "recovery": "SCHC_VECTOR_RECOVERY",
    "window_transition": "SCHC_VECTOR_WINDOW_TRANSITION",
    "controls": "SCHC_VECTOR_CONTROLS",
    "retry_exhaustion": "SCHC_VECTOR_RETRY_EXHAUSTION",
    "capacity": "SCHC_VECTOR_CAPACITY",
    "malformed": "SCHC_VECTOR_MALFORMED",
}

STATUSES = {
    None: "SCHC_VECTOR_STATUS_NONE",
    "ok": "SCHC_VECTOR_STATUS_OK",
    "aborted": "SCHC_VECTOR_STATUS_ABORTED",
    "packet_too_large": "SCHC_VECTOR_STATUS_PACKET_TOO_LARGE",
}

ERRORS = {
    None: "SCHC_VECTOR_ERROR_NONE",
    "regular_tile_length": "SCHC_VECTOR_ERROR_FRAGMENT_LENGTH",
    "nonzero_padding": "SCHC_VECTOR_ERROR_FRAGMENT_PADDING",
    "empty_final_tile": "SCHC_VECTOR_ERROR_FRAGMENT_LENGTH",
    "ack_success_trailing_bits": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
    "malformed_control": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
    "final_window_all0_tile": "SCHC_VECTOR_ERROR_FRAGMENT_FCN",
    "unassigned_bitmap_bit_set": "SCHC_VECTOR_ERROR_ACK_UNASSIGNED",
}

KINDS = {
    "regular": "SCHC_VECTOR_FRAGMENT_REGULAR",
    "all0": "SCHC_VECTOR_FRAGMENT_ALL0",
    "all1": "SCHC_VECTOR_FRAGMENT_ALL1",
}

RETRY_SCENARIOS = {
    "sender_retry_exhaustion": "SCHC_VECTOR_RETRY_SENDER",
    "receiver_retry_exhaustion": "SCHC_VECTOR_RETRY_RECEIVER",
}

MALFORMED_SCENARIOS = {
    "regular_short_tile": ("SCHC_VECTOR_PARSER_FRAGMENT", "regular_tile_length"),
    "regular_nonzero_padding": ("SCHC_VECTOR_PARSER_FRAGMENT", "nonzero_padding"),
    "all1_without_final_tile": ("SCHC_VECTOR_PARSER_FRAGMENT", "empty_final_tile"),
    "ack_success_extra_octet": ("SCHC_VECTOR_PARSER_ACK", "ack_success_trailing_bits"),
    "malformed_control": ("SCHC_VECTOR_PARSER_ACK", "malformed_control"),
    "final_window_all0": ("SCHC_VECTOR_PARSER_FRAGMENT", "final_window_all0_tile"),
    "unassigned_bitmap_bit": ("SCHC_VECTOR_PARSER_ACK", "unassigned_bitmap_bit_set"),
}

COMMON_FIELDS = {"name", "category", "provenance"}
RECOVERY_FIELDS = COMMON_FIELDS | {
    "rule_id",
    "packet",
    "packet_length",
    "packet_sha256",
    "rcs",
    "fragments",
    "loss",
}
RETRY_FIELDS = COMMON_FIELDS | {
    "rule_id",
    "attempts_before",
    "trigger",
    "expected_message",
    "expect_status",
}
CAPACITY_FIELDS = COMMON_FIELDS | {
    "packet",
    "packet_length",
    "packet_sha256",
    "rcs",
    "fragment_count",
    "expect_status",
}
MALFORMED_FIELDS = COMMON_FIELDS | {"wire", "expect_error"}

CANONICAL_SCENARIOS = {
    "recover_missing_regular_tile": "recovery",
    "all0_window_transition": "window_transition",
    "control_messages": "controls",
    "sender_retry_exhaustion": "retry_exhaustion",
    "receiver_retry_exhaustion": "retry_exhaustion",
    "mandatory_receiver_boundary": "capacity",
    "profile_capacity": "capacity",
    "over_profile_capacity": "capacity",
    "regular_short_tile": "malformed",
    "regular_nonzero_padding": "malformed",
    "all1_without_final_tile": "malformed",
    "ack_success_extra_octet": "malformed",
    "malformed_control": "malformed",
    "final_window_all0": "malformed",
    "unassigned_bitmap_bit": "malformed",
}

SCENARIO_FIELDS = {
    "recover_missing_regular_tile": RECOVERY_FIELDS,
    "all0_window_transition": RECOVERY_FIELDS | {"fragment_count"},
    "control_messages": COMMON_FIELDS | {"controls"},
    "sender_retry_exhaustion": RETRY_FIELDS,
    "receiver_retry_exhaustion": RETRY_FIELDS,
    "mandatory_receiver_boundary": CAPACITY_FIELDS,
    "profile_capacity": CAPACITY_FIELDS,
    "over_profile_capacity": CAPACITY_FIELDS - {"rcs"},
    "regular_short_tile": MALFORMED_FIELDS,
    "regular_nonzero_padding": MALFORMED_FIELDS,
    "all1_without_final_tile": MALFORMED_FIELDS,
    "ack_success_extra_octet": MALFORMED_FIELDS,
    "malformed_control": MALFORMED_FIELDS,
    "final_window_all0": MALFORMED_FIELDS,
    "unassigned_bitmap_bit": MALFORMED_FIELDS | {"assigned_fcns"},
}

LOSS_FIELDS = {
    "drop_fragment",
    "ack_failure",
    "retransmission",
    "ack_req",
    "ack_success",
    "corrupt_all1",
    "rcs_failure_ack",
    "next_sender_message",
}

TILE_SIZE = 187
WINDOW_SIZE = 63
MAX_PACKET_SIZE = 23562


def expand(value):
    if isinstance(value, str):
        return bytes.fromhex(value)
    output = bytearray()
    for part in value["parts"]:
        if isinstance(part, str):
            output.extend(bytes.fromhex(part))
        else:
            output.extend(bytes.fromhex(part["repeat_byte"]) * part["count"])
    return bytes(output)


def array(name, data):
    lines = [f"static const uint8_t {name}[] = {{"]
    for offset in range(0, len(data), 16):
        values = ", ".join(f"0x{byte:02x}" for byte in data[offset : offset + 16])
        lines.append(f"\t{values},")
    lines.append("};")
    return "\n".join(lines)


def validate_packet(vector, packet):
    name = vector["name"]
    if "packet_sha256" not in vector:
        raise ValueError(f"{name} packet omits packet_sha256")
    if "packet_length" in vector and len(packet) != vector["packet_length"]:
        raise ValueError(f"{name} packet_length does not match expanded packet")
    if "packet_sha256" in vector:
        digest = hashlib.sha256(packet).hexdigest()
        if digest != vector["packet_sha256"]:
            raise ValueError(f"{name} packet_sha256 mismatch")
    if "rcs" in vector:
        rcs = zlib.crc32(packet + b"\x00").to_bytes(4, "big")
        if rcs != expand(vector["rcs"]):
            raise ValueError(f"{name} RCS mismatch")
    expected_count = 0 if len(packet) > MAX_PACKET_SIZE else (
        len(packet) + TILE_SIZE - 1
    ) // TILE_SIZE
    if "fragment_count" in vector and vector["fragment_count"] != expected_count:
        raise ValueError(f"{name} fragment_count mismatch")


def validate_fragments(vector):
    fragments = vector.get("fragments", [])
    if not fragments:
        return
    name = vector["name"]
    count = vector.get("fragment_count", len(fragments))
    ordinals = [fragment["tile_ordinal"] for fragment in fragments]
    if len(set(ordinals)) != len(ordinals) or set(ordinals) != set(range(count)):
        raise ValueError(f"{name} fragment ordinals are not unique and complete")
    for fragment in fragments:
        if set(fragment) != {"name", "kind", "window", "fcn", "tile_ordinal", "wire"}:
            raise ValueError(f"{name}/{fragment['name']} has unknown or omitted fields")
        ordinal = fragment["tile_ordinal"]
        final = ordinal + 1 == count
        expected_window = ordinal // WINDOW_SIZE
        expected_fcn = 63 if final else 62 - ordinal % WINDOW_SIZE
        expected_kind = "all1" if final else "all0" if expected_fcn == 0 else "regular"
        if fragment["kind"] != expected_kind or fragment["kind"] not in KINDS:
            raise ValueError(f"{name}/{fragment['name']} kind mismatch")
        if fragment["window"] != expected_window or fragment["fcn"] != expected_fcn:
            raise ValueError(f"{name}/{fragment['name']} ordinal metadata mismatch")
        wire = expand(fragment["wire"])
        if len(wire) < 2 or wire[-1] & 1:
            raise ValueError(f"{name}/{fragment['name']} malformed wire")
        if wire[0] != vector["rule_id"]:
            raise ValueError(f"{name}/{fragment['name']} Rule ID mismatch")
        wire_window = wire[1] >> 7
        wire_fcn = (wire[1] >> 1) & 0x3F
        if (wire_window, wire_fcn) != (fragment["window"], fragment["fcn"]):
            raise ValueError(f"{name}/{fragment['name']} wire metadata mismatch")
        expected_len = 2 + (4 if final else 0) + (
            len(expand(vector["packet"])) - ordinal * TILE_SIZE if final else TILE_SIZE
        )
        if len(wire) != expected_len:
            raise ValueError(f"{name}/{fragment['name']} wire length mismatch")
        if final:
            final_len = len(wire) - 6
            if final_len <= 0:
                raise ValueError(f"{name}/{fragment['name']} final tile is empty")
            decoded_rcs = bytes(
                ((wire[1 + i] << 7) | (wire[2 + i] >> 1)) & 0xFF for i in range(4)
            )
            if decoded_rcs != expand(vector["rcs"]):
                raise ValueError(f"{name}/{fragment['name']} encoded RCS mismatch")
            decoded_tile = bytes(
                ((wire[5 + i] << 7) | (wire[6 + i] >> 1)) & 0xFF
                for i in range(final_len)
            )
            packet_tail = expand(vector["packet"])[ordinal * TILE_SIZE :]
            if decoded_tile != packet_tail:
                raise ValueError(f"{name}/{fragment['name']} final tile mismatch")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_H")

    document = json.loads(Path(sys.argv[1]).read_text())
    if set(document) != {"format_version", "description", "vectors"}:
        raise ValueError("document keys must be exactly format_version/description/vectors")
    if document["format_version"] != 1:
        raise ValueError("format_version must be 1")
    if not isinstance(document["description"], str) or not document["description"].strip():
        raise ValueError("description must be nonempty")
    if not isinstance(document["vectors"], list):
        raise ValueError("vectors must be an array")
    byte_rows = []
    scenario_rows = []
    fragment_rows = []
    arrays = []
    scenario_names = set()
    seen_categories = set()
    seen_retry_scenarios = set()
    seen_malformed_scenarios = set()

    for vector in document["vectors"]:
        name = vector["name"]
        if name not in CANONICAL_SCENARIOS:
            raise ValueError(f"unknown or renamed scenario: {name}")
        expected_fields = SCENARIO_FIELDS[name]
        if set(vector) != expected_fields:
            extras = sorted(set(vector) - expected_fields)
            missing = sorted(expected_fields - set(vector))
            raise ValueError(f"{name} field mismatch: extras={extras}, missing={missing}")
        if name in scenario_names:
            raise ValueError(f"duplicate scenario name: {name}")
        scenario_names.add(name)
        category = vector["category"]
        if category != CANONICAL_SCENARIOS[name]:
            raise ValueError(f"{name} category changed")
        if category not in CATEGORIES:
            raise ValueError(f"unknown category in {name}: {category}")
        seen_categories.add(category)
        status = vector.get("expect_status")
        error = vector.get("expect_error")
        if status not in STATUSES:
            raise ValueError(f"unknown status in {name}: {status}")
        if error not in ERRORS:
            raise ValueError(f"unknown error in {name}: {error}")
        parser = "SCHC_VECTOR_PARSER_NONE"
        if category == "malformed":
            if name not in MALFORMED_SCENARIOS:
                raise ValueError(f"unknown malformed scenario: {name}")
            parser, expected_error = MALFORMED_SCENARIOS[name]
            if error != expected_error:
                raise ValueError(f"{name} expect_error changed")
            seen_malformed_scenarios.add(name)
        loss = vector.get("loss", {})
        unknown_loss = set(loss) - LOSS_FIELDS
        if unknown_loss:
            raise ValueError(f"{name} has unhandled loss fields: {unknown_loss}")
        if category in {"recovery", "window_transition"}:
            required_loss = {
                "drop_fragment",
                "ack_failure",
                "retransmission",
                "ack_req",
                "ack_success",
            }
            if not required_loss <= set(loss):
                raise ValueError(f"{name} omits required recovery loss fields")
            optional_recovery = {
                "corrupt_all1",
                "rcs_failure_ack",
                "next_sender_message",
            }
            present_optional = set(loss) & optional_recovery
            if present_optional and present_optional != optional_recovery:
                raise ValueError(f"{name} omits part of the RCS-failure recovery fields")
        if category == "controls":
            controls = vector["controls"]
            required_controls = {
                "ack_success_w0",
                "ack_success_w1",
                "ack_req_w0",
                "ack_req_w1",
                "sender_abort",
                "receiver_abort",
            }
            if set(controls) != {"rule_78", "rule_79"} or any(
                set(values) != required_controls for values in controls.values()
            ):
                raise ValueError(f"{name} control set is incomplete or unknown")
        packet = expand(vector["packet"]) if "packet" in vector else None
        if packet is not None:
            validate_packet(vector, packet)
        validate_fragments(vector)
        retry_role = "SCHC_VECTOR_RETRY_NONE"
        if category == "retry_exhaustion":
            if name not in RETRY_SCENARIOS:
                raise ValueError(f"unknown retry scenario: {name}")
            retry_role = RETRY_SCENARIOS[name]
            seen_retry_scenarios.add(name)
            trigger = expand(vector["trigger"])
            expected = expand(vector["expected_message"])
            rule_id = vector["rule_id"]
            if len(trigger) != 2 or trigger[0] != rule_id or trigger[1] & 0x7F:
                raise ValueError(f"{name} retry trigger is not ACK REQ")
            expected_for_role = (
                bytes((rule_id, 0xFE))
                if retry_role == "SCHC_VECTOR_RETRY_SENDER"
                else bytes((rule_id, 0xFF, 0xFF))
            )
            if expected != expected_for_role:
                raise ValueError(f"{name} expected_message does not match retry role")
        scenario_rows.append(
            (
                name,
                CATEGORIES[category],
                vector["provenance"],
                vector.get("packet_length", 0),
                vector.get("fragment_count", len(vector.get("fragments", []))),
                vector.get("rule_id", 0),
                vector.get("attempts_before", 0),
                STATUSES[status],
                ERRORS[error],
                vector.get("loss", {}).get("drop_fragment"),
                retry_role,
                parser,
            )
        )

        values = []
        if "packet" in vector:
            values.append(("packet", vector["packet"]))
        if "rcs" in vector:
            values.append(("rcs", vector["rcs"]))
        if "trigger" in vector:
            values.append(("trigger", vector["trigger"]))
        if "expected_message" in vector:
            values.append(("expected_message", vector["expected_message"]))
        if "assigned_fcns" in vector:
            values.append(("assigned_fcns", bytes(vector["assigned_fcns"])))
        values.extend(
            (key, value)
            for key, value in vector.get("loss", {}).items()
            if key != "drop_fragment"
        )
        for rule_name, controls in vector.get("controls", {}).items():
            values.extend((f"{rule_name}_{key}", value) for key, value in controls.items())
        if "wire" in vector:
            values.append(("wire", vector["wire"]))

        fragment_names = set()
        for fragment in vector.get("fragments", []):
            if fragment["name"] in fragment_names:
                raise ValueError(f"duplicate fragment name in {name}: {fragment['name']}")
            fragment_names.add(fragment["name"])
            data = expand(fragment["wire"])
            symbol = f"schc_v_{len(arrays)}"
            arrays.append(array(symbol, data))
            fragment_rows.append(
                (
                    name,
                    fragment["name"],
                    KINDS[fragment["kind"]],
                    fragment["window"],
                    fragment["fcn"],
                    fragment["tile_ordinal"],
                    symbol,
                    len(data),
                )
            )

        for field_name, value in values:
            data = value if isinstance(value, bytes) else expand(value)
            symbol = f"schc_v_{len(arrays)}"
            arrays.append(array(symbol, data))
            byte_rows.append((name, field_name, symbol, len(data)))

    if seen_categories != set(CATEGORIES):
        missing = sorted(set(CATEGORIES) - seen_categories)
        raise ValueError(f"vector categories omitted: {', '.join(missing)}")
    if scenario_names != set(CANONICAL_SCENARIOS):
        raise ValueError("canonical scenario set changed")
    if seen_retry_scenarios != set(RETRY_SCENARIOS):
        raise ValueError("retry scenario set changed")
    if seen_malformed_scenarios != set(MALFORMED_SCENARIOS):
        raise ValueError("malformed scenario set changed")

    lines = [
        "/* Generated mechanically from test/vectors/schc_fragmentation.json. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "",
        "#ifndef LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_",
        "#define LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define SCHC_FRAGMENT_VECTOR_SOURCE_COUNT {len(document['vectors'])}U",
        f"#define SCHC_FRAGMENT_BYTE_VECTOR_COUNT {len(byte_rows)}U",
        f"#define SCHC_FRAGMENT_FRAGMENT_VECTOR_COUNT {len(fragment_rows)}U",
        "",
        "enum schc_fragment_vector_category {",
        *(f"\t{value}," for value in CATEGORIES.values()),
        "};",
        "",
        "enum schc_fragment_vector_status {",
        *(f"\t{value}," for value in STATUSES.values()),
        "};",
        "",
        "enum schc_fragment_vector_error {",
        *(f"\t{value}," for value in dict.fromkeys(ERRORS.values())),
        "};",
        "",
        "enum schc_fragment_vector_kind {",
        *(f"\t{value}," for value in KINDS.values()),
        "};",
        "",
        "enum schc_fragment_vector_retry_role {",
        "\tSCHC_VECTOR_RETRY_NONE,",
        "\tSCHC_VECTOR_RETRY_SENDER,",
        "\tSCHC_VECTOR_RETRY_RECEIVER,",
        "};",
        "",
        "enum schc_fragment_vector_parser {",
        "\tSCHC_VECTOR_PARSER_NONE,",
        "\tSCHC_VECTOR_PARSER_FRAGMENT,",
        "\tSCHC_VECTOR_PARSER_ACK,",
        "};",
        "",
        "struct schc_fragment_byte_vector {",
        "\tconst char *scenario;",
        "\tconst char *field;",
        "\tconst uint8_t *data;",
        "\tsize_t len;",
        "};",
        "",
        "struct schc_fragment_scenario_vector {",
        "\tconst char *name;",
        "\tenum schc_fragment_vector_category category;",
        "\tconst char *provenance;",
        "\tsize_t packet_len;",
        "\tsize_t fragment_count;",
        "\tuint8_t rule_id;",
        "\tuint8_t attempts_before;",
        "\tenum schc_fragment_vector_status expect_status;",
        "\tenum schc_fragment_vector_error expect_error;",
        "\tconst char *drop_fragment;",
        "\tenum schc_fragment_vector_retry_role retry_role;",
        "\tenum schc_fragment_vector_parser parser;",
        "};",
        "",
        "struct schc_fragment_fragment_vector {",
        "\tconst char *scenario;",
        "\tconst char *name;",
        "\tenum schc_fragment_vector_kind kind;",
        "\tuint8_t window;",
        "\tuint8_t fcn;",
        "\tsize_t tile_ordinal;",
        "\tconst uint8_t *wire;",
        "\tsize_t wire_len;",
        "};",
        "",
        *arrays,
        "",
        "static const struct schc_fragment_byte_vector schc_fragment_byte_vectors[] = {",
    ]
    lines.extend(
        f"\t{{ {json.dumps(scenario)}, {json.dumps(field)}, "
        f"{symbol}, {length}U }},"
        for scenario, field, symbol, length in byte_rows
    )
    lines.extend(
        [
            "};",
            "",
            "static const struct schc_fragment_scenario_vector "
            "schc_fragment_scenarios[] = {",
        ]
    )
    lines.extend(
        "\t{ "
        f"{json.dumps(name)}, {category}, {json.dumps(provenance)}, "
        f"{packet_len}U, "
        f"{fragment_count}U, {rule_id}U, {attempts_before}U, "
        f"{status}, {error}, "
        f"{json.dumps(drop) if drop else 'NULL'}, {retry_role}, {parser}"
        " },"
        for (
            name,
            category,
            provenance,
            packet_len,
            fragment_count,
            rule_id,
            attempts_before,
            status,
            error,
            drop,
            retry_role,
            parser,
        ) in scenario_rows
    )
    lines.extend(
        [
            "};",
            "",
            "static const struct schc_fragment_fragment_vector "
            "schc_fragment_fragments[] = {",
        ]
    )
    lines.extend(
        "\t{ "
        f"{json.dumps(scenario)}, {json.dumps(name)}, {kind}, "
        f"{window}U, {fcn}U, {tile_ordinal}U, {symbol}, {length}U"
        " },"
        for scenario, name, kind, window, fcn, tile_ordinal, symbol, length in fragment_rows
    )
    lines.extend(["};", "", "#endif /* LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_ */", ""])
    Path(sys.argv[2]).write_text("\n".join(lines))


if __name__ == "__main__":
    main()
