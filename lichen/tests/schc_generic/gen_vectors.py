#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
import hashlib
import re
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
    "sender_abort_trailing_octet": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
    "receiver_abort_non_ff_padding": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
    "receiver_abort_trailing_octet": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
    "unsupported_rule": "SCHC_VECTOR_ERROR_ACK_MALFORMED",
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
    "sender_abort_trailing_octet": (
        "SCHC_VECTOR_PARSER_ACK",
        "sender_abort_trailing_octet",
    ),
    "receiver_abort_non_ff_padding": (
        "SCHC_VECTOR_PARSER_ACK",
        "receiver_abort_non_ff_padding",
    ),
    "receiver_abort_trailing_octet": (
        "SCHC_VECTOR_PARSER_ACK",
        "receiver_abort_trailing_octet",
    ),
    "unsupported_rule_sender_abort": ("SCHC_VECTOR_PARSER_ACK", "unsupported_rule"),
    "unsupported_rule_receiver_abort": (
        "SCHC_VECTOR_PARSER_ACK",
        "unsupported_rule",
    ),
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
SENDER_RETRY_FIELDS = COMMON_FIELDS | {
    "rule_id",
    "attempts_before",
    "retransmission_timeout_s",
    "timer_policy",
    "timer_start_s",
    "timer_deadlines_s",
    "max_ack_requests",
    "inactivity_timeout_s",
    "bitmap_one_means",
    "trigger_event",
    "pre_exhaustion_message",
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
    "sender_abort_trailing_octet": "malformed",
    "receiver_abort_non_ff_padding": "malformed",
    "receiver_abort_trailing_octet": "malformed",
    "unsupported_rule_sender_abort": "malformed",
    "unsupported_rule_receiver_abort": "malformed",
    "final_window_all0": "malformed",
    "unassigned_bitmap_bit": "malformed",
}

SCENARIO_FIELDS = {
    "recover_missing_regular_tile": RECOVERY_FIELDS,
    "all0_window_transition": RECOVERY_FIELDS | {"fragment_count"},
    "control_messages": COMMON_FIELDS | {"controls"},
    "sender_retry_exhaustion": SENDER_RETRY_FIELDS,
    "receiver_retry_exhaustion": RETRY_FIELDS,
    "mandatory_receiver_boundary": CAPACITY_FIELDS,
    "profile_capacity": CAPACITY_FIELDS,
    "over_profile_capacity": CAPACITY_FIELDS - {"rcs"},
    "regular_short_tile": MALFORMED_FIELDS,
    "regular_nonzero_padding": MALFORMED_FIELDS,
    "all1_without_final_tile": MALFORMED_FIELDS,
    "ack_success_extra_octet": MALFORMED_FIELDS,
    "malformed_control": MALFORMED_FIELDS,
    "sender_abort_trailing_octet": MALFORMED_FIELDS,
    "receiver_abort_non_ff_padding": MALFORMED_FIELDS,
    "receiver_abort_trailing_octet": MALFORMED_FIELDS,
    "unsupported_rule_sender_abort": MALFORMED_FIELDS,
    "unsupported_rule_receiver_abort": MALFORMED_FIELDS,
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

TILE_SIZE = 179
WINDOW_SIZE = 63
MAX_PACKET_SIZE = 22554
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")


def require_mapping(value, fields, context):
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    actual = set(value)
    if actual != fields:
        extras = sorted(actual - fields)
        missing = sorted(fields - actual)
        raise ValueError(f"{context} field mismatch: extras={extras}, missing={missing}")


def require_string(value, context):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a nonempty string")


def require_int(value, minimum, maximum, context):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{context} must be in [{minimum}, {maximum}]")


def decode_hex(value, context):
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise ValueError(f"{context} must be nonempty even-length hexadecimal")
    return bytes.fromhex(value)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key: {key}")
        result[key] = value
    return result


def expand(value, context="encoded bytes"):
    if isinstance(value, str):
        return decode_hex(value, context)
    require_mapping(value, {"parts"}, context)
    if not isinstance(value["parts"], list) or not value["parts"]:
        raise ValueError(f"{context}.parts must be a nonempty array")
    output = bytearray()
    for index, part in enumerate(value["parts"]):
        part_context = f"{context}.parts[{index}]"
        if isinstance(part, str):
            output.extend(decode_hex(part, part_context))
        else:
            require_mapping(part, {"repeat_byte", "count"}, part_context)
            repeated = decode_hex(part["repeat_byte"], f"{part_context}.repeat_byte")
            if len(repeated) != 1:
                raise ValueError(f"{part_context}.repeat_byte must encode one byte")
            require_int(part["count"], 1, MAX_PACKET_SIZE + 1, f"{part_context}.count")
            output.extend(repeated * part["count"])
        if len(output) > MAX_PACKET_SIZE + TILE_SIZE:
            raise ValueError(f"{context} expands beyond the bounded vector limit")
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
    if not packet:
        raise ValueError(f"{name} packet must be nonempty")
    require_int(vector["packet_length"], 1, MAX_PACKET_SIZE + 1, f"{name}.packet_length")
    if len(packet) != vector["packet_length"]:
        raise ValueError(f"{name} packet_length does not match expanded packet")
    digest_value = vector["packet_sha256"]
    if not isinstance(digest_value, str) or re.fullmatch(r"[0-9a-f]{64}", digest_value) is None:
        raise ValueError(f"{name}.packet_sha256 must be 64 lowercase hex digits")
    digest = hashlib.sha256(packet).hexdigest()
    if digest != digest_value:
        raise ValueError(f"{name} packet_sha256 mismatch")
    if "rcs" in vector:
        encoded_rcs = expand(vector["rcs"], f"{name}.rcs")
        if len(encoded_rcs) != 4:
            raise ValueError(f"{name}.rcs must encode exactly four bytes")
        rcs = zlib.crc32(packet + b"\x00").to_bytes(4, "big")
        if rcs != encoded_rcs:
            raise ValueError(f"{name} RCS mismatch")
    expected_count = 0 if len(packet) > MAX_PACKET_SIZE else (
        len(packet) + TILE_SIZE - 1
    ) // TILE_SIZE
    if "fragment_count" in vector:
        require_int(vector["fragment_count"], 0, 126, f"{name}.fragment_count")
        if vector["fragment_count"] != expected_count:
            raise ValueError(f"{name} fragment_count mismatch")


def validate_fragments(vector):
    fragments = vector.get("fragments", [])
    if not fragments:
        return
    name = vector["name"]
    if not isinstance(fragments, list):
        raise ValueError(f"{name}.fragments must be an array")
    count = vector.get("fragment_count", len(fragments))
    require_int(count, 1, 126, f"{name}.fragment_count")
    for index, fragment in enumerate(fragments):
        require_mapping(
            fragment,
            {"name", "kind", "window", "fcn", "tile_ordinal", "wire"},
            f"{name}.fragments[{index}]",
        )
        require_string(fragment["name"], f"{name}.fragments[{index}].name")
        require_int(fragment["window"], 0, 1, f"{name}/{fragment['name']}.window")
        require_int(fragment["fcn"], 0, 63, f"{name}/{fragment['name']}.fcn")
        require_int(fragment["tile_ordinal"], 0, 125, f"{name}/{fragment['name']}.tile_ordinal")
    ordinals = [fragment["tile_ordinal"] for fragment in fragments]
    if len(set(ordinals)) != len(ordinals) or set(ordinals) != set(range(count)):
        raise ValueError(f"{name} fragment ordinals are not unique and complete")
    for fragment in fragments:
        ordinal = fragment["tile_ordinal"]
        final = ordinal + 1 == count
        expected_window = ordinal // WINDOW_SIZE
        expected_fcn = 63 if final else 62 - ordinal % WINDOW_SIZE
        expected_kind = "all1" if final else "all0" if expected_fcn == 0 else "regular"
        if fragment["kind"] != expected_kind or fragment["kind"] not in KINDS:
            raise ValueError(f"{name}/{fragment['name']} kind mismatch")
        if fragment["window"] != expected_window or fragment["fcn"] != expected_fcn:
            raise ValueError(f"{name}/{fragment['name']} ordinal metadata mismatch")
        wire = expand(fragment["wire"], f"{name}/{fragment['name']}.wire")
        if len(wire) < 2 or wire[-1] & 1:
            raise ValueError(f"{name}/{fragment['name']} malformed wire")
        if wire[0] != vector["rule_id"]:
            raise ValueError(f"{name}/{fragment['name']} Rule ID mismatch")
        wire_window = wire[1] >> 7
        wire_fcn = (wire[1] >> 1) & 0x3F
        if (wire_window, wire_fcn) != (fragment["window"], fragment["fcn"]):
            raise ValueError(f"{name}/{fragment['name']} wire metadata mismatch")
        expected_len = 2 + (4 if final else 0) + (
            len(expand(vector["packet"], f"{name}.packet")) - ordinal * TILE_SIZE
            if final
            else TILE_SIZE
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
            if decoded_rcs != expand(vector["rcs"], f"{name}.rcs"):
                raise ValueError(f"{name}/{fragment['name']} encoded RCS mismatch")
            decoded_tile = bytes(
                ((wire[5 + i] << 7) | (wire[6 + i] >> 1)) & 0xFF
                for i in range(final_len)
            )
            packet_tail = expand(vector["packet"], f"{name}.packet")[
                ordinal * TILE_SIZE :
            ]
            if decoded_tile != packet_tail:
                raise ValueError(f"{name}/{fragment['name']} final tile mismatch")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_H")

    document = json.loads(
        Path(sys.argv[1]).read_text(), object_pairs_hook=reject_duplicate_keys
    )
    require_mapping(
        document,
        {"format_version", "description", "vectors"},
        "document",
    )
    require_int(document["format_version"], 2, 2, "format_version")
    require_string(document["description"], "description")
    if not isinstance(document["vectors"], list) or not document["vectors"]:
        raise ValueError("vectors must be a nonempty array")
    byte_rows = []
    scenario_rows = []
    fragment_rows = []
    arrays = []
    scenario_names = set()
    seen_categories = set()
    seen_retry_scenarios = set()
    seen_malformed_scenarios = set()

    for index, vector in enumerate(document["vectors"]):
        if not isinstance(vector, dict):
            raise ValueError(f"vectors[{index}] must be an object")
        if "name" not in vector:
            raise ValueError(f"vectors[{index}] omits name")
        name = vector["name"]
        require_string(name, f"vectors[{index}].name")
        if name not in CANONICAL_SCENARIOS:
            raise ValueError(f"unknown or renamed scenario: {name}")
        expected_fields = SCENARIO_FIELDS[name]
        require_mapping(vector, expected_fields, name)
        if name in scenario_names:
            raise ValueError(f"duplicate scenario name: {name}")
        scenario_names.add(name)
        category = vector["category"]
        require_string(category, f"{name}.category")
        require_string(vector["provenance"], f"{name}.provenance")
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
        if "rule_id" in vector:
            require_int(vector["rule_id"], 0, 255, f"{name}.rule_id")
            if vector["rule_id"] not in (0x78, 0x79):
                raise ValueError(f"{name}.rule_id is outside the fixed profile")
        packet = expand(vector["packet"], f"{name}.packet") if "packet" in vector else None
        if packet is not None:
            validate_packet(vector, packet)
        validate_fragments(vector)
        parser = "SCHC_VECTOR_PARSER_NONE"
        if category == "malformed":
            if name not in MALFORMED_SCENARIOS:
                raise ValueError(f"unknown malformed scenario: {name}")
            parser, expected_error = MALFORMED_SCENARIOS[name]
            if error != expected_error:
                raise ValueError(f"{name} expect_error changed")
            seen_malformed_scenarios.add(name)
        loss = vector.get("loss", {})
        if not isinstance(loss, dict):
            raise ValueError(f"{name}.loss must be an object")
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
            require_string(loss["drop_fragment"], f"{name}.loss.drop_fragment")
            fragment_names = {fragment["name"] for fragment in vector["fragments"]}
            if loss["drop_fragment"] not in fragment_names:
                raise ValueError(f"{name}.loss.drop_fragment names no fragment")
            for field_name, encoded in loss.items():
                if field_name != "drop_fragment":
                    expand(encoded, f"{name}.loss.{field_name}")
            dropped = next(
                fragment
                for fragment in vector["fragments"]
                if fragment["name"] == loss["drop_fragment"]
            )
            if expand(loss["retransmission"], f"{name}.loss.retransmission") != expand(
                dropped["wire"], f"{name}/{dropped['name']}.wire"
            ):
                raise ValueError(f"{name}.loss.retransmission differs from dropped fragment")
            ack_request = expand(loss["ack_req"], f"{name}.loss.ack_req")
            ack_success = expand(loss["ack_success"], f"{name}.loss.ack_success")
            if (
                len(ack_request) != 2
                or ack_request[0] != vector["rule_id"]
                or ack_request[1] & 0x7F
            ):
                raise ValueError(f"{name}.loss.ack_req is noncanonical")
            if (
                len(ack_success) != 2
                or ack_success[0] != vector["rule_id"]
                or ack_success[1] & 0x7F != 0x40
            ):
                raise ValueError(f"{name}.loss.ack_success is noncanonical")
            if ack_request[1] >> 7 != ack_success[1] >> 7:
                raise ValueError(f"{name} ACK request/success windows differ")
            ack_failure = expand(loss["ack_failure"], f"{name}.loss.ack_failure")
            if len(ack_failure) < 2 or ack_failure[0] != vector["rule_id"]:
                raise ValueError(f"{name}.loss.ack_failure is noncanonical")
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
            if not isinstance(controls, dict) or set(controls) != {"rule_78", "rule_79"} or any(
                not isinstance(values, dict) or set(values) != required_controls
                for values in controls.values()
            ):
                raise ValueError(f"{name} control set is incomplete or unknown")
            for rule_name, values in controls.items():
                rule_id = int(rule_name[-2:], 16)
                expected_controls = {
                    "ack_success_w0": bytes((rule_id, 0x40)),
                    "ack_success_w1": bytes((rule_id, 0xC0)),
                    "ack_req_w0": bytes((rule_id, 0x00)),
                    "ack_req_w1": bytes((rule_id, 0x80)),
                    "sender_abort": bytes((rule_id, 0xFE)),
                    "receiver_abort": bytes((rule_id, 0xFF, 0xFF)),
                }
                for field_name, expected in expected_controls.items():
                    if expand(values[field_name], f"{name}.{rule_name}.{field_name}") != expected:
                        raise ValueError(f"{name}.{rule_name}.{field_name} is noncanonical")
        retry_role = "SCHC_VECTOR_RETRY_NONE"
        if category == "retry_exhaustion":
            if name not in RETRY_SCENARIOS:
                raise ValueError(f"unknown retry scenario: {name}")
            retry_role = RETRY_SCENARIOS[name]
            seen_retry_scenarios.add(name)
            require_int(vector["attempts_before"], 0, 255, f"{name}.attempts_before")
            trigger_value = (
                vector["pre_exhaustion_message"]
                if name == "sender_retry_exhaustion"
                else vector["trigger"]
            )
            trigger = expand(trigger_value, f"{name}.trigger")
            expected = expand(vector["expected_message"], f"{name}.expected_message")
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
            if vector["expect_status"] != "aborted" or vector["attempts_before"] != 4:
                raise ValueError(f"{name} retry boundary changed")
            if name == "sender_retry_exhaustion":
                for field_name in (
                    "retransmission_timeout_s",
                    "timer_start_s",
                    "max_ack_requests",
                    "inactivity_timeout_s",
                ):
                    require_int(vector[field_name], 0, 86400, f"{name}.{field_name}")
                if vector["retransmission_timeout_s"] == 0:
                    raise ValueError(f"{name}.retransmission_timeout_s must be positive")
                if vector["timer_policy"] != "fixed":
                    raise ValueError(f"{name}.timer_policy must be fixed")
                if vector["bitmap_one_means"] != "received":
                    raise ValueError(f"{name}.bitmap_one_means must be received")
                if vector["trigger_event"] != "timeout":
                    raise ValueError(f"{name}.trigger_event must be timeout")
                if vector["max_ack_requests"] != vector["attempts_before"]:
                    raise ValueError(f"{name} attempts/max_ack_requests mismatch")
                deadlines = vector["timer_deadlines_s"]
                if not isinstance(deadlines, list) or len(deadlines) != vector["max_ack_requests"]:
                    raise ValueError(f"{name}.timer_deadlines_s has wrong length")
                expected_deadlines = [
                    vector["timer_start_s"]
                    + vector["retransmission_timeout_s"] * (position + 1)
                    for position in range(vector["max_ack_requests"])
                ]
                for position, deadline in enumerate(deadlines):
                    require_int(deadline, 0, 86400, f"{name}.timer_deadlines_s[{position}]")
                if deadlines != expected_deadlines:
                    raise ValueError(f"{name}.timer_deadlines_s violates fixed policy")
                if vector["inactivity_timeout_s"] <= deadlines[-1]:
                    raise ValueError(f"{name}.inactivity_timeout_s must follow retry deadlines")
        if category == "capacity":
            expected_status = "packet_too_large" if name == "over_profile_capacity" else "ok"
            if vector["expect_status"] != expected_status:
                raise ValueError(f"{name}.expect_status changed")
        if category == "malformed":
            wire = expand(vector["wire"], f"{name}.wire")
            if len(wire) < 2 or len(wire) > TILE_SIZE + 6:
                raise ValueError(f"{name}.wire has invalid length")
            if "assigned_fcns" in vector:
                fcns = vector["assigned_fcns"]
                if not isinstance(fcns, list) or not fcns:
                    raise ValueError(f"{name}.assigned_fcns must be a nonempty array")
                for position, fcn in enumerate(fcns):
                    require_int(fcn, 0, 63, f"{name}.assigned_fcns[{position}]")
                if len(set(fcns)) != len(fcns):
                    raise ValueError(f"{name}.assigned_fcns contains duplicates")
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
        if "pre_exhaustion_message" in vector:
            values.append(("trigger", vector["pre_exhaustion_message"]))
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
