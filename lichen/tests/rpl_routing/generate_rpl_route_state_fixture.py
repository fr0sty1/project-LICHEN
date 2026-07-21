#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate the C fixture from the authoritative RPL route-state JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_INPUT = HERE.parents[2] / "test" / "vectors" / "rpl_route_state.json"
DEFAULT_OUTPUT = HERE / "src" / "rpl_route_state_vectors.h"

DAO_MAX = 160
TARGET_MAX = 32
CANDIDATE_MAX = 16
HOP_BOUNDARY_MAX = 16


def c_bytes(value: str, width: int = 16) -> str:
    data = bytes.fromhex(value)
    rows = []
    for offset in range(0, len(data), width):
        rows.append(", ".join(f"0x{byte:02x}" for byte in data[offset : offset + width]))
    return ", ".join(rows)


def c_bool(value: bool) -> str:
    return "true" if value else "false"


def validate_dimensions(document: dict) -> None:
    limits = document["oracle"]["limits"]
    max_route_hops = document["oracle"]["max_route_hops"]
    if not 0 < limits["max_targets"] <= TARGET_MAX:
        raise ValueError("oracle max_targets exceeds bounded C fixture storage")
    if not 0 < limits["max_candidates_per_target"] <= CANDIDATE_MAX:
        raise ValueError("oracle max_candidates_per_target exceeds bounded C fixture storage")
    if (
        not 0
        < limits["max_candidates"]
        <= (limits["max_targets"] * limits["max_candidates_per_target"])
    ):
        raise ValueError("oracle max_candidates exceeds aggregate candidate capacity")
    if not 0 < max_route_hops < HOP_BOUNDARY_MAX:
        raise ValueError("oracle max_route_hops exceeds bounded C fixture storage")
    for boundary in document["route_hop_boundaries"]:
        if not 0 < len(boundary["path"]) <= HOP_BOUNDARY_MAX:
            raise ValueError(f"{boundary['name']}: path exceeds bounded C fixture storage")
    for vector in document["vectors"]:
        expected = vector["expected"]
        state = expected["state"]
        if len(bytes.fromhex(vector.get("dao_hex", ""))) > DAO_MAX:
            raise ValueError(f"{vector['name']}: DAO exceeds bounded C fixture storage")
        if len(state["targets"]) > limits["max_targets"]:
            raise ValueError(f"{vector['name']}: too many targets")
        if len(state["routing_table"]["routes"]) > limits["max_targets"]:
            raise ValueError(f"{vector['name']}: too many routes")
        if not expected["reason"]:
            raise ValueError(f"{vector['name']}: empty reason")
        for target in state["targets"]:
            if len(target["candidates"]) > limits["max_candidates_per_target"]:
                raise ValueError(f"{vector['name']}: too many candidates")
            selected = target["selected_candidate"]
            if selected is not None and len(selected["path"]) > max_route_hops:
                raise ValueError(f"{vector['name']}: selected path is too long")
        for route in state["routing_table"]["routes"]:
            if len(route["path"]) > max_route_hops:
                raise ValueError(f"{vector['name']}: route path is too long")


def render(document: dict) -> str:
    validate_dimensions(document)
    limits = document["oracle"]["limits"]
    max_route_hops = document["oracle"]["max_route_hops"]
    hop_boundary_max = max(len(boundary["path"]) for boundary in document["route_hop_boundaries"])
    retention_seconds = document["oracle"]["freshness_retention_seconds"]
    lines = [
        "/* Generated from test/vectors/rpl_route_state.json. Do not edit. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "#ifndef LICHEN_RPL_ROUTE_STATE_VECTORS_H_",
        "#define LICHEN_RPL_ROUTE_STATE_VECTORS_H_",
        "",
        f"#define RPL_ROUTE_VECTOR_DAO_MAX {DAO_MAX}",
        f"#define RPL_ROUTE_VECTOR_TARGET_MAX {limits['max_targets']}",
        f"#define RPL_ROUTE_VECTOR_CANDIDATES_PER_TARGET_MAX {limits['max_candidates_per_target']}",
        f"#define RPL_ROUTE_VECTOR_AGGREGATE_CANDIDATE_MAX {limits['max_candidates']}",
        f"#define RPL_ROUTE_VECTOR_HOP_BOUNDARY_MAX {hop_boundary_max}",
        f"#define RPL_ROUTE_ORACLE_MAX_HOPS {max_route_hops}",
        "#define RPL_ROUTE_DISPOSITION_ACTIVE 0",
        "#define RPL_ROUTE_DISPOSITION_WITHDRAWN 1",
        "#define RPL_ROUTE_DISPOSITION_EXPIRED 2",
        "",
        "struct rpl_route_sequence_relation {",
        "\tconst char *name;",
        "\tuint8_t current;",
        "\tuint8_t incoming;",
        "\tenum lichen_rpl_sequence_relation expected;",
        "};",
        "",
        "struct rpl_route_tx_sequence_transition {",
        "\tconst char *name;",
        "\tuint8_t path_lifetime;",
        "\tuint8_t expected_dao_sequence;",
        "\tuint8_t expected_path_sequence;",
        "\tbool advance_path_sequence;",
        "};",
        "",
        "struct rpl_route_hop_boundary {",
        "\tconst char *name;",
        "\tuint8_t path[RPL_ROUTE_VECTOR_HOP_BOUNDARY_MAX][16];",
        "\tuint8_t path_len;",
        "\tbool accepted;",
        "};",
        "",
        "struct rpl_route_vector_candidate {",
        "\tuint8_t parent[16];",
        "\tuint8_t path_control;",
        "\tuint8_t path_lifetime;",
        "\tbool external;",
        "\tuint32_t installed_at;",
        "\tuint32_t expires_at;",
        "\tbool has_expiry;",
        "};",
        "",
        "struct rpl_route_vector_selected {",
        "\tuint8_t parent[16];",
        "\tuint8_t path[LICHEN_RPL_MAX_HOPS][16];",
        "\tuint8_t preference_subfield;",
        "\tuint8_t path_len;",
        "\tbool present;",
        "};",
        "",
        "struct rpl_route_vector_target {",
        "\tuint8_t target[16];",
        "\tstruct rpl_route_vector_candidate "
        "candidates[RPL_ROUTE_VECTOR_CANDIDATES_PER_TARGET_MAX];",
        "\tuint32_t last_updated;",
        "\tuint32_t retain_until;",
        "\tuint32_t descriptor;",
        "\tuint8_t path_sequence;",
        "\tuint8_t candidate_count;",
        "\tuint8_t disposition;",
        "\tbool has_descriptor;",
        "\tstruct rpl_route_vector_selected selected;",
        "};",
        "",
        "struct rpl_route_vector_route {",
        "\tuint8_t target[16];",
        "\tuint8_t path[LICHEN_RPL_MAX_HOPS][16];",
        "\tuint32_t installed_at;",
        "\tuint32_t expires_at;",
        "\tuint8_t path_lifetime;",
        "\tuint8_t path_len;",
        "\tbool has_expiry;",
        "};",
        "",
        "struct rpl_route_state_vector {",
        "\tconst char *name;",
        "\tuint8_t dao[RPL_ROUTE_VECTOR_DAO_MAX];",
        "\tuint16_t dao_len;",
        "\tuint32_t now;",
        "\tbool expire;",
        "\tbool accepted;",
        "\tbool changed;",
        "\tbool refreshed;",
        "\tconst char *reason;",
        "\tuint8_t target_count;",
        "\tuint8_t route_count;",
        "\tstruct rpl_route_vector_target targets[RPL_ROUTE_VECTOR_TARGET_MAX];",
        "\tstruct rpl_route_vector_route routes[RPL_ROUTE_VECTOR_TARGET_MAX];",
        "};",
        "",
        "static const struct rpl_route_sequence_relation rpl_route_sequence_relations[] = {",
    ]
    relation_names = {
        "equal": "LICHEN_RPL_SEQUENCE_EQUAL",
        "newer": "LICHEN_RPL_SEQUENCE_NEWER",
        "stale": "LICHEN_RPL_SEQUENCE_STALE",
        "incomparable": "LICHEN_RPL_SEQUENCE_INCOMPARABLE",
    }
    for relation in document["sequence_relations"]:
        lines.append(
            "\t{ "
            f".name = {json.dumps(relation['name'])}, "
            f".current = {relation['current']}, .incoming = {relation['incoming']}, "
            f".expected = {relation_names[relation['expected']]} "
            "},"
        )
    lines.extend(
        [
            "};",
            "",
            "#define RPL_ROUTE_SEQUENCE_RELATION_COUNT \\",
            "\t(sizeof(rpl_route_sequence_relations) / sizeof(rpl_route_sequence_relations[0]))",
            "",
            "static const struct rpl_route_tx_sequence_transition "
            "rpl_route_tx_sequence_transitions[] = {",
        ]
    )
    for transition in document["tx_sequence_transitions"]:
        lines.append(
            "\t{ "
            f".name = {json.dumps(transition['name'])}, "
            f".path_lifetime = {transition['path_lifetime']}, "
            f".expected_dao_sequence = {transition['expected_dao_sequence']}, "
            f".expected_path_sequence = {transition['expected_path_sequence']}, "
            f".advance_path_sequence = {c_bool(transition['advance_path_sequence'])} "
            "},"
        )
    lines.extend(
        [
            "};",
            "",
            "#define RPL_ROUTE_TX_SEQUENCE_TRANSITION_COUNT \\",
            "\t(sizeof(rpl_route_tx_sequence_transitions) / "
            "sizeof(rpl_route_tx_sequence_transitions[0]))",
            "",
            "static const struct rpl_route_hop_boundary rpl_route_hop_boundaries[] = {",
        ]
    )
    for boundary in document["route_hop_boundaries"]:
        path_rows = ", ".join(f"{{ {c_bytes(address)} }}" for address in boundary["path"])
        lines.append(
            "\t{ "
            f".name = {json.dumps(boundary['name'])}, "
            f".path = {{ {path_rows} }}, .path_len = {len(boundary['path'])}, "
            f".accepted = {c_bool(boundary['accepted'])} "
            "},"
        )
    lines.extend(
        [
            "};",
            "",
            "#define RPL_ROUTE_HOP_BOUNDARY_COUNT \\",
            "\t(sizeof(rpl_route_hop_boundaries) / sizeof(rpl_route_hop_boundaries[0]))",
            "",
            "static const struct rpl_route_state_vector rpl_route_state_vectors[] = {",
        ]
    )
    retention: dict[str, int] = {}
    previous_disposition: dict[str, str] = {}
    for vector in document["vectors"]:
        wire = vector.get("dao_hex", "")
        expected = vector["expected"]
        targets = expected["state"]["targets"]
        lines.extend(
            [
                "\t{",
                f"\t\t.name = {json.dumps(vector['name'])},",
                f"\t\t.dao = {{ {c_bytes(wire)} }}," if wire else "\t\t.dao = { 0 },",
                f"\t\t.dao_len = {len(bytes.fromhex(wire))},",
                f"\t\t.now = {vector['now_seconds']}U,",
                f"\t\t.expire = {'true' if vector['event'] == 'expire' else 'false'},",
                f"\t\t.accepted = {'true' if expected['accepted'] else 'false'},",
                f"\t\t.changed = {'true' if expected['state_changed'] else 'false'},",
                f"\t\t.refreshed = {c_bool(expected['refreshed'])},",
                f"\t\t.reason = {json.dumps(expected['reason'])},",
                f"\t\t.target_count = {len(targets)},",
                "\t\t.targets = {",
            ]
        )
        for target in targets:
            candidates = target["candidates"]
            prefix = target["prefix"]
            disposition = target["disposition"]
            if disposition == "active":
                retain_until = 0xFFFFFFFF
            elif disposition == "withdrawn":
                retain_until = candidates[0]["installed_at"] + retention_seconds
            elif previous_disposition.get(prefix) != "expired":
                retain_until = candidates[0]["expires_at"] + retention_seconds
            else:
                retain_until = retention[prefix]
            retention[prefix] = retain_until
            previous_disposition[prefix] = disposition
            selected = target["selected_candidate"]
            lines.extend(
                [
                    "\t\t\t{",
                    f"\t\t\t\t.target = {{ {c_bytes(target['prefix'])} }},",
                    "\t\t\t\t.candidates = {",
                ]
            )
            for candidate in candidates:
                lines.extend(
                    [
                        "\t\t\t\t\t{",
                        f"\t\t\t\t\t\t.parent = {{ {c_bytes(candidate['parent'])} }},",
                        f"\t\t\t\t\t\t.path_control = 0x{candidate['path_control']:02x},",
                        f"\t\t\t\t\t\t.path_lifetime = {candidate['path_lifetime']},",
                        f"\t\t\t\t\t\t.external = {'true' if candidate['external'] else 'false'},",
                        f"\t\t\t\t\t\t.installed_at = {candidate['installed_at']}U,",
                        f"\t\t\t\t\t\t.expires_at = {(candidate['expires_at'] or 0)}U,",
                        f"\t\t\t\t\t\t.has_expiry = {c_bool(candidate['expires_at'] is not None)},",
                        "\t\t\t\t\t},",
                    ]
                )
            lines.extend(
                [
                    "\t\t\t\t},",
                    f"\t\t\t\t.last_updated = {candidates[0]['installed_at']}U,",
                    f"\t\t\t\t.retain_until = {retain_until}U,",
                    f"\t\t\t\t.descriptor = {(target['descriptor'] or 0)}U,",
                    f"\t\t\t\t.path_sequence = {target['path_sequence']},",
                    f"\t\t\t\t.candidate_count = {len(candidates)},",
                    f"\t\t\t\t.disposition = RPL_ROUTE_DISPOSITION_{disposition.upper()},",
                    f"\t\t\t\t.has_descriptor = {c_bool(target['descriptor'] is not None)},",
                ]
            )
            if selected is None:
                lines.append("\t\t\t\t.selected = { .present = false },")
            else:
                path_rows = ", ".join(f"{{ {c_bytes(address)} }}" for address in selected["path"])
                lines.extend(
                    [
                        "\t\t\t\t.selected = {",
                        f"\t\t\t\t\t.parent = {{ {c_bytes(selected['parent'])} }},",
                        f"\t\t\t\t\t.path = {{ {path_rows} }},",
                        f"\t\t\t\t\t.preference_subfield = {selected['preference_subfield']},",
                        f"\t\t\t\t\t.path_len = {len(selected['path'])},",
                        "\t\t\t\t\t.present = true,",
                        "\t\t\t\t},",
                    ]
                )
            lines.append("\t\t\t},")
        routes = expected["state"]["routing_table"]["routes"]
        lines.extend(["\t\t},", f"\t\t.route_count = {len(routes)},", "\t\t.routes = {"])
        for route in routes:
            path_rows = ", ".join(f"{{ {c_bytes(address)} }}" for address in route["path"])
            lines.extend(
                [
                    "\t\t\t{",
                    f"\t\t\t\t.target = {{ {c_bytes(route['prefix'])} }},",
                    f"\t\t\t\t.path = {{ {path_rows} }},",
                    f"\t\t\t\t.installed_at = {route['installed_at']}U,",
                    f"\t\t\t\t.expires_at = {(route['expires_at'] or 0)}U,",
                    f"\t\t\t\t.path_lifetime = {route['path_lifetime']},",
                    f"\t\t\t\t.path_len = {len(route['path'])},",
                    f"\t\t\t\t.has_expiry = {c_bool(route['expires_at'] is not None)},",
                    "\t\t\t},",
                ]
            )
        lines.extend(["\t\t},", "\t},"])
    lines.extend(
        [
            "};",
            "",
            "#define RPL_ROUTE_STATE_VECTOR_COUNT \\",
            "\t(sizeof(rpl_route_state_vectors) / sizeof(rpl_route_state_vectors[0]))",
            "",
            "#endif /* LICHEN_RPL_ROUTE_STATE_VECTORS_H_ */",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    if sys.argv[1:] == ["--check"]:
        document = json.loads(DEFAULT_INPUT.read_text())
        if DEFAULT_OUTPUT.read_text() != render(document):
            raise SystemExit(f"{DEFAULT_OUTPUT.name} is not deterministically generated")
        print(f"checked C fixture generated from {DEFAULT_INPUT.name}")
        return
    if len(sys.argv) > 3:
        raise SystemExit("usage: generate_rpl_route_state_fixture.py [input [output]] | --check")
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT
    document = json.loads(source.read_text())
    output.write_text(render(document))


if __name__ == "__main__":
    main()
