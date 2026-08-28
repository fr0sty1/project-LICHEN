# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO test vector runner.

This module provides utilities for running canonical route-state test vectors
to verify DAO processing implementation correctness.
"""
from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

from lichen.rpl.dao_manager import DaoManager
from lichen.rpl.dao_types import (
    MAX_ROUTE_HOPS_ALIAS,
    DaoError,
    DaoOutcome,
    TransitInformation,
    sequence_relation,
)
from lichen.rpl.messages import DAO
from lichen.rpl.routing import RoutingError, RoutingTable


def run_route_state_vectors(path: str | Path) -> DaoManager:
    """Apply canonical literal DAO bytes and verify production route-state outcomes."""
    document: dict[str, Any] = json.loads(Path(path).read_text())
    if document.get("vector_type") != "rpl_route_state":
        raise ValueError("not an RPL route-state vector document")
    oracle: dict[str, Any] = document["oracle"]
    limits: dict[str, int] = oracle["limits"]
    authority = IPv6Address(bytes.fromhex(oracle["sequence_authority"]))
    manager = DaoManager(
        node_address=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
        is_root=True,
        rpl_instance_id=oracle["rpl_instance_id"],
        dodag_id=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
        lifetime_unit_seconds=oracle["lifetime_unit_seconds"],
        pcs=oracle["path_control_size"],
        max_targets=limits["max_targets"],
        max_candidates=limits["max_candidates"],
        max_candidates_per_target=limits.get("max_candidates_per_target", limits["max_candidates"]),
        freshness_retention_seconds=oracle["freshness_retention_seconds"],
    )
    tx_manager = DaoManager(
        node_address=authority,
        rpl_instance_id=oracle["rpl_instance_id"],
        dodag_id=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
    )
    for transition in document["tx_sequence_transitions"]:
        expected_lifetime = transition["path_lifetime"]
        if transition["advance_path_sequence"]:
            tx_dao = tx_manager.build_dao_with_lifetime_semantics_for_test(
                manager.node_address, transition["path_lifetime"]
            )
        else:
            cached_update = tx_manager._last_logical_update
            if cached_update != (manager.node_address, transition["path_lifetime"]):
                counters = (tx_manager._dao_sequence, tx_manager._path_sequence)
                try:
                    tx_manager.build_dao_copy_with_lifetime_semantics_for_test(
                        manager.node_address, transition["path_lifetime"]
                    )
                except DaoError:
                    pass
                else:
                    raise AssertionError(f"{transition['name']}: non-exact DAO copy accepted")
                if (tx_manager._dao_sequence, tx_manager._path_sequence) != counters:
                    raise AssertionError(f"{transition['name']}: rejected copy advanced counters")
                if cached_update is None:
                    raise AssertionError(f"{transition['name']}: no logical update to copy")
                expected_lifetime = cached_update[1]
                tx_dao = tx_manager.build_dao_copy_with_lifetime_semantics_for_test(
                    *cached_update
                )
            else:
                tx_dao = tx_manager.build_dao_copy_with_lifetime_semantics_for_test(
                    manager.node_address, transition["path_lifetime"]
                )
        tx_transit = TransitInformation.from_option(tx_dao.options[1])
        if tx_dao.dao_sequence != transition["expected_dao_sequence"]:
            raise AssertionError(f"{transition['name']}: DAOSequence")
        if tx_transit.path_sequence != transition["expected_path_sequence"]:
            raise AssertionError(f"{transition['name']}: Path Sequence")
        if tx_transit.path_lifetime != expected_lifetime:
            raise AssertionError(f"{transition['name']}: Path Lifetime")
        if tx_dao.to_bytes().hex() != transition["expected_wire"]:
            raise AssertionError(f"{transition['name']}: canonical leaf DAO wire")
    if oracle["max_route_hops"] != MAX_ROUTE_HOPS_ALIAS:
        raise AssertionError("production route-hop limit differs from vector oracle")
    for boundary in document["route_hop_boundaries"]:
        route_table = RoutingTable()
        path_addresses: list[IPv6Address | str] = [
            IPv6Address(bytes.fromhex(hop)) for hop in boundary["path"]
        ]
        try:
            route_table.add_route(path_addresses[-1], path_addresses)
            accepted = True
        except RoutingError:
            accepted = False
        if accepted != boundary["accepted"]:
            raise AssertionError(f"{boundary['name']}: route-hop boundary")
    for relation in document.get("sequence_relations", []):
        actual = sequence_relation(relation["incoming"], relation["current"])
        if actual != relation["expected"]:
            raise AssertionError(
                f"{relation['name']}: sequence relation {actual} != {relation['expected']}"
            )
    for vector in document["vectors"]:
        name = vector["name"]
        expected = vector["expected"]
        has_route_oracle = any(
            key in container
            for container in (
                vector,
                expected,
                vector["before"],
                expected["state"],
            )
            for key in ("routes", "routing_table")
        )
        before = manager.route_state_snapshot(authority)
        comparable_before = before if has_route_oracle else _without_selected_candidates(before)
        expected_before = (
            vector["before"] if has_route_oracle else _without_selected_candidates(vector["before"])
        )
        if comparable_before != expected_before:
            raise AssertionError(f"{name}: production pre-state differs from vector")
        if vector["event"] == "expire":
            outcome = DaoOutcome(
                True,
                manager.expire_routes(vector["now_seconds"]),
                False,
                "expired",
            )
        else:
            dao = DAO.from_bytes(bytes.fromhex(vector["dao_hex"]))
            outcome = manager.evaluate_dao_semantics_for_test_at(
                dao, vector["now_seconds"]
            )
        actual_outcome = {
            "accepted": outcome.accepted,
            "state_changed": outcome.state_changed,
            "refreshed": outcome.refreshed,
            "reason": outcome.reason,
        }
        expected_outcome = {key: expected[key] for key in actual_outcome}
        if actual_outcome != expected_outcome:
            raise AssertionError(
                f"{name}: production outcome {actual_outcome} != {expected_outcome}"
            )
        snapshot = manager.route_state_snapshot(authority)
        expected_routes = expected.get(
            "routes",
            expected.get(
                "routing_table",
                expected["state"].get(
                    "routes",
                    expected["state"].get(
                        "routing_table",
                        vector.get("routes", vector.get("routing_table")),
                    ),
                ),
            ),
        )
        if expected_routes is None:
            # Version-1 legacy vectors selected from parent addresses without
            # providing parent-to-root state. Their retained candidate state is
            # still valid, but synthetic selected paths are not production routes.
            comparable_actual = _without_selected_candidates(snapshot)
            comparable_expected = _without_selected_candidates(expected["state"])
        else:
            comparable_actual = snapshot
            comparable_expected = expected["state"]
            actual_routes = manager.routing_table_snapshot()
            normalized_routes = _normalize_expected_routes(expected_routes)
            if actual_routes != normalized_routes:
                raise AssertionError(
                    f"{name}: production routes {actual_routes} != {normalized_routes}"
                )
        if comparable_actual != comparable_expected:
            raise AssertionError(f"{name}: production post-state differs from vector")
        if "selected_path" in expected:
            target = IPv6Address(bytes.fromhex(expected["selected_target"]))
            selected = manager.routing_table.lookup(target)
            encoded = None if selected is None else [hop.packed.hex() for hop in selected]
            if encoded != expected["selected_path"]:
                raise AssertionError(f"{name}: selected path differs from vector")
    return manager


def _without_selected_candidates(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "targets": [
            {key: value for key, value in target.items() if key != "selected_candidate"}
            for target in snapshot["targets"]
        ]
    }


def _normalize_expected_routes(routes: Any) -> dict[str, list[str]]:
    if isinstance(routes, dict):
        if "routes" in routes:
            return _normalize_expected_routes(routes["routes"])
        return {str(target): list(path) for target, path in routes.items()}
    if isinstance(routes, list):
        return {str(route.get("target", route["prefix"])): list(route["path"]) for route in routes}
    raise ValueError("route-state vector routes must be an object or array")
