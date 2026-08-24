# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RPL Multi-Instance Coordination oracle (GCP-5).

These tests validate the Python oracle implementation against the spec
requirements in spec/08-gateway-coordination.md GCP-5, mirror the security
behaviors of rust/lichen-rpl/src/multi_instance.rs (GCP-9 replay/auth/DoS
guards), and cross-check every case in the canonical vector file
test/vectors/rpl_multi_instance.json.
"""

from __future__ import annotations

import json
import math
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.rpl import (
    DAO,
    DIO,
    DaoBackboneBridge,
    GatewayInfo,
    GatewayRole,
    MultiRootCoordinator,
    RplTarget,
    TransitInformation,
    generate_multi_instance_vectors,
    iid_compare,
    resolve_slot_conflict,
    validate_rpl_instance_id,
)
from lichen.rpl.dodag import ROOT_RANK
from lichen.rpl.multi_instance import (
    MAX_PEERS,
    MAX_PENDING_PROPAGATIONS,
    MAX_RECEIVED_ROUTE_PEERS,
    MAX_ROUTES_PER_MESSAGE,
)

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "rpl_multi_instance.json"

LOCAL_IID = "fe80::1234:5678:9abc:def0"
PEER_IID = "fe80::abcd:ef01:2345:6789"


def _gateway(iid: str, *, routes_learned: int = 0) -> GatewayInfo:
    """Build a GatewayInfo with empty discovery metadata."""
    return GatewayInfo(
        iid=IPv6Address(iid),
        capabilities={},
        slot_map={},
        superframe_duration_s=60,
        federation_modes=(),
        routes_learned=routes_learned,
    )


def _mutated(message: dict, **changes) -> dict:
    """Return a copy of a backbone message with the given field changes."""
    updated = dict(message)
    updated.update(changes)
    return updated


def _backbone_message(
    *,
    origin: str = LOCAL_IID,
    rpl_instance_id: int = 0,
    dao_sequence: int = 42,
    timestamp: float = 1000.0,
    targets: list[dict] | None = None,
    transit: list[dict] | None = None,
) -> dict:
    """Build a canonical-shape DaoBackboneMessage dict."""
    return {
        "origin_gateway": origin,
        "rpl_instance_id": rpl_instance_id,
        "dao_sequence": dao_sequence,
        "targets": targets if targets is not None else [],
        "transit": transit if transit is not None else [],
        "timestamp": timestamp,
    }


class TestGatewayInfo:
    """Tests for GatewayInfo dataclass."""

    def test_create_gateway_info(self) -> None:
        """Gateway info can be created with IID and capabilities."""
        info = GatewayInfo(
            iid=IPv6Address("fe80::1234:5678:9abc:def0"),
            capabilities={"max_slots": 60, "gps_sync": True},
            slot_map={"allocation": "interleaved", "owned_slots": [0, 3, 6]},
            superframe_duration_s=60,
            federation_modes=("psk", "ed25519"),
        )
        assert info.iid == IPv6Address("fe80::1234:5678:9abc:def0")
        assert info.capabilities["gps_sync"] is True
        assert info.federation_modes == ("psk", "ed25519")

    def test_gateway_info_string_iid_coerced(self) -> None:
        """String IID is coerced to IPv6Address."""
        info = GatewayInfo(
            iid="fe80::abcd:1234:5678:9abc",  # type: ignore[arg-type]
            capabilities={},
            slot_map={},
            superframe_duration_s=60,
            federation_modes=(),
        )
        assert isinstance(info.iid, IPv6Address)

    def test_routes_learned_defaults_to_zero(self) -> None:
        """routes_learned feeds federation totals and defaults to 0."""
        assert _gateway(LOCAL_IID).routes_learned == 0


class TestMultiRootCoordinator:
    """Tests for MultiRootCoordinator per GCP-5."""

    def test_create_coordinator_with_default_instance_id(self) -> None:
        """Coordinator defaults to RPLInstanceID 0 per spec."""
        coord = MultiRootCoordinator()
        assert coord.rpl_instance_id == 0

    def test_invalid_instance_id_rejected(self) -> None:
        """RPLInstanceID must be 0-255."""
        with pytest.raises(ValueError, match="RPLInstanceID must be 0-255"):
            MultiRootCoordinator(rpl_instance_id=256)
        with pytest.raises(ValueError, match="RPLInstanceID must be 0-255"):
            MultiRootCoordinator(rpl_instance_id=-1)

    def test_add_and_get_peers(self) -> None:
        """Peers can be added and retrieved."""
        coord = MultiRootCoordinator()

        assert coord.add_peer(_gateway("fe80::1111:2222:3333:4444")) is True
        assert coord.add_peer(_gateway("fe80::5555:6666:7777:8888")) is True

        peers = coord.get_peers()
        assert len(peers) == 2

    def test_add_peer_updates_existing_at_capacity(self) -> None:
        """Existing peers can be refreshed even at MAX_PEERS (mirrors Rust)."""
        coord = MultiRootCoordinator()
        first = _gateway("fe80::0000:0000:0000:0001")
        coord.add_peer(first)
        for i in range(MAX_PEERS - 1):
            assert coord.add_peer(_gateway(f"fe80::200:{i:04x}")) is True
        assert coord.peer_count() == MAX_PEERS

        # A new peer at capacity is refused...
        assert coord.add_peer(_gateway("fe80::ffff:ffff:ffff:ffff")) is False
        # ...but refreshing an existing peer still works.
        assert coord.add_peer(first) is True
        assert coord.peer_count() == MAX_PEERS

    def test_remove_peer(self) -> None:
        """Peers can be removed."""
        coord = MultiRootCoordinator()
        gw = _gateway("fe80::1111:2222:3333:4444")
        coord.add_peer(gw)
        assert len(coord.get_peers()) == 1

        removed = coord.remove_peer(gw.iid)
        assert removed is True
        assert len(coord.get_peers()) == 0

        # Remove non-existent returns False
        removed = coord.remove_peer("fe80::dead:beef:cafe:babe")
        assert removed is False

    def test_elect_time_master_lowest_iid(self) -> None:
        """Time master elected by lowest IID per GCP-6.1."""
        coord = MultiRootCoordinator()
        coord.add_peer(_gateway("fe80::abcd:ef01:2345:6789"))  # Higher IID
        coord.add_peer(_gateway("fe80::1234:5678:9abc:def0"))  # Lower IID

        master = coord.elect_time_master()
        assert master is not None
        assert master.iid == IPv6Address("fe80::1234:5678:9abc:def0")

    def test_elect_time_master_includes_local(self) -> None:
        """Local gateway participates in time master election."""
        local = _gateway("fe80::0001:0002:0003:0004")  # Lowest
        coord = MultiRootCoordinator(local_gateway=local)
        coord.add_peer(_gateway("fe80::ffff:ffff:ffff:ffff"))  # Higher

        master = coord.elect_time_master()
        assert master is not None
        assert master.iid == local.iid

    def test_get_role_standalone(self) -> None:
        """Without local gateway or peers, role is STANDALONE."""
        coord = MultiRootCoordinator()
        assert coord.get_role() == GatewayRole.STANDALONE

        coord = MultiRootCoordinator(local_gateway=_gateway(LOCAL_IID))
        assert coord.get_role() == GatewayRole.STANDALONE

    def test_get_role_primary(self) -> None:
        """Local gateway with lowest IID is PRIMARY."""
        coord = MultiRootCoordinator(local_gateway=_gateway("fe80::0001:0002:0003:0004"))
        coord.add_peer(_gateway("fe80::ffff:ffff:ffff:ffff"))

        assert coord.get_role() == GatewayRole.PRIMARY

    def test_get_role_secondary(self) -> None:
        """Local gateway with higher IID is SECONDARY."""
        coord = MultiRootCoordinator(local_gateway=_gateway("fe80::ffff:ffff:ffff:ffff"))
        coord.add_peer(_gateway("fe80::0001:0002:0003:0004"))

        assert coord.get_role() == GatewayRole.SECONDARY

    def test_dodag_version_increment_lollipop(self) -> None:
        """DODAG version uses lollipop semantics."""
        coord = MultiRootCoordinator()
        # Default starts at 128
        assert coord.get_dodag_version() == 128

        # Increment to 129
        new_version = coord.increment_dodag_version()
        assert new_version == 129

        # Wrap around at 255 -> 0
        coord.set_dodag_version(255)
        new_version = coord.increment_dodag_version()
        assert new_version == 0

    def test_set_dodag_version_range_check(self) -> None:
        """Explicit version synchronization only accepts 0-255."""
        coord = MultiRootCoordinator()
        coord.set_dodag_version(200)
        assert coord.get_dodag_version() == 200
        with pytest.raises(ValueError, match="must be 0-255"):
            coord.set_dodag_version(256)

    def test_total_aggregated_routes(self) -> None:
        """Federation route totals include peers and local gateway."""
        coord = MultiRootCoordinator(
            local_gateway=_gateway("fe80::0000:0000:0000:0009", routes_learned=2)
        )
        coord.add_peer(_gateway("fe80::aaaa:1111:2222:3333", routes_learned=5))
        coord.add_peer(_gateway("fe80::bbbb:4444:5555:6666", routes_learned=3))
        assert coord.total_aggregated_routes() == 10

    def test_create_dodag_state_as_root(self) -> None:
        """Coordinator creates root DODAG state with shared instance ID."""
        coord = MultiRootCoordinator(rpl_instance_id=0)
        state = coord.create_dodag_state(
            dodag_id="fe80::1234:5678:9abc:def0",
            node_address="fe80::1234:5678:9abc:def0",
        )

        assert state.rpl_instance_id == 0
        assert state.is_root()
        assert state.rank == ROOT_RANK

    def test_validate_dio_same_instance(self) -> None:
        """DIO with matching RPLInstanceID is accepted."""
        coord = MultiRootCoordinator(rpl_instance_id=0)
        dio = DIO(
            rpl_instance_id=0,
            version=1,
            rank=ROOT_RANK,
            dtsn=0,
            dodag_id=IPv6Address("fe80::1234:5678:9abc:def0"),
        )

        is_valid, reason = coord.validate_dio(dio)
        assert is_valid is True
        assert reason == "valid"

    def test_validate_dio_different_instance_rejected(self) -> None:
        """DIO with different RPLInstanceID is rejected per GCP-5."""
        coord = MultiRootCoordinator(rpl_instance_id=0)
        dio = DIO(
            rpl_instance_id=1,  # Different instance
            version=1,
            rank=ROOT_RANK,
            dtsn=0,
            dodag_id=IPv6Address("fe80::1234:5678:9abc:def0"),
        )

        is_valid, reason = coord.validate_dio(dio)
        assert is_valid is False
        assert "mismatch" in reason

    def test_validate_dio_non_root_rank_rejected(self) -> None:
        """Peer gateway DIO must have root rank."""
        coord = MultiRootCoordinator(rpl_instance_id=0)
        dio = DIO(
            rpl_instance_id=0,
            version=1,
            rank=512,  # Not root rank
            dtsn=0,
            dodag_id=IPv6Address("fe80::1234:5678:9abc:def0"),
        )

        is_valid, reason = coord.validate_dio(dio)
        assert is_valid is False
        assert "root rank" in reason


class TestDaoBackboneBridge:
    """Tests for DAO backbone propagation per GCP-5 and GCP-9."""

    def test_create_bridge(self) -> None:
        """Bridge can be created with coordinator."""
        coord = MultiRootCoordinator()
        bridge = DaoBackboneBridge(
            coordinator=coord,
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )
        assert bridge.local_gateway_iid == IPv6Address(LOCAL_IID)

    def test_queue_and_get_propagations(self) -> None:
        """Propagation messages can be queued and retrieved."""
        coord = MultiRootCoordinator()
        bridge = DaoBackboneBridge(
            coordinator=coord,
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )

        message = _backbone_message(targets=[{"target": "0200:1234::", "prefix_length": 64}])
        assert bridge.queue_for_propagation(message) is True

        pending = bridge.get_pending_propagations()
        assert len(pending) == 1
        assert pending[0]["dao_sequence"] == 42

        # Queue is cleared after get
        assert len(bridge.get_pending_propagations()) == 0

    def test_queue_respects_max_pending_limit(self) -> None:
        """Queue refuses messages beyond MAX_PENDING_PROPAGATIONS (mirrors Rust)."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        for seq in range(MAX_PENDING_PROPAGATIONS):
            assert bridge.queue_for_propagation(_backbone_message(dao_sequence=seq)) is True
        assert bridge.queue_for_propagation(_backbone_message(dao_sequence=255)) is False

        # Draining makes room again
        assert len(bridge.get_pending_propagations()) == MAX_PENDING_PROPAGATIONS
        assert bridge.queue_for_propagation(_backbone_message()) is True

    def test_receive_from_peer_stores_routes(self) -> None:
        """Routes received from peers are stored for aggregation."""
        coord = MultiRootCoordinator()
        bridge = DaoBackboneBridge(
            coordinator=coord,
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )

        message = _backbone_message(
            origin=PEER_IID,
            targets=[{"target": "0200:5678::", "prefix_length": 64}],
            transit=[{"path_sequence": 42, "path_lifetime": 60, "path_control": 0}],
        )
        accepted, reason = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=message["timestamp"] + 1
        )
        assert (accepted, reason) == (True, "stored")

        aggregated = bridge.get_aggregated_routes()
        assert IPv6Address(PEER_IID) in aggregated
        routes = aggregated[IPv6Address(PEER_IID)]
        assert len(routes) == 1
        target, transit = routes[0]
        assert target.prefix_length == 64
        assert transit.path_sequence == 42

    def test_receive_pairs_targets_with_transits_by_index(self) -> None:
        """Each target pairs with its own transit by index (mirrors Rust)."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        transits = [
            {"path_sequence": 10, "path_lifetime": 30, "path_control": 0},
            {"path_sequence": 20, "path_lifetime": 60, "path_control": 0},
            {"path_sequence": 30, "path_lifetime": 90, "path_control": 0},
        ]
        targets = [
            {"target": "0200:1111::", "prefix_length": 64},
            {"target": "0200:2222::", "prefix_length": 64},
            {"target": "0200:3333::", "prefix_length": 64},
        ]
        message = _backbone_message(origin=PEER_IID, targets=targets, transit=transits)

        accepted, _ = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=message["timestamp"]
        )
        assert accepted is True

        routes = bridge.get_aggregated_routes()[IPv6Address(PEER_IID)]
        assert [(t.path_sequence, t.path_lifetime) for _, t in routes] == [
            (10, 30),
            (20, 60),
            (30, 90),
        ]

    def test_receive_extra_targets_use_default_transit(self) -> None:
        """Targets without a matching transit fall back to defaults (mirrors Rust)."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        message = _backbone_message(
            origin=PEER_IID,
            dao_sequence=50,
            targets=[
                {"target": "0200:1111::", "prefix_length": 64},
                {"target": "0200:2222::", "prefix_length": 64},
            ],
            transit=[{"path_sequence": 10, "path_lifetime": 30, "path_control": 0}],
        )

        accepted, _ = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=message["timestamp"]
        )
        assert accepted is True

        routes = bridge.get_aggregated_routes()[IPv6Address(PEER_IID)]
        assert routes[0][1].path_sequence == 10
        # Default transit derives path_sequence from the DAO sequence
        assert routes[1][1].path_sequence == 50
        assert routes[1][1].path_lifetime == 60
        assert routes[1][1].parent_address is None

    @pytest.mark.parametrize(
        ("changes", "expected_reason"),
        [
            pytest.param({"rpl_instance_id": 42}, "instance_mismatch", id="instance"),
            pytest.param({"origin_gateway": LOCAL_IID}, "self_origin", id="self-origin"),
            pytest.param({"timestamp": 0.0}, "stale_timestamp", id="stale"),
            pytest.param({"timestamp": 5000.0}, "stale_timestamp", id="future"),
            pytest.param({"timestamp": math.nan}, "stale_timestamp", id="nan-timestamp"),
        ],
    )
    def test_receive_rejects_invalid_messages(self, changes: dict, expected_reason: str) -> None:
        """GCP-9 guards: instance match, self-loop prevention, replay window."""
        bridge = DaoBackboneBridge(
            coordinator=MultiRootCoordinator(),
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )
        message = _mutated(_backbone_message(origin=PEER_IID), **changes)

        accepted, reason = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=1000.0
        )
        assert accepted is False
        assert reason == expected_reason

    def test_receive_rejects_origin_auth_mismatch(self) -> None:
        """Claimed origin must match the OSCORE-authenticated sender (GCP-9)."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        message = _backbone_message(origin=PEER_IID)

        accepted, reason = bridge.receive_from_peer(
            message, authenticated_sender="fe80::1111:2222:3333:4444", current_time=1000.0
        )
        assert (accepted, reason) == (False, "origin_auth_mismatch")

    def test_receive_rejects_too_many_routes(self) -> None:
        """Messages exceeding MAX_ROUTES_PER_MESSAGE are rejected (DoS guard)."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        flood = [
            {"target": f"0200::{i:x}", "prefix_length": 64}
            for i in range(MAX_ROUTES_PER_MESSAGE + 1)
        ]
        message = _backbone_message(origin=PEER_IID, targets=flood)

        accepted, reason = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=1000.0
        )
        assert (accepted, reason) == (False, "too_many_routes")

    def test_receive_enforces_peer_limit(self) -> None:
        """Routes from more than MAX_RECEIVED_ROUTE_PEERS origins are refused."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        for i in range(MAX_RECEIVED_ROUTE_PEERS):
            origin = f"fe80::900:{i:04x}"
            accepted, _ = bridge.receive_from_peer(
                _backbone_message(origin=origin),
                authenticated_sender=origin,
                current_time=1000.0,
            )
            assert accepted is True

        overflow = "fe80::900:ffff"
        accepted, reason = bridge.receive_from_peer(
            _backbone_message(origin=overflow),
            authenticated_sender=overflow,
            current_time=1000.0,
        )
        assert (accepted, reason) == (False, "peer_limit_reached")

    @pytest.mark.parametrize(
        "changes",
        [
            pytest.param({"origin_gateway": None}, id="origin-none"),
            pytest.param({"origin_gateway": "not-an-ip"}, id="origin-garbage"),
            pytest.param({"origin_gateway": ""}, id="origin-empty"),
            pytest.param({"origin_gateway": 42}, id="origin-int"),
            pytest.param({"rpl_instance_id": "0"}, id="instance-str"),
            pytest.param({"rpl_instance_id": 256}, id="instance-over-u8"),
            pytest.param({"rpl_instance_id": -1}, id="instance-negative"),
            pytest.param({"rpl_instance_id": True}, id="instance-bool"),
            pytest.param({"dao_sequence": 256}, id="sequence-over-u8"),
            pytest.param({"dao_sequence": None}, id="sequence-none"),
            pytest.param({"targets": "nope"}, id="targets-not-list"),
            pytest.param({"transit": {}}, id="transit-not-list"),
            pytest.param({"targets": [{"target": "0200::1"}]}, id="target-missing-prefix"),
            pytest.param(
                {"targets": [{"target": "0200::1", "prefix_length": 999}]},
                id="prefix-over-u8",
            ),
            pytest.param(
                {"targets": [{"target": "0200::1", "prefix_length": True}]},
                id="prefix-bool",
            ),
            pytest.param({"targets": [["0200::1", 64]]}, id="target-not-dict"),
            pytest.param(
                {
                    "targets": [{"target": "0200::1", "prefix_length": 64}],
                    "transit": [{"path_sequence": 1, "path_lifetime": 2}],
                },
                id="transit-missing-path-control",
            ),
            pytest.param(
                {
                    "targets": [{"target": "0200::1", "prefix_length": 64}],
                    "transit": [
                        {
                            "path_sequence": 1,
                            "path_lifetime": 2,
                            "path_control": 3,
                            "parent": None,
                        }
                    ],
                },
                id="parent-none",
            ),
            pytest.param(
                {
                    "targets": [{"target": "0200::1", "prefix_length": 64}],
                    "transit": [
                        {
                            "path_sequence": 1,
                            "path_lifetime": 2,
                            "path_control": 3,
                            "parent": "garbage",
                        }
                    ],
                },
                id="parent-garbage",
            ),
            pytest.param({"timestamp": "1000.0"}, id="timestamp-str"),
            pytest.param({"timestamp": None}, id="timestamp-none"),
            pytest.param({"timestamp": True}, id="timestamp-bool"),
        ],
    )
    def test_receive_malformed_envelope_rejected(self, changes: dict) -> None:
        """Malformed envelopes yield (False, 'malformed') instead of raising.

        Rust decodes backbone messages into typed structs, so these states
        are unrepresentable there; the dict-shaped Python oracle must reject
        them up front (fail-closed) rather than escape TypeError/KeyError/
        ValueError mid-guard.
        """
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        message = _mutated(_backbone_message(origin=PEER_IID), **changes)

        accepted, reason = bridge.receive_from_peer(
            message, authenticated_sender=PEER_IID, current_time=1000.0
        )
        assert (accepted, reason) == (False, "malformed")

    def test_receive_missing_keys_rejected(self) -> None:
        """Every required envelope key is mandatory."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        full = _backbone_message(origin=PEER_IID)
        for key in full:
            message = {k: v for k, v in full.items() if k != key}
            accepted, reason = bridge.receive_from_peer(
                message,  # type: ignore[arg-type]
                authenticated_sender=PEER_IID,
                current_time=1000.0,
            )
            assert (accepted, reason) == (False, "malformed"), f"missing {key}"

    def test_receive_non_dict_rejected(self) -> None:
        """Non-dict messages are rejected without raising."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        for junk in ([], "dict?", None, 42):
            accepted, reason = bridge.receive_from_peer(
                junk,  # type: ignore[arg-type]
                authenticated_sender=PEER_IID,
                current_time=1000.0,
            )
            assert (accepted, reason) == (False, "malformed")

    def test_receive_never_raises_for_any_dict(self) -> None:
        """Exhaustive junk sweep: no input shape raises; output stays a tuple."""
        bridge = DaoBackboneBridge(
            coordinator=MultiRootCoordinator(),
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )
        base = _backbone_message(origin=PEER_IID)
        junk_values: list[object] = [
            None,
            True,
            False,
            0,
            -1,
            256,
            "",
            "junk",
            [],
            {},
            [1, 2],
            {"x": 1},
            float("inf"),
        ]
        for key in base:
            for junk in junk_values:
                message = _mutated(base, **{key: junk})
                result = bridge.receive_from_peer(
                    message, authenticated_sender=PEER_IID, current_time=1000.0
                )
                assert len(result) == 2
                assert isinstance(result[0], bool)
                assert isinstance(result[1], str)

    def test_dao_to_backbone_message_shape(self) -> None:
        """Local DAOs serialize into the canonical backbone message shape."""
        bridge = DaoBackboneBridge(
            coordinator=MultiRootCoordinator(),
            local_gateway_iid=IPv6Address(LOCAL_IID),
        )
        dao = DAO(rpl_instance_id=0, dao_sequence=42)
        dao.options.append(
            TransitInformation(
                path_control=0,
                path_sequence=42,
                path_lifetime=60,
                parent_address=IPv6Address("fe80::1111:2222:3333:4444"),
            ).to_option()
        )
        message = bridge.dao_to_backbone_message(
            dao, [RplTarget(target=IPv6Address("0200:1234:5678:9abc::"), prefix_length=64)]
        )

        assert message["origin_gateway"] == LOCAL_IID
        assert message["rpl_instance_id"] == 0
        assert message["dao_sequence"] == 42
        # str(IPv6Address) normalizes per RFC 5952 ("0200:" compresses to "200:")
        assert [IPv6Address(t["target"]) for t in message["targets"]] == [
            IPv6Address("0200:1234:5678:9abc::")
        ]
        assert message["targets"][0]["prefix_length"] == 64
        assert message["transit"] == [
            {
                "path_control": 0,
                "path_sequence": 42,
                "path_lifetime": 60,
                "parent": "fe80::1111:2222:3333:4444",
            }
        ]

    def test_total_received_routes(self) -> None:
        """total_received_routes counts stored routes across origins."""
        bridge = DaoBackboneBridge(coordinator=MultiRootCoordinator())
        bridge.receive_from_peer(
            _backbone_message(
                origin=PEER_IID,
                targets=[
                    {"target": "0200:a::", "prefix_length": 64},
                    {"target": "0200:b::", "prefix_length": 64},
                ],
            ),
            authenticated_sender=PEER_IID,
            current_time=1000.0,
        )
        assert bridge.total_received_routes() == 2


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_iid_compare_less(self) -> None:
        """iid_compare returns -1 when a < b."""
        result = iid_compare(
            "fe80::0001:0002:0003:0004",
            "fe80::ffff:ffff:ffff:ffff",
        )
        assert result == -1

    def test_iid_compare_greater(self) -> None:
        """iid_compare returns 1 when a > b."""
        result = iid_compare(
            "fe80::ffff:ffff:ffff:ffff",
            "fe80::0001:0002:0003:0004",
        )
        assert result == 1

    def test_iid_compare_equal(self) -> None:
        """iid_compare returns 0 when a == b."""
        result = iid_compare(
            "fe80::1234:5678:9abc:def0",
            "fe80::1234:5678:9abc:def0",
        )
        assert result == 0

    def test_iid_compare_scope_boundaries(self) -> None:
        """Packed-byte ordering spans scopes: loopback < link-local < multicast."""
        # First octet decides: 0x00 (::1) < 0xfe (fe80::) < 0xff (ff02::).
        assert iid_compare("::1", "fe80::0001:0002:0003:0004") == -1
        assert iid_compare("fe80::ffff:ffff:ffff:ffff", "ff02::1") == -1
        assert iid_compare("ff02::1", "ff02::2") == -1

    def test_resolve_slot_conflict_lowest_wins(self) -> None:
        """Slot conflict resolved by lowest IID per GCP-6.3."""
        winner = resolve_slot_conflict(
            "fe80::1234:5678:9abc:def0",  # Lower
            "fe80::abcd:ef01:2345:6789",  # Higher
        )
        assert winner == IPv6Address("fe80::1234:5678:9abc:def0")

    def test_resolve_slot_conflict_reversed_order(self) -> None:
        """Slot conflict resolution is order-independent."""
        winner = resolve_slot_conflict(
            "fe80::abcd:ef01:2345:6789",  # Higher
            "fe80::1234:5678:9abc:def0",  # Lower
        )
        assert winner == IPv6Address("fe80::1234:5678:9abc:def0")

    def test_validate_rpl_instance_id_accepts_valid_range(self) -> None:
        """Valid RPLInstanceIDs pass validation."""
        for instance_id in (0, 1, 127, 128, 255):
            is_valid, reason = validate_rpl_instance_id(instance_id)
            assert is_valid is True, f"id {instance_id}: {reason}"

    def test_validate_rpl_instance_id_out_of_range(self) -> None:
        """RPLInstanceID out of range fails validation."""
        for instance_id in (-1, 256, 1000):
            is_valid, reason = validate_rpl_instance_id(instance_id)
            assert is_valid is False
            assert "Invalid" in reason


class TestGenerateVectors:
    """Tests for test vector generation."""

    def test_generate_vectors_returns_list(self) -> None:
        """generate_multi_instance_vectors returns non-empty list."""
        vectors = generate_multi_instance_vectors()
        assert isinstance(vectors, list)
        assert len(vectors) > 0

    def test_vectors_have_required_fields(self) -> None:
        """Each vector has name, type, and description."""
        vectors = generate_multi_instance_vectors()
        for vec in vectors:
            assert "name" in vec
            assert "type" in vec
            assert "description" in vec

    def test_vector_names_are_unique(self) -> None:
        """Vector names are unique so consumers can look them up by name."""
        names = [vec["name"] for vec in generate_multi_instance_vectors()]
        assert len(names) == len(set(names))

    def test_multi_root_basic_vector(self) -> None:
        """Multi-root basic vector has correct structure."""
        vectors = generate_multi_instance_vectors()
        basic = next(v for v in vectors if v["name"] == "multi_root_basic")

        assert basic["type"] == "coordination"
        assert basic["rpl_instance_id"] == 0
        assert len(basic["gateways"]) == 2
        assert basic["election_rule"] == "lowest_iid"

    def test_slot_conflict_vector(self) -> None:
        """Slot conflict vector matches GCP-6.3 spec."""
        vectors = generate_multi_instance_vectors()
        conflict = next(v for v in vectors if v["name"] == "slot_conflict_iid_resolution")

        assert conflict["type"] == "conflict_resolution"
        # The winner should be the lower IID
        assert conflict["expected_winner"] == "fe80::1234:5678:9abc:def0"
        assert conflict["loser_action"] == "select_next_available"

    def test_iid_comparison_covers_scope_boundaries(self) -> None:
        """Comparison vector covers loopback/link-local/multicast boundaries."""
        comparisons = next(
            v for v in generate_multi_instance_vectors() if v["name"] == "iid_comparison_bytes"
        )["comparisons"]
        addresses = {cmp["a"] for cmp in comparisons} | {cmp["b"] for cmp in comparisons}
        assert "::1" in addresses
        assert any(addr.startswith("fe80:") for addr in addresses)
        assert any(addr.startswith("ff02:") for addr in addresses)


def _load_canonical_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def _gateway_from_entry(entry: dict) -> GatewayInfo:
    return GatewayInfo(
        iid=entry["iid"],
        capabilities={"gps_sync": entry.get("has_gps", False)},
        slot_map={},
        superframe_duration_s=60,
        federation_modes=(),
        routes_learned=entry.get("routes_learned", 0),
    )


class TestCanonicalVectors:
    """Run every case in test/vectors/rpl_multi_instance.json through the oracle.

    The JSON file is the cross-language contract shared with the Rust
    implementation (rust/lichen-rpl/tests/multi_instance_vectors.rs);
    expected values were derived by hand from the spec, never from this
    module's output.
    """

    @pytest.fixture(scope="class")
    def doc(self) -> dict:
        data = _load_canonical_vectors()
        assert data["format_version"] == 2
        return data

    def _get(self, doc: dict, name: str) -> dict:
        return next(v for v in doc["vectors"] if v["name"] == name)

    def test_all_expected_vectors_present(self, doc: dict) -> None:
        """The canonical file carries exactly the generator's vector names."""
        expected = {v["name"] for v in generate_multi_instance_vectors()}
        actual = {v["name"] for v in doc["vectors"]}
        assert actual == expected

    def test_multi_root_basic(self, doc: dict) -> None:
        """Lowest IID is elected time master per GCP-6.1."""
        vec = self._get(doc, "multi_root_basic")
        coord = MultiRootCoordinator(vec["rpl_instance_id"])
        for gw in vec["gateways"]:
            coord.add_peer(_gateway_from_entry(gw))

        master = coord.elect_time_master()
        assert master is not None
        assert str(master.iid) == vec["expected_time_master"]

    def test_slot_conflict_iid_resolution(self, doc: dict) -> None:
        """Slot conflict resolves to lowest IID regardless of order."""
        vec = self._get(doc, "slot_conflict_iid_resolution")
        expected = IPv6Address(vec["expected_winner"])

        assert resolve_slot_conflict(vec["claimant_a"], vec["claimant_b"]) == expected
        assert resolve_slot_conflict(vec["claimant_b"], vec["claimant_a"]) == expected

    def test_dao_backbone_propagation(self, doc: dict) -> None:
        """Backbone message round-trips: queue, receive, aggregate.

        The receiving bridge models gateway B (a different IID than the
        origin gateway A), matching the vector's propagation scenario.
        """
        vec = self._get(doc, "dao_backbone_propagation")
        receiver_iid = "fe80::abcd:ef01:2345:6789"
        coord = MultiRootCoordinator(vec["rpl_instance_id"])
        bridge = DaoBackboneBridge(coordinator=coord, local_gateway_iid=receiver_iid)

        message = {
            "origin_gateway": vec["origin_gateway"],
            "rpl_instance_id": vec["rpl_instance_id"],
            "dao_sequence": vec["dao_sequence"],
            "targets": vec["targets"],
            "transit": vec["transit"],
            "timestamp": 1000.0,
        }

        assert bridge.queue_for_propagation(message) is True
        assert bridge.get_pending_propagations() == [message]

        accepted, reason = bridge.receive_from_peer(
            message,
            authenticated_sender=vec["origin_gateway"],
            current_time=1000.0 + 10,
        )
        assert (accepted, reason) == (True, "stored")

        routes = bridge.get_aggregated_routes()[IPv6Address(vec["origin_gateway"])]
        assert len(routes) == len(vec["targets"])
        target, transit = routes[0]
        assert target.target == IPv6Address(vec["targets"][0]["target"])
        assert target.prefix_length == vec["targets"][0]["prefix_length"]
        assert transit.path_sequence == vec["transit"][0]["path_sequence"]
        assert transit.path_lifetime == vec["transit"][0]["path_lifetime"]
        assert transit.parent_address == IPv6Address(vec["transit"][0]["parent"])

    @pytest.mark.parametrize(
        "name",
        ["dio_validation_same_instance", "dio_validation_different_instance"],
    )
    def test_dio_validation(self, doc: dict, name: str) -> None:
        """DIO validity decisions match the vector expectation."""
        vec = self._get(doc, name)
        coord = MultiRootCoordinator(vec["rpl_instance_id"])
        dio = DIO(
            rpl_instance_id=vec["dio_instance_id"],
            version=1,
            rank=vec["dio_rank"],
            dtsn=0,
            dodag_id=IPv6Address("fe80::1234:5678:9abc:def0"),
        )

        is_valid, reason = coord.validate_dio(dio)
        assert is_valid is vec["expected_valid"]
        if not is_valid:
            assert vec["rejection_reason"] in reason

    def test_dodag_version_lollipop(self, doc: dict) -> None:
        """Lollipop counter wraps 254 -> 255 -> 0 -> 1 per RFC 6550 7.2."""
        vec = self._get(doc, "dodag_version_lollipop")
        coord = MultiRootCoordinator()
        coord.set_dodag_version(vec["initial_version"])

        observed = [coord.increment_dodag_version() for _ in range(vec["increments"])]
        assert observed == vec["expected_versions"]

    def test_three_gateway_federation(self, doc: dict) -> None:
        """Three-way federation elects lowest IID and totals learned routes."""
        vec = self._get(doc, "three_gateway_federation")
        coord = MultiRootCoordinator(vec["rpl_instance_id"])
        for gw in vec["gateways"]:
            coord.add_peer(_gateway_from_entry(gw))

        master = coord.elect_time_master()
        assert master is not None
        assert str(master.iid) == vec["expected_time_master"]
        assert coord.total_aggregated_routes() == vec["total_aggregated_routes"]

    def test_unified_dodag_view(self, doc: dict) -> None:
        """Both roots advertise the shared instance at root rank (GCP-5)."""
        vec = self._get(doc, "unified_dodag_view")
        coord = MultiRootCoordinator(vec["rpl_instance_id"])

        validations = []
        for root in (vec["root_a"], vec["root_b"]):
            dio = DIO(
                rpl_instance_id=vec["rpl_instance_id"],
                version=root["version"],
                rank=root["rank"],
                dtsn=0,
                dodag_id=IPv6Address(root["iid"]),
            )
            validations.append(coord.validate_dio(dio)[0])

        # Both roots valid => node may select either as parent.
        assert all(validations) is vec["node_can_select_either_parent"]

    def test_dodag_version_synchronization(self, doc: dict) -> None:
        """Federation members hold identical versions after one increment."""
        vec = self._get(doc, "dodag_version_synchronization")
        primary = MultiRootCoordinator(vec["rpl_instance_id"])
        secondary = MultiRootCoordinator(vec["rpl_instance_id"])
        for coord in (primary, secondary):
            coord.set_dodag_version(vec["initial_version"])
            coord.increment_dodag_version()

        after = vec["after_increment"]
        assert primary.get_dodag_version() == after["primary_version"]
        assert secondary.get_dodag_version() == after["secondary_version"]
        assert primary.get_dodag_version() == secondary.get_dodag_version()
        assert after["versions_match"] is True

    def test_gateway_role_determination(self, doc: dict) -> None:
        """Roles: standalone without federation, primary iff lowest IID."""
        vec = self._get(doc, "gateway_role_determination")
        for case in vec["test_cases"]:
            coord = MultiRootCoordinator(
                local_gateway=_gateway(case["local_gateway"]),
            )
            for peer in case["peers"]:
                coord.add_peer(_gateway(peer))

            role = coord.get_role()
            assert role.value == case["expected_role"], case["scenario"]

    def test_rpl_instance_id_validation(self, doc: dict) -> None:
        """Range checks accept 0-255 and reject everything else."""
        vec = self._get(doc, "rpl_instance_id_validation")
        for instance_id in vec["valid_ids"]:
            assert validate_rpl_instance_id(instance_id)[0] is True
        for instance_id in vec["invalid_ids"]:
            assert validate_rpl_instance_id(instance_id)[0] is False
        assert MultiRootCoordinator().rpl_instance_id == vec["default_id"]
        with pytest.raises(ValueError):
            MultiRootCoordinator(rpl_instance_id=vec["invalid_ids"][1])

    def test_dao_target_aggregation(self, doc: dict) -> None:
        """Multiple targets aggregate into one backbone message."""
        vec = self._get(doc, "dao_target_aggregation")
        bridge = DaoBackboneBridge(
            coordinator=MultiRootCoordinator(vec["rpl_instance_id"]),
            local_gateway_iid=vec["origin_gateway"],
        )

        message = {
            "origin_gateway": vec["origin_gateway"],
            "rpl_instance_id": vec["rpl_instance_id"],
            "dao_sequence": vec["dao_sequence"],
            "targets": vec["targets"],
            "transit": [],
            "timestamp": 1000.0,
        }

        assert bridge.queue_for_propagation(message) is True
        assert len(message["targets"]) == vec["target_count"]

    def test_iid_comparison_bytes(self, doc: dict) -> None:
        """Packed-byte comparison results and winners match the vectors."""
        vec = self._get(doc, "iid_comparison_bytes")
        for cmp in vec["comparisons"]:
            result = iid_compare(cmp["a"], cmp["b"])
            assert result == cmp["result"], f"{cmp['a']} vs {cmp['b']}"
            if cmp["winner"] != "either":
                winner = resolve_slot_conflict(cmp["a"], cmp["b"])
                assert winner == IPv6Address(cmp["winner"]), f"{cmp['a']} vs {cmp['b']}"

    @pytest.mark.parametrize(
        "name",
        [
            "receive_guard_stale_timestamp",
            "receive_guard_future_timestamp",
            "receive_guard_nan_timestamp",
            "receive_guard_self_origin",
            "receive_guard_origin_auth_mismatch",
            "receive_guard_too_many_routes",
            "receive_guard_peer_limit_reached",
        ],
    )
    def test_receive_from_peer_guards(self, doc: dict, name: str) -> None:
        """GCP-9 guard outcomes match the hand-derived vector expectations.

        Each vector pins one reject path shared with
        rust/lichen-rpl/src/multi_instance.rs::receive_from_peer.
        """
        vec = self._get(doc, name)
        bridge = DaoBackboneBridge(
            coordinator=MultiRootCoordinator(),
            local_gateway_iid=vec["receiver_local_iid"],
        )
        now = vec["current_time"]

        # Replay the saturation preconditions (peer_limit vector): each
        # prior origin stores one minimal valid message.
        for prior in vec["prior_stored_origins"]:
            accepted, reason = bridge.receive_from_peer(
                {
                    "origin_gateway": prior,
                    "rpl_instance_id": 0,
                    "dao_sequence": 0,
                    "targets": [],
                    "transit": [],
                    "timestamp": now - 10.0,
                },
                authenticated_sender=prior,
                current_time=now,
            )
            assert (accepted, reason) == (True, "stored"), prior

        # JSON cannot carry NaN: the "NaN" string sentinel decodes to f64 NaN
        # before evaluation (convention shared with ccp_beacon_sig_gate.json).
        message = dict(vec["message"])
        if message["timestamp"] == "NaN":
            message["timestamp"] = math.nan

        accepted, reason = bridge.receive_from_peer(
            message,
            authenticated_sender=vec["authenticated_sender"],
            current_time=now,
        )
        assert (accepted, reason) == (vec["expected_accepted"], vec["expected_reason"])
