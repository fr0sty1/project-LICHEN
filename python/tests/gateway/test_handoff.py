# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for node handoff protocol (GCP-7)."""

from __future__ import annotations

import time
from ipaddress import IPv6Address

import cbor2
import pytest

from lichen.gateway.handoff import (
    FreshnessState,
    HandoffError,
    HandoffRejectReason,
    HandoffRequest,
    HandoffResponse,
    NodeRegistry,
    OscoreState,
)


class TestOscoreState:
    """Tests for OscoreState serialization."""

    @pytest.fixture
    def oscore_state(self) -> OscoreState:
        return OscoreState(
            master_secret=b"\x01" * 16,
            master_salt=b"\x02" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            algorithm=10,  # AES-CCM-16-64-128
            hashfun="SHA-256",
            window_size=32,
            id_context=None,
            sender_sequence=12345,
            replay_index=100,
            replay_bitfield=0xFFFFFFFF,
        )

    def test_roundtrip(self, oscore_state: OscoreState) -> None:
        """OSCORE state survives encode/decode roundtrip."""
        cbor_map = oscore_state.to_cbor_map()
        decoded = OscoreState.from_cbor_map(cbor_map)
        assert decoded == oscore_state

    def test_with_id_context(self) -> None:
        """OSCORE state with id_context roundtrips correctly."""
        state = OscoreState(
            master_secret=b"secret",
            master_salt=b"salt",
            sender_id=b"\x00",
            recipient_id=b"\x01",
            algorithm=10,
            hashfun="SHA-256",
            window_size=32,
            id_context=b"context123",
            sender_sequence=999,
            replay_index=50,
            replay_bitfield=0,
        )
        cbor_map = state.to_cbor_map()
        decoded = OscoreState.from_cbor_map(cbor_map)
        assert decoded.id_context == b"context123"

    def test_missing_field_raises(self) -> None:
        """Missing required field raises HandoffError."""
        incomplete = {4: {1: b"secret"}}  # Missing most fields
        with pytest.raises(HandoffError, match="malformed OSCORE state"):
            OscoreState.from_cbor_map(incomplete)


class TestFreshnessState:
    """Tests for FreshnessState serialization."""

    def test_roundtrip(self) -> None:
        """Freshness state survives encode/decode roundtrip."""
        state = FreshnessState(
            sequence=42,
            active_until=1000.0,
            retain_until=2000.0,
            updated_at=500.0,
        )
        cbor_map = state.to_cbor_map()
        decoded = FreshnessState.from_cbor_map(cbor_map)
        assert decoded == state

    def test_none_active_until(self) -> None:
        """Freshness state with None active_until roundtrips correctly."""
        state = FreshnessState(
            sequence=0,
            active_until=None,
            retain_until=1000.0,
            updated_at=0.0,
        )
        cbor_map = state.to_cbor_map()
        assert "active" not in cbor_map
        decoded = FreshnessState.from_cbor_map(cbor_map)
        assert decoded.active_until is None


class TestHandoffRequest:
    """Tests for HandoffRequest serialization."""

    def test_roundtrip(self) -> None:
        """Handoff request survives encode/decode roundtrip."""
        request = HandoffRequest(
            node_address=IPv6Address("fe80::1"),
            timestamp=1234567890,
            rssi=-75,
        )
        encoded = request.encode()
        decoded = HandoffRequest.decode(encoded)
        assert decoded.node_address == request.node_address
        assert decoded.timestamp == request.timestamp
        assert decoded.rssi == request.rssi

    def test_without_rssi(self) -> None:
        """Handoff request without RSSI roundtrips correctly."""
        request = HandoffRequest(
            node_address=IPv6Address("2001:db8::1"),
            timestamp=1000,
        )
        decoded = HandoffRequest.decode(request.encode())
        assert decoded.rssi is None

    def test_invalid_cbor(self) -> None:
        """Invalid CBOR raises HandoffError."""
        # Use truncated CBOR (array of 5 elements but only 1 provided)
        with pytest.raises(HandoffError, match="invalid CBOR"):
            HandoffRequest.decode(b"\x85\x01")

    def test_non_map_raises(self) -> None:
        """Non-map CBOR raises HandoffError."""
        with pytest.raises(HandoffError, match="expected CBOR map"):
            HandoffRequest.decode(cbor2.dumps([1, 2, 3]))

    def test_missing_timestamp_raises(self) -> None:
        """Missing timestamp raises HandoffError."""
        payload = cbor2.dumps({1: IPv6Address("fe80::1").packed})
        with pytest.raises(HandoffError, match="malformed request"):
            HandoffRequest.decode(payload)


class TestHandoffResponse:
    """Tests for HandoffResponse serialization."""

    @pytest.fixture
    def oscore_state(self) -> OscoreState:
        return OscoreState(
            master_secret=b"\x01" * 16,
            master_salt=b"\x02" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            algorithm=10,
            hashfun="SHA-256",
            window_size=32,
            id_context=None,
            sender_sequence=100,
            replay_index=50,
            replay_bitfield=0,
        )

    @pytest.fixture
    def freshness_state(self) -> FreshnessState:
        return FreshnessState(
            sequence=10,
            active_until=1000.0,
            retain_until=2000.0,
            updated_at=500.0,
        )

    def test_success_response_roundtrip(
        self, oscore_state: OscoreState, freshness_state: FreshnessState
    ) -> None:
        """Successful handoff response survives roundtrip."""
        response = HandoffResponse.success(
            node_address=IPv6Address("fe80::1"),
            dao_sequence=42,
            path_sequence=10,
            oscore_state=oscore_state,
            freshness=freshness_state,
            parents=(IPv6Address("fe80::2"), IPv6Address("fe80::3")),
        )
        decoded = HandoffResponse.decode(response.encode())
        assert decoded.status == HandoffRejectReason.SUCCESS
        assert decoded.node_address == IPv6Address("fe80::1")
        assert decoded.dao_sequence == 42
        assert decoded.path_sequence == 10
        assert decoded.oscore_state == oscore_state
        assert decoded.freshness == freshness_state
        assert decoded.parents == (IPv6Address("fe80::2"), IPv6Address("fe80::3"))

    def test_error_response_roundtrip(self) -> None:
        """Error response survives roundtrip."""
        response = HandoffResponse.error(
            HandoffRejectReason.NODE_NOT_FOUND,
            "node fe80::1 not in registry",
        )
        decoded = HandoffResponse.decode(response.encode())
        assert decoded.status == HandoffRejectReason.NODE_NOT_FOUND
        assert decoded.message == "node fe80::1 not in registry"
        assert decoded.node_address is None
        assert decoded.oscore_state is None

    def test_error_factory_rejects_success(self) -> None:
        """error() factory rejects SUCCESS status."""
        with pytest.raises(ValueError, match="use success"):
            HandoffResponse.error(HandoffRejectReason.SUCCESS)

    def test_minimal_success_response(self) -> None:
        """Success response with only required fields works."""
        response = HandoffResponse.success(
            node_address=IPv6Address("fe80::1"),
            dao_sequence=0,
            path_sequence=0,
        )
        decoded = HandoffResponse.decode(response.encode())
        assert decoded.status == HandoffRejectReason.SUCCESS
        assert decoded.oscore_state is None
        assert decoded.freshness is None
        assert decoded.parents == ()


class TestNodeRegistry:
    """Tests for NodeRegistry operations."""

    @pytest.fixture
    def registry(self) -> NodeRegistry:
        return NodeRegistry()

    @pytest.fixture
    def node_address(self) -> IPv6Address:
        return IPv6Address("fe80::1234:5678:9abc:def0")

    @pytest.fixture
    def oscore_state(self) -> OscoreState:
        return OscoreState(
            master_secret=b"\x01" * 16,
            master_salt=b"\x02" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            algorithm=10,
            hashfun="SHA-256",
            window_size=32,
            id_context=None,
            sender_sequence=100,
            replay_index=50,
            replay_bitfield=0,
        )

    def test_register_and_get(self, registry: NodeRegistry, node_address: IPv6Address) -> None:
        """Register a node and retrieve it."""
        registry.register(node_address, dao_sequence=42, path_sequence=10)
        entry = registry.get(node_address)
        assert entry is not None
        assert entry.address == node_address
        assert entry.dao_sequence == 42
        assert entry.path_sequence == 10

    def test_unregister(self, registry: NodeRegistry, node_address: IPv6Address) -> None:
        """Unregister removes node from registry."""
        registry.register(node_address)
        entry = registry.unregister(node_address)
        assert entry is not None
        assert registry.get(node_address) is None
        assert node_address not in registry

    def test_contains(self, registry: NodeRegistry, node_address: IPv6Address) -> None:
        """Contains check works."""
        assert node_address not in registry
        registry.register(node_address)
        assert node_address in registry
        assert registry.contains(node_address)

    def test_len(self, registry: NodeRegistry) -> None:
        """Length reflects registered node count."""
        assert len(registry) == 0
        registry.register(IPv6Address("fe80::1"))
        assert len(registry) == 1
        registry.register(IPv6Address("fe80::2"))
        assert len(registry) == 2

    def test_list_nodes(self, registry: NodeRegistry) -> None:
        """list_nodes returns all registered addresses."""
        addrs = [IPv6Address(f"fe80::{i}") for i in range(3)]
        for addr in addrs:
            registry.register(addr)
        assert set(registry.list_nodes()) == set(addrs)


class TestHandoffProtocol:
    """Tests for the complete handoff protocol flow."""

    @pytest.fixture
    def source_registry(self) -> NodeRegistry:
        return NodeRegistry()

    @pytest.fixture
    def dest_registry(self) -> NodeRegistry:
        return NodeRegistry()

    @pytest.fixture
    def node_address(self) -> IPv6Address:
        return IPv6Address("fe80::1234:5678:9abc:def0")

    @pytest.fixture
    def oscore_state(self) -> OscoreState:
        return OscoreState(
            master_secret=b"secret_key_here!",
            master_salt=b"saltsalt",
            sender_id=b"\x00",
            recipient_id=b"\x01",
            algorithm=10,
            hashfun="SHA-256",
            window_size=32,
            id_context=None,
            sender_sequence=100,
            replay_index=50,
            replay_bitfield=0xFFFF,
        )

    def test_successful_handoff(
        self,
        source_registry: NodeRegistry,
        dest_registry: NodeRegistry,
        node_address: IPv6Address,
        oscore_state: OscoreState,
    ) -> None:
        """Complete handoff transfers node from source to destination."""
        # Setup: node is registered at source
        source_registry.register(
            node_address,
            dao_sequence=42,
            path_sequence=10,
            oscore_state=oscore_state,
            parents=(IPv6Address("fe80::ff"),),
        )
        assert node_address in source_registry
        assert node_address not in dest_registry

        # Step 1: Destination gateway sends handoff request
        request = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
            rssi=-65,
        )

        # Step 2: Source gateway processes request
        response = source_registry.handle_handoff_request(request)
        assert response.status == HandoffRejectReason.SUCCESS
        assert response.node_address == node_address
        assert response.dao_sequence == 42
        assert response.path_sequence == 10
        assert response.oscore_state == oscore_state
        assert node_address not in source_registry  # Removed from source

        # Step 3: Destination accepts handoff
        dest_registry.accept_handoff(response)
        assert node_address in dest_registry

        # Verify sequence numbers were incremented for safety
        entry = dest_registry.get(node_address)
        assert entry is not None
        assert entry.dao_sequence == 43  # 42 + 1
        assert entry.path_sequence == 11  # 10 + 1
        assert entry.oscore_state is not None
        assert entry.oscore_state.sender_sequence == 101  # 100 + 1

    def test_handoff_node_not_found(
        self, source_registry: NodeRegistry, node_address: IPv6Address
    ) -> None:
        """Handoff request for unknown node returns NODE_NOT_FOUND."""
        request = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        )
        response = source_registry.handle_handoff_request(request)
        assert response.status == HandoffRejectReason.NODE_NOT_FOUND

    def test_handoff_node_busy(
        self, source_registry: NodeRegistry, node_address: IPv6Address
    ) -> None:
        """Handoff request for busy node returns NODE_BUSY."""
        source_registry.register(node_address, dao_sequence=10, path_sequence=5)
        source_registry.set_busy(node_address, True)

        request = HandoffRequest(
            node_address=node_address,
            timestamp=int(time.time()),
        )
        response = source_registry.handle_handoff_request(request)
        assert response.status == HandoffRejectReason.NODE_BUSY
        # Node should still be in registry (not released)
        assert node_address in source_registry

    def test_accept_handoff_rejects_failure(self, dest_registry: NodeRegistry) -> None:
        """accept_handoff rejects non-success responses."""
        error_response = HandoffResponse.error(
            HandoffRejectReason.NODE_NOT_FOUND,
            "node not found",
        )
        with pytest.raises(HandoffError, match="cannot accept failed handoff"):
            dest_registry.accept_handoff(error_response)

    def test_wire_format_roundtrip(
        self, source_registry: NodeRegistry, node_address: IPv6Address, oscore_state: OscoreState
    ) -> None:
        """Handoff messages survive CBOR encode/decode over the wire."""
        source_registry.register(
            node_address,
            dao_sequence=100,
            path_sequence=50,
            oscore_state=oscore_state,
        )

        # Simulate wire transfer: encode request, decode on other side
        request = HandoffRequest(node_address=node_address, timestamp=1000)
        wire_request = request.encode()
        received_request = HandoffRequest.decode(wire_request)

        # Process and encode response
        response = source_registry.handle_handoff_request(received_request)
        wire_response = response.encode()
        received_response = HandoffResponse.decode(wire_response)

        assert received_response.status == HandoffRejectReason.SUCCESS
        assert received_response.dao_sequence == 100
        assert received_response.oscore_state == oscore_state


class TestHandoffRejectReason:
    """Tests for HandoffRejectReason enum."""

    def test_all_reasons_have_int_values(self) -> None:
        """All reject reasons can be converted to int for wire format."""
        for reason in HandoffRejectReason:
            assert isinstance(int(reason), int)

    def test_reasons_are_distinct(self) -> None:
        """All reject reasons have distinct values."""
        values = [int(r) for r in HandoffRejectReason]
        assert len(values) == len(set(values))
