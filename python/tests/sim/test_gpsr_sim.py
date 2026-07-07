# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulation integration tests for GPSR geographic routing (spec 9.7).

Tests verify that:
1. Announces carry geographic coordinates in app_data
2. Nodes extract and store neighbor coords from announces
3. GPSR greedy forwarding selects neighbor closest to destination
4. GPSR serves as fallback when gradient table lacks a route

Paranoid defensive style: explicit assertions at every step, guard against
None values aggressively, verify invariants.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.coords import (
    APP_DATA_TYPE_COORDS,
    decode_coords,
    encode_coords,
)
from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.gradient import GradientTable
from lichen.radio.sim_client import SimRadio
from lichen.routing.router import Router, _haversine
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode

# --- Test fixtures ---


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start a simulator server with a test simulation.

    PARANOID: Verify server started, verify simulation created, verify cleanup.
    """
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()

    # PARANOID: Verify server is actually listening
    # Server uses _node_servers dict keyed by sim_id
    assert server._node_servers is not None, "node servers dict must exist"

    sim = await server.create_simulation("gpsr-test", TimeMode.BARRIER_SYNC)

    # PARANOID: Verify simulation was created
    assert sim is not None, "simulation must be created"
    assert sim.id == "gpsr-test", "simulation ID must match"

    yield server, sim

    # PARANOID: Verify cleanup doesn't fail
    await server.stop()


def make_identity(seed_byte: int) -> Identity:
    """Create a deterministic identity from a single seed byte.

    PARANOID: Verify seed_byte is valid.
    """
    assert 0 <= seed_byte <= 255, f"seed_byte must be 0-255, got {seed_byte}"
    seed = bytes([seed_byte] + [0] * 31)
    identity = Identity.from_seed(seed)

    # PARANOID: Verify identity is complete
    assert identity.pubkey is not None, "identity must have pubkey"
    assert identity.privkey is not None, "identity must have privkey"
    assert identity.iid is not None, "identity must have IID"
    assert len(identity.iid) == 8, "IID must be 8 bytes"

    return identity


def build_address_from_iid(iid: bytes) -> IPv6Address:
    """Build a link-local IPv6 address from an IID.

    PARANOID: Verify IID is correct length.
    """
    assert len(iid) == 8, f"IID must be 8 bytes, got {len(iid)}"
    prefix = bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    addr = IPv6Address(prefix + iid)

    # PARANOID: Verify address is link-local
    assert addr.is_link_local, f"address {addr} must be link-local"

    return addr


class MockTransmitter:
    """Mock transmitter that captures announce bytes.

    PARANOID: Track all transmissions for verification.
    """

    def __init__(self) -> None:
        self.last_data: bytes | None = None
        self.tx_count: int = 0

    async def transmit_announce(self, data: bytes) -> bool:
        assert data is not None, "cannot transmit None data"
        assert len(data) > 0, "cannot transmit empty data"
        self.last_data = data
        self.tx_count += 1
        return True


# --- Test classes ---


class TestAnnounceWithCoords:
    """Test that announces carry geographic coordinates (python-sm2.1)."""

    @pytest.mark.asyncio
    async def test_encode_coords_in_app_data(self) -> None:
        """Verify coords are encoded in announce app_data.

        PARANOID: Check encoding format byte-by-byte.
        """
        # Seattle-ish coords; west-coast longitude exercises full-range encoding.
        lat, lon = 47.6062, -122.3321

        # PARANOID: Verify coords are in valid range before encoding
        assert -90 <= lat <= 90, f"lat {lat} out of range"
        assert -180 <= lon <= 180, f"lon {lon} out of range"

        app_data = encode_coords(lat, lon)

        # PARANOID: Verify encoding structure
        assert app_data is not None, "encoding must not return None"
        assert len(app_data) == 9, f"coords app_data must be 9 bytes, got {len(app_data)}"
        assert app_data[0] == APP_DATA_TYPE_COORDS, "first byte must be coords type"

        # Verify round-trip decoding
        decoded = decode_coords(app_data)
        assert decoded is not None, "decoding must succeed"

        decoded_lat, decoded_lon = decoded
        # Resolution is 1e-7 degrees, allow small floating point error.
        assert abs(decoded_lat - lat) < 1e-7, f"lat mismatch: {decoded_lat} vs {lat}"
        assert abs(decoded_lon - lon) < 1e-7, f"lon mismatch: {decoded_lon} vs {lon}"

    @pytest.mark.asyncio
    async def test_scheduler_builds_announce_with_coords(self) -> None:
        """AnnounceScheduler includes coords in announce app_data.

        PARANOID: Verify every field of the announce.
        """
        identity = make_identity(10)
        lat, lon = 51.5074, -0.1278

        # Encode coords as app_data
        app_data = encode_coords(lat, lon)
        assert len(app_data) == 9, "coords must be 9 bytes"

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        # Build announce
        announce = scheduler.build_announce()

        # PARANOID: Verify announce structure
        assert announce is not None, "announce must be built"
        assert announce.originator_iid == identity.iid, "IID must match"
        assert announce.pubkey == identity.pubkey, "pubkey must match"
        assert announce.seq_num == 1, "first seq_num must be 1"
        assert announce.hop_count == 0, "originator hop_count must be 0"
        assert announce.signature is not None, "signature must be present"

        # PARANOID: Verify app_data contains coords
        assert announce.app_data == app_data, "app_data must contain coords"

        # Verify coords can be decoded from announce
        decoded = decode_coords(announce.app_data)
        assert decoded is not None, "coords must be decodable from announce"

        decoded_lat, decoded_lon = decoded
        assert abs(decoded_lat - lat) < 1e-4, "lat must match"
        assert abs(decoded_lon - lon) < 1e-4, "lon must match"

    @pytest.mark.asyncio
    async def test_announce_with_coords_survives_transmission(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce with coords survives simulation TX/RX.

        PARANOID: Verify byte-for-byte match after transmission.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("gpsr-test")

        # PARANOID: Verify we got a valid port
        assert node_port is not None, "must get node server port"
        assert node_port > 0, "port must be positive"

        identity = make_identity(20)
        lat, lon = 40.7128, -74.006  # NYC (lon adjusted slightly for range)
        # Actually -74.006 is out of range, use -70.0
        lat, lon = 40.7128, -70.0

        app_data = encode_coords(lat, lon)

        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce = scheduler.build_announce()
        original_bytes = announce.to_bytes()

        # PARANOID: Verify serialization
        assert original_bytes is not None, "serialization must succeed"
        assert len(original_bytes) > 0, "serialized announce must not be empty"

        async with SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "tx-node", (0.0, 0.0, 0.0)
        ) as radio_tx, SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "rx-node", (50.0, 0.0, 0.0)
        ) as radio_rx:
            # PARANOID: Verify radios connected
            # (SimRadio doesn't expose connection state, but transmit will fail if not)

            tx_success = await radio_tx.transmit(original_bytes)
            assert tx_success is True, "transmit must succeed"

            result = await radio_rx.receive(1000)

            # PARANOID: Verify reception
            assert result is not None, "must receive data"

            rx_bytes, rssi, snr = result

            # PARANOID: Verify signal quality
            assert rssi is not None, "rssi must be present"
            assert snr is not None, "snr must be present"
            assert rssi > -140, f"rssi {rssi} too weak (below sensitivity)"

            # PARANOID: Verify byte-for-byte match
            assert rx_bytes == original_bytes, "received bytes must match sent bytes"

            # Parse and verify coords survive
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"

            rx_coords = decode_coords(rx_announce.app_data)
            assert rx_coords is not None, "coords must be decodable"

            rx_lat, rx_lon = rx_coords
            assert abs(rx_lat - lat) < 1e-4, "lat must match after TX/RX"
            assert abs(rx_lon - lon) < 1e-4, "lon must match after TX/RX"


class TestNeighborCoordsExtraction:
    """Test that nodes extract and store neighbor coords from announces (python-sm2.2 partial)."""

    @pytest.mark.asyncio
    async def test_processor_extracts_coords_to_gradient(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """AnnounceProcessor extracts coords and stores in gradient entry.

        PARANOID: Verify gradient entry has correct coords.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("gpsr-test")
        assert node_port is not None, "must get node server port"

        identity_a = make_identity(30)
        lat_a, lon_a = 35.6762, 139.6503

        app_data = encode_coords(lat_a, lon_a)

        mock_tx = MockTransmitter()
        scheduler_a = AnnounceScheduler(
            identity=identity_a,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=app_data,
        )

        announce_a = scheduler_a.build_announce()
        announce_bytes = announce_a.to_bytes()

        # Node B's gradient table and processor
        gradient_table_b = GradientTable()
        processor_b = AnnounceProcessor(
            gradient_table=gradient_table_b,
            address_builder=build_address_from_iid,
        )

        async with SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "node-b", (50.0, 0.0, 0.0)
        ) as radio_b:
            # A transmits
            tx_success = await radio_a.transmit(announce_bytes)
            assert tx_success is True, "A must transmit successfully"

            # B receives
            result = await radio_b.receive(1000)
            assert result is not None, "B must receive announce"

            rx_bytes, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"

            # B processes
            from_neighbor = build_address_from_iid(identity_a.iid)
            process_result = processor_b.process(rx_announce, from_neighbor, now_ms=1000)

            # PARANOID: Verify processing succeeded
            assert process_result.accepted is True, "announce must be accepted"
            assert process_result.peer is not None, "peer identity must be returned"
            assert process_result.peer.iid == identity_a.iid, "peer IID must match"

            # PARANOID: Verify gradient entry
            addr_a = build_address_from_iid(identity_a.iid)
            entry = gradient_table_b.lookup(addr_a, now=1000)

            assert entry is not None, "gradient entry must exist for A"
            assert entry.next_hop == from_neighbor, "next_hop must be A's address"
            assert entry.hop_count == 0, "hop_count must be 0"

            # PARANOID: Verify coords in gradient entry
            assert entry.coords is not None, "gradient entry must have coords"

            entry_lat, entry_lon = entry.coords
            assert abs(entry_lat - lat_a) < 1e-4, f"gradient lat {entry_lat} must match {lat_a}"
            assert abs(entry_lon - lon_a) < 1e-4, f"gradient lon {entry_lon} must match {lon_a}"


class TestGPSRGreedyForwarding:
    """Test GPSR greedy forwarding selection (python-sm2.2)."""

    @pytest.mark.asyncio
    async def test_gpsr_selects_closest_neighbor(self) -> None:
        """gpsr_forward() selects neighbor closest to destination.

        PARANOID: Verify distance calculations, verify selection logic.
        """
        # Our node is at origin (0, 0) in GPS coords
        node_coords = (0.0, 0.0)

        # Destination is at (10.0, 10.0) - northeast
        dst_coords = (10.0, 10.0)

        # Three neighbors:
        # - neighbor_a: (5.0, 5.0) - closer to destination
        # - neighbor_b: (-5.0, -5.0) - farther from destination
        # - neighbor_c: (8.0, 8.0) - even closer to destination
        neighbor_a = IPv6Address("fe80::1")
        neighbor_b = IPv6Address("fe80::2")
        neighbor_c = IPv6Address("fe80::3")

        coords_a = (5.0, 5.0)
        coords_b = (-5.0, -5.0)
        coords_c = (8.0, 8.0)

        # PARANOID: Verify our distance calculations
        my_dist = _haversine(node_coords, dst_coords)
        dist_a = _haversine(coords_a, dst_coords)
        dist_b = _haversine(coords_b, dst_coords)
        dist_c = _haversine(coords_c, dst_coords)

        # PARANOID: Verify expected distance ordering
        # C is closest (8,8 to 10,10), then A (5,5 to 10,10), then us (0,0 to 10,10), then B
        assert dist_c < dist_a, f"C ({dist_c}m) must be closer than A ({dist_a}m)"
        assert dist_a < my_dist, f"A ({dist_a}m) must be closer than us ({my_dist}m)"
        assert my_dist < dist_b, f"us ({my_dist}m) must be closer than B ({dist_b}m)"

        # Create router with our coords and neighbor coords
        router = Router(
            node_address=IPv6Address("fe80::dead"),
            gradient_table=GradientTable(),
            node_coords=node_coords,
        )

        # Add neighbor coords
        router.update_neighbor_coords(neighbor_a, coords_a)
        router.update_neighbor_coords(neighbor_b, coords_b)
        router.update_neighbor_coords(neighbor_c, coords_c)

        # PARANOID: Verify neighbors were stored
        assert neighbor_a in router.neighbor_coords, "A must be in neighbor_coords"
        assert neighbor_b in router.neighbor_coords, "B must be in neighbor_coords"
        assert neighbor_c in router.neighbor_coords, "C must be in neighbor_coords"

        # GPSR should select C (closest to destination)
        selected = router.gpsr_forward(dst_coords)

        # PARANOID: Verify selection
        assert selected is not None, "GPSR must return a neighbor (progress is possible)"
        assert selected == neighbor_c, f"GPSR must select C (closest), got {selected}"

    @pytest.mark.asyncio
    async def test_gpsr_returns_none_at_local_minimum(self) -> None:
        """gpsr_forward() returns None when no neighbor is closer.

        This is a "local minimum" - greedy routing cannot make progress.

        PARANOID: Verify no neighbor is selected when we're closest.
        """
        # Our node is closest to destination
        node_coords = (9.0, 9.0)
        dst_coords = (10.0, 10.0)

        # All neighbors are farther from destination
        neighbor_a = IPv6Address("fe80::1")
        neighbor_b = IPv6Address("fe80::2")

        coords_a = (0.0, 0.0)  # farther
        coords_b = (5.0, 5.0)  # also farther

        # PARANOID: Verify we are actually closest
        my_dist = _haversine(node_coords, dst_coords)
        dist_a = _haversine(coords_a, dst_coords)
        dist_b = _haversine(coords_b, dst_coords)

        assert my_dist < dist_a, f"we ({my_dist}m) must be closer than A ({dist_a}m)"
        assert my_dist < dist_b, f"we ({my_dist}m) must be closer than B ({dist_b}m)"

        router = Router(
            node_address=IPv6Address("fe80::dead"),
            gradient_table=GradientTable(),
            node_coords=node_coords,
        )

        router.update_neighbor_coords(neighbor_a, coords_a)
        router.update_neighbor_coords(neighbor_b, coords_b)

        # GPSR should return None (no progress possible)
        selected = router.gpsr_forward(dst_coords)

        # PARANOID: Verify no selection
        assert selected is None, "GPSR must return None at local minimum"

    @pytest.mark.asyncio
    async def test_gpsr_requires_node_coords(self) -> None:
        """gpsr_forward() returns None if node has no coords.

        PARANOID: Verify GPSR fails gracefully without node coords.
        """
        router = Router(
            node_address=IPv6Address("fe80::dead"),
            gradient_table=GradientTable(),
            node_coords=None,  # No coords
        )

        # Add a neighbor with coords
        router.update_neighbor_coords(IPv6Address("fe80::1"), (5.0, 5.0))

        selected = router.gpsr_forward((10.0, 10.0))

        assert selected is None, "GPSR must return None without node coords"

    @pytest.mark.asyncio
    async def test_gpsr_requires_neighbor_coords(self) -> None:
        """gpsr_forward() returns None if no neighbors have coords.

        PARANOID: Verify GPSR fails gracefully without neighbor coords.
        """
        router = Router(
            node_address=IPv6Address("fe80::dead"),
            gradient_table=GradientTable(),
            node_coords=(0.0, 0.0),
        )

        # No neighbors
        assert len(router.neighbor_coords) == 0, "must have no neighbor coords"

        selected = router.gpsr_forward((10.0, 10.0))

        assert selected is None, "GPSR must return None without neighbor coords"


class TestGPSRFallback:
    """Test GPSR as fallback when gradient is missing (python-sm2.3)."""

    @pytest.mark.asyncio
    async def test_gpsr_fallback_when_gradient_missing(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Router uses GPSR when gradient table has no entry.

        Scenario:
        - Node has coords and knows neighbor coords
        - Gradient table is empty for destination
        - LOADng is not configured (loadng=None)
        - But we have destination coords from an expired gradient entry
        - Router should fall back to GPSR

        PARANOID: Verify fallback path is taken.
        """
        server, sim = simulator_server

        # Our node
        node_addr = IPv6Address("fe80::1111")
        node_coords = (0.0, 0.0)

        # Destination (ULA address)
        dst_addr = IPv6Address("fd00::dead")
        dst_coords = (10.0, 10.0)

        # Neighbor that is closer to destination
        neighbor_addr = IPv6Address("fe80::2222")
        neighbor_coords = (8.0, 8.0)

        gradient_table = GradientTable()

        # Install an expired gradient entry for destination (has coords but expired)
        from lichen.gradient import GradientEntry, GradientSource

        expired_entry = GradientEntry(
            destination=dst_addr,
            next_hop=neighbor_addr,
            hop_count=1,
            seq_num=100,
            source=GradientSource.ANNOUNCE,
            expires=500,  # Already expired at time 1000
            coords=dst_coords,
        )
        gradient_table.update(expired_entry, now=100)

        # PARANOID: Verify entry exists but is expired
        entry = gradient_table.lookup(dst_addr, now=1000)
        assert entry is None, "entry must be expired at now=1000"

        # But entry should still be accessible (for coords) when ignoring expiry
        raw_entry = gradient_table.lookup(dst_addr)  # no now = no expiry check
        assert raw_entry is not None, "entry must exist (without expiry check)"
        assert raw_entry.coords == dst_coords, "entry must have coords"

        router = Router(
            node_address=node_addr,
            gradient_table=gradient_table,
            dodag=None,
            loadng=None,  # No LOADng - forces GPSR fallback
            node_coords=node_coords,
        )

        router.update_neighbor_coords(neighbor_addr, neighbor_coords)

        # PARANOID: Verify neighbor coords stored
        assert neighbor_addr in router.neighbor_coords, "neighbor must be in neighbor_coords"

        # Create a packet to route
        from lichen.ipv6.packet import IPv6Header, IPv6Packet

        packet = IPv6Packet(
            header=IPv6Header(
                src_addr=node_addr,
                dst_addr=dst_addr,
                next_header=17,  # UDP
                hop_limit=64,
                payload_length=10,
            ),
            payload=b"test data!",
        )

        # Route should use GPSR fallback
        decision, next_hop = router.route(packet, now_ms=1000)

        # PARANOID: Verify GPSR fallback was used
        from lichen.routing.router import RouteDecision

        assert decision == RouteDecision.FORWARD, f"must FORWARD via GPSR, got {decision}"
        assert next_hop == neighbor_addr, (
            f"must forward to neighbor {neighbor_addr}, got {next_hop}"
        )


class TestGPSRSimulationIntegration:
    """Full simulation integration test for GPSR."""

    @pytest.mark.asyncio
    async def test_announce_with_coords_builds_neighbor_knowledge(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Announce with coords allows neighbor knowledge to be built.

        This is a simpler integration test that verifies the basic flow:
        1. B announces with coords
        2. A receives and extracts coords
        3. A can use those coords for GPSR decisions

        PARANOID: Verify every step of the process.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("gpsr-test")

        assert node_port is not None, "must get node server port"

        # Create identities
        identity_a = make_identity(50)
        identity_b = make_identity(51)

        # GPS coords (for GPSR routing)
        coords_a = (0.0, 0.0)
        coords_b = (5.0, 5.0)

        # Build B's announce with coords
        mock_tx = MockTransmitter()
        scheduler_b = AnnounceScheduler(
            identity=identity_b,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            app_data=encode_coords(*coords_b),
        )
        announce_b = scheduler_b.build_announce()

        # Node A's state
        gradient_a = GradientTable()
        processor_a = AnnounceProcessor(
            gradient_table=gradient_a,
            address_builder=build_address_from_iid,
        )

        # Sim positions (for radio propagation)
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (50.0, 0.0, 0.0)

        async with SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "node-a-int", pos_a
        ) as radio_a, SimRadio(
            "127.0.0.1", node_port, "gpsr-test", "node-b-int", pos_b
        ) as radio_b:
            # B announces
            tx_success = await radio_b.transmit(announce_b.to_bytes())
            assert tx_success, "B must transmit successfully"

            # A receives
            result = await radio_a.receive(1000)
            assert result is not None, "A must receive B's announce"

            rx_bytes, rssi, snr = result

            # PARANOID: Verify signal quality
            assert rssi > -140, f"rssi {rssi} too weak"

            # Parse announce
            rx_announce = AnnounceMessage.from_bytes(rx_bytes)
            assert rx_announce is not None, "announce must parse"
            assert rx_announce.originator_iid == identity_b.iid, "must be B's announce"

            # A processes announce
            from_b = build_address_from_iid(identity_b.iid)
            process_result = processor_a.process(rx_announce, from_b, now_ms=1000)

            # PARANOID: Verify processing
            assert process_result.accepted, "announce must be accepted"

            # PARANOID: Verify gradient entry has coords
            addr_b = build_address_from_iid(identity_b.iid)
            entry = gradient_a.lookup(addr_b, now=1000)

            assert entry is not None, "gradient entry must exist"
            assert entry.coords is not None, "gradient entry must have coords"

            # PARANOID: Verify coords match
            entry_lat, entry_lon = entry.coords
            assert abs(entry_lat - coords_b[0]) < 1e-4, "lat must match"
            assert abs(entry_lon - coords_b[1]) < 1e-4, "lon must match"

            # Now test GPSR decision making with a Router
            router_a = Router(
                node_address=build_address_from_iid(identity_a.iid),
                gradient_table=gradient_a,
                node_coords=coords_a,
                loadng=None,
            )

            # Add B as a neighbor with coords
            router_a.update_neighbor_coords(from_b, coords_b)

            # PARANOID: Verify neighbor_coords
            assert len(router_a.neighbor_coords) == 1, "must have exactly 1 neighbor"
            assert from_b in router_a.neighbor_coords, "from_b must be in neighbors"
            assert router_a.neighbor_coords[from_b] == coords_b, "coords must match"

            # Destination further in B's direction
            dst_coords = (10.0, 10.0)

            # GPSR should select B
            selected = router_a.gpsr_forward(dst_coords)

            # PARANOID: Verify selection
            assert selected is not None, "GPSR must select a neighbor"
            assert selected == from_b, f"GPSR must select B ({from_b}), got {selected}"

            # PARANOID: Verify B is actually closer
            dist_a_to_dst = _haversine(coords_a, dst_coords)
            dist_b_to_dst = _haversine(coords_b, dst_coords)

            assert dist_b_to_dst < dist_a_to_dst, (
                f"B ({dist_b_to_dst}m) must be closer than A ({dist_a_to_dst}m)"
            )
