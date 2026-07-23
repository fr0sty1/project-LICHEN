# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for hybrid router.

Why these tests: The router is the core decision point for packet forwarding.
Bugs here mean:
- Packets sent to wrong destinations (routing failure)
- External traffic not reaching border router (connectivity failure)
- Mesh traffic not discovered (peer-to-peer failure)
- Link-local traffic mishandled (neighbor communication failure)

Test categories:
1. Address classification
2. Route decisions by address class
3. Gradient table integration
4. Pending packet queue management
5. RPL parent routing
6. LOADng discovery integration
"""

from ipaddress import IPv6Address

import pytest

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.routing.router import (
    AddressClass,
    RouteDecision,
    Router,
)
from lichen.rpl.dodag import DodagRole, DodagState


def make_packet(dst: str, src: str = "fe80::1") -> IPv6Packet:
    """Create a minimal IPv6 packet for testing."""
    return IPv6Packet(
        header=IPv6Header(
            src_addr=IPv6Address(src),
            dst_addr=IPv6Address(dst),
            next_header=17,  # UDP
            payload_length=0,
        ),
        payload=b"",
    )


@pytest.fixture
def gradient_table() -> GradientTable:
    """An empty gradient table."""
    return GradientTable()


@pytest.fixture
def router(gradient_table: GradientTable) -> Router:
    """A router with minimal configuration."""
    return Router(
        node_address=IPv6Address("fd00::1"),
        gradient_table=gradient_table,
    )


class TestAddressClassification:
    """Tests for classify_address()."""

    def test_link_local_fe80(self, router: Router):
        """fe80::x is link-local."""
        # Why test: Link-local is the most common case for neighbor traffic.
        addr = IPv6Address("fe80::1234")
        assert router.classify_address(addr) == AddressClass.LINK_LOCAL

    def test_link_local_fea0(self, router: Router):
        """fea0::x is also link-local (within fe80::/10)."""
        # Why test: fe80::/10 includes fe80:: through febf::.
        addr = IPv6Address("fea0::1")
        assert router.classify_address(addr) == AddressClass.LINK_LOCAL

    def test_ula_is_mesh_local(self, router: Router):
        """fd00::x (ULA) is mesh-local."""
        # Why test: LICHEN meshes typically use ULA for internal addressing.
        addr = IPv6Address("fd00::1234")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_ula_different_prefix_is_mesh_local(self, router: Router):
        """fdxx::x (any ULA) is mesh-local."""
        # Why test: ULA is fd00::/8, not just fd00::.
        addr = IPv6Address("fdab:cdef::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_gua_without_prefix_is_external(self, router: Router):
        """GUA not in mesh_prefixes is external."""
        # Why test: Unknown GUA should route via border router.
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

    def test_gua_with_prefix_is_mesh_local(self, router: Router):
        """GUA in mesh_prefixes is mesh-local."""
        # Why test: Border router may assign GUA prefixes to the mesh.
        router.add_mesh_prefix("2001:db8::/32")
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_localhost_is_external(self, router: Router):
        """::1 (localhost) is external."""
        # Why test: Localhost shouldn't be routed at all, classified as external.
        addr = IPv6Address("::1")
        assert router.classify_address(addr) == AddressClass.EXTERNAL


class TestLinkLocalRouting:
    """Tests for link-local address routing."""

    def test_link_local_forwards_directly(self, router: Router):
        """Link-local destinations forward directly to the address."""
        # Why test: Link-local = one hop, destination is next hop.
        packet = make_packet("fe80::1234")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::1234")


class TestMeshLocalRouting:
    """Tests for mesh-local address routing."""

    def test_gradient_found_forwards(self, router: Router, gradient_table: GradientTable):
        """Mesh-local with gradient entry forwards to next_hop."""
        # Why test: The happy path - gradient exists, forward immediately.
        dst = IPv6Address("fd00::beef")
        next_hop = IPv6Address("fe80::1")

        gradient_table.update(GradientEntry(
            destination=dst,
            next_hop=next_hop,
            hop_count=3,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=10000,
        ))

        packet = make_packet("fd00::beef")
        decision, result_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert result_hop == next_hop

    def test_expired_gradient_queues(self, router: Router, gradient_table: GradientTable):
        """Expired gradient entry triggers queue (if LOADng available)."""
        # Why test: Stale routes should not be used; need rediscovery.
        dst = IPv6Address("fd00::beef")

        gradient_table.update(GradientEntry(
            destination=dst,
            next_hop=IPv6Address("fe80::1"),
            hop_count=3,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=100,  # Already expired at now=1000
        ))

        # Without LOADng, should drop
        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=1000)
        assert decision == RouteDecision.DROP

    def test_no_gradient_without_loadng_drops(self, router: Router):
        """No gradient and no LOADng = drop."""
        # Why test: Can't discover without LOADng.
        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_no_gradient_with_loadng_queues(self, router: Router, gradient_table: GradientTable):
        """No gradient but LOADng available = queue for discovery."""
        # Why test: LOADng can discover routes on demand.
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.QUEUE


class TestExternalRouting:
    """Tests for external address routing."""

    def test_external_without_dodag_drops(self, router: Router):
        """External destination without DODAG = drop."""
        # Why test: Can't route external without RPL.
        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_unjoined_drops(self, router: Router):
        """External destination when not joined to DODAG = drop."""
        # Why test: Must be joined to use RPL parent.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.UNJOINED,
        )

        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_no_parent_drops(self, router: Router):
        """External destination when joined but no parent = drop."""
        # Why test: Edge case - joined but lost parent.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.JOINED,
            preferred_parent=None,  # No parent!
        )

        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_with_parent_forwards(self, router: Router):
        """External destination with RPL parent = forward to parent."""
        # Why test: Happy path for external routing.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.JOINED,
            preferred_parent=IPv6Address("fe80::abcd"),
        )

        packet = make_packet("2001:db8::1")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::abcd")


class TestLocalDelivery:
    """Tests for packets addressed to this node."""

    def test_packet_for_self_delivers_local(self, router: Router):
        """Packet to node's own address = deliver local."""
        # Why test: Don't route packets addressed to us.
        packet = make_packet("fd00::1")  # router.node_address
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DELIVER_LOCAL


class TestPendingQueue:
    """Tests for pending packet queue management."""

    def test_queue_stores_packet(self, router: Router, gradient_table: GradientTable):
        """Queued packets are stored for later forwarding."""
        # Setup LOADng so we queue instead of drop
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        packet = make_packet("fd00::beef")
        router.route(packet, now_ms=0)

        pending = router.get_pending(dst)
        assert len(pending) == 1
        assert pending[0].packet == packet

    def test_queue_limit_drops_oldest(self, router: Router, gradient_table: GradientTable):
        """Queue limit drops oldest packets when exceeded."""
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )
        router.max_pending_per_dest = 2

        dst = "fd00::beef"
        p1 = make_packet(dst)
        p2 = make_packet(dst)
        p3 = make_packet(dst)

        router.route(p1, now_ms=0)
        router.route(p2, now_ms=1)
        router.route(p3, now_ms=2)  # Should drop p1

        pending = router.get_pending(IPv6Address(dst))
        assert len(pending) == 2
        # p1 should be gone, p2 and p3 remain
        assert pending[0].packet == p2
        assert pending[1].packet == p3

    def test_clear_pending_removes_all(self, router: Router, gradient_table: GradientTable):
        """clear_pending removes all packets for a destination."""
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        router.route(make_packet("fd00::beef"), now_ms=0)
        router.route(make_packet("fd00::beef"), now_ms=1)

        count = router.clear_pending(dst)
        assert count == 2
        assert router.get_pending(dst) == []

    def test_expire_pending_removes_old(self, router: Router, gradient_table: GradientTable):
        """expire_pending removes packets older than timeout."""
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        router.route(make_packet("fd00::beef"), now_ms=0)
        router.route(make_packet("fd00::beef"), now_ms=100)
        router.route(make_packet("fd00::beef"), now_ms=200)

        # Expire packets older than 150ms
        expired = router.expire_pending(now_ms=300, timeout_ms=150)

        assert expired == 2  # Packets at 0 and 100 expired
        pending = router.get_pending(dst)
        assert len(pending) == 1
        assert pending[0].queued_at_ms == 200

    def test_release_pending_for_returns_pending(
        self, router: Router, gradient_table: GradientTable
    ):
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        p1 = make_packet("fd00::beef")
        p2 = make_packet("fd00::beef")
        router.route(p1, now_ms=0)
        router.route(p2, now_ms=1)

        pending = router.release_pending_for(dst)

        assert len(pending) == 2
        assert router.get_pending(dst) == []

    def test_max_pending_destinations_evicts_oldest(self, router: Router):
        from lichen.gradient import GradientTable
        from lichen.loadng.cache import RouteCache
        from lichen.loadng.discovery import LoadngRouter

        gradient_table = GradientTable()
        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )
        router.max_pending_destinations = 2

        d1 = IPv6Address("fd00:aaaa::1")
        d2 = IPv6Address("fd00:bbbb::1")
        d3 = IPv6Address("fd00:cccc::1")
        router.route(make_packet(str(d1)), now_ms=0)
        router.route(make_packet(str(d2)), now_ms=1)
        router.route(make_packet(str(d3)), now_ms=2)

        assert len(router.pending_queue) == 2
        assert d1 not in router.pending_queue
        assert d2 in router.pending_queue
        assert d3 in router.pending_queue


class TestMeshPrefixManagement:
    """Tests for mesh prefix add/remove."""

    def test_add_prefix_makes_gua_mesh_local(self, router: Router):
        """Adding a prefix makes addresses in it mesh-local."""
        addr = IPv6Address("2001:db8:1234::5678")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

        router.add_mesh_prefix("2001:db8::/32")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_remove_prefix_makes_gua_external(self, router: Router):
        """Removing a prefix makes addresses external again."""
        router.add_mesh_prefix("2001:db8::/32")
        addr = IPv6Address("2001:db8:1234::5678")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

        router.remove_mesh_prefix("2001:db8::/32")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

    def test_add_prefix_string_form(self, router: Router):
        """add_mesh_prefix accepts string form."""
        router.add_mesh_prefix("2001:db8::/48")
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL


class TestRootNode:
    """Tests for border router (root) behavior."""

    def test_root_can_route_external(self, router: Router):
        """Root node routes external via preferred_parent (self)."""
        # Why test: Root may have different routing behavior.
        # For now, root still uses parent (which might be upstream gateway).
        router.dodag = DodagState.as_root(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
        )
        # Root needs a parent (upstream gateway) to route external
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.ROOT,
            preferred_parent=IPv6Address("fe80::aaaa"),  # Upstream gateway
        )

        packet = make_packet("2001:db8::1")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::aaaa")


class TestGPSRFallback:
    """Tests for GPSR geographic routing fallback (spec 9.7)."""

    def test_gpsr_forward_selects_closest_neighbor(self, router: Router):
        """gpsr_forward returns neighbor closest to destination."""
        # Why test: Core GPSR algorithm - greedy forwarding.
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {
            IPv6Address("fe80::a"): (1.0, 0.0),  # 1 degree north
            IPv6Address("fe80::b"): (0.5, 0.0),  # 0.5 degrees north (closer)
        }
        dst_coords = (2.0, 0.0)  # destination is 2 degrees north

        next_hop = router.gpsr_forward(dst_coords)

        assert next_hop == IPv6Address("fe80::a")  # 1.0 is closer to 2.0 than 0.5

    def test_gpsr_forward_requires_progress(self, router: Router):
        """gpsr_forward returns None if no neighbor is closer than us."""
        # Why test: GPSR only forwards if progress is made (greedy requirement).
        router.node_coords = (1.0, 0.0)
        router.neighbor_coords = {
            IPv6Address("fe80::a"): (0.5, 0.0),  # further from dest than us
            IPv6Address("fe80::b"): (0.0, 0.0),  # even further
        }
        dst_coords = (2.0, 0.0)

        next_hop = router.gpsr_forward(dst_coords)

        assert next_hop is None  # local minimum

    def test_gpsr_forward_no_coords(self, router: Router):
        """gpsr_forward returns None if node has no coords."""
        router.node_coords = None
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        next_hop = router.gpsr_forward((2.0, 0.0))

        assert next_hop is None

    def test_gpsr_forward_no_neighbors(self, router: Router):
        """gpsr_forward returns None if no neighbors have coords."""
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {}

        next_hop = router.gpsr_forward((2.0, 0.0))

        assert next_hop is None

    def test_gpsr_forward_nan_coords(self, router: Router):
        """gpsr_forward returns None for NaN coordinates."""
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        assert router.gpsr_forward((float("nan"), 0.0)) is None
        assert router.gpsr_forward((0.0, float("nan"))) is None

    def test_gpsr_forward_inf_coords(self, router: Router):
        """gpsr_forward returns None for infinite coordinates."""
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        assert router.gpsr_forward((float("inf"), 0.0)) is None
        assert router.gpsr_forward((float("-inf"), 0.0)) is None

    def test_gpsr_forward_invalid_latitude(self, router: Router):
        """gpsr_forward returns None for out-of-range latitude."""
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        assert router.gpsr_forward((91.0, 0.0)) is None
        assert router.gpsr_forward((-91.0, 0.0)) is None

    def test_gpsr_forward_invalid_longitude(self, router: Router):
        """gpsr_forward returns None for out-of-range longitude."""
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        assert router.gpsr_forward((0.0, 181.0)) is None
        assert router.gpsr_forward((0.0, -181.0)) is None

    def test_gpsr_forward_null_island(self, router: Router):
        """gpsr_forward returns None for null island (0,0) sentinel."""
        router.node_coords = (1.0, 1.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (0.5, 0.5)}

        assert router.gpsr_forward((0.0, 0.0)) is None

    def test_gpsr_forward_near_null_island(self, router: Router):
        """gpsr_forward rejects coords near null island (epsilon check)."""
        router.node_coords = (1.0, 1.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (0.5, 0.5)}

        # Near-zero coords should also be rejected (GPS garbage)
        assert router.gpsr_forward((0.0001, 0.0)) is None
        assert router.gpsr_forward((0.0, 0.0001)) is None
        assert router.gpsr_forward((1e-10, 1e-10)) is None
        assert router.gpsr_forward((-0.0005, 0.0005)) is None

        # Just outside epsilon (0.001) should be accepted
        assert router.gpsr_forward((0.002, 0.002)) is not None

    def test_mesh_local_rejects_expired_coords_for_gpsr(
        self, router: Router, gradient_table: GradientTable
    ):
        """GPSR fallback rejects expired entries to avoid stale coordinates."""
        # Setup: expired gradient with coords, no LOADng
        router.loadng = None
        router.node_coords = (0.0, 0.0)
        router.neighbor_coords = {IPv6Address("fe80::a"): (1.0, 0.0)}

        # Add an expired entry with coords
        dst = IPv6Address("fd00::100")
        gradient_table.update(
            GradientEntry(
                destination=dst,
                next_hop=IPv6Address("fe80::dead"),
                hop_count=3,
                seq_num=1,
                source=GradientSource.ANNOUNCE,
                expires=0,  # expired
                coords=(2.0, 0.0),
            )
        )

        packet = make_packet("fd00::100")
        decision, next_hop = router.route(packet, now_ms=1000)

        # SECURITY: Should drop rather than use stale coordinates
        assert decision == RouteDecision.DROP
        assert next_hop is None

    def test_update_neighbor_coords(self, router: Router):
        """update_neighbor_coords stores coords for neighbor."""
        neighbor = IPv6Address("fe80::a")
        coords = (47.6062, 12.3321)

        router.update_neighbor_coords(neighbor, coords)

        assert router.neighbor_coords[neighbor] == coords


class TestBackpressure:
    """Tests for backpressure routing (spec 11.4)."""

    def test_update_neighbor_queue_depth(self, router: Router):
        """update_neighbor_queue_depth stores queue depth."""
        neighbor = IPv6Address("fe80::a")

        router.update_neighbor_queue_depth(neighbor, 10)

        assert router.neighbor_queue_depth[neighbor] == 10

    def test_get_neighbor_queue_depth_default(self, router: Router):
        """get_neighbor_queue_depth returns 0 for unknown neighbor."""
        neighbor = IPv6Address("fe80::dead")

        depth = router.get_neighbor_queue_depth(neighbor)

        assert depth == 0

    def test_get_neighbor_queue_depth_known(self, router: Router):
        neighbor = IPv6Address("fe80::a")
        router.neighbor_queue_depth[neighbor] = 42

        depth = router.get_neighbor_queue_depth(neighbor)

        assert depth == 42

    def test_neighbor_lru_eviction(self, router: Router):
        router.max_neighbors = 2
        n1 = IPv6Address("fe80::1")
        n2 = IPv6Address("fe80::2")
        n3 = IPv6Address("fe80::3")
        router.update_neighbor_coords(n1, (10.0, 10.0))
        router.update_neighbor_queue_depth(n2, 0)
        router.update_neighbor_coords(n1, (11.0, 11.0))
        router.update_neighbor_coords(n3, (30.0, 30.0))
        assert n2 not in router.neighbor_coords
        assert n2 not in router.neighbor_queue_depth
        assert n1 in router.neighbor_coords
        assert n3 in router.neighbor_coords


class TestDtnBuffer:
    """Tests for DTN store-and-forward buffer (spec 9.8)."""

    def test_buffer_message(self, router: Router):
        """dtn_buffer_message adds message to buffer."""
        import time
        packet = make_packet("fd00::100")
        iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        expiry = int(time.time()) + 3600  # 1 hour from now

        result = router.dtn_buffer_message(packet, iid, expiry, now_ms=0)

        assert result is True
        assert len(router.dtn_buffer) == 1
        assert router.dtn_buffer[0].destination_iid == iid

    def test_buffer_rejects_expired(self, router: Router):
        """dtn_buffer_message rejects already-expired messages."""
        import time
        packet = make_packet("fd00::100")
        iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        expiry = int(time.time()) - 100  # already expired

        result = router.dtn_buffer_message(packet, iid, expiry, now_ms=0)

        assert result is False
        assert len(router.dtn_buffer) == 0

    def test_get_pending_iids(self, router: Router):
        """dtn_get_pending_iids returns unique IIDs."""
        import time
        expiry = int(time.time()) + 3600
        iid1 = b"\x01" * 8
        iid2 = b"\x02" * 8

        router.dtn_buffer_message(make_packet("fd00::1"), iid1, expiry, 0)
        router.dtn_buffer_message(make_packet("fd00::1"), iid1, expiry, 1)  # duplicate
        router.dtn_buffer_message(make_packet("fd00::2"), iid2, expiry, 2)

        pending = router.dtn_get_pending_iids()

        assert len(pending) == 2
        assert iid1 in pending
        assert iid2 in pending

    def test_retrieve_for(self, router: Router):
        """dtn_retrieve_for removes and returns matching messages."""
        import time
        expiry = int(time.time()) + 3600
        iid1 = b"\x01" * 8
        iid2 = b"\x02" * 8

        router.dtn_buffer_message(make_packet("fd00::1"), iid1, expiry, 0)
        router.dtn_buffer_message(make_packet("fd00::2"), iid2, expiry, 1)
        router.dtn_buffer_message(make_packet("fd00::1b"), iid1, expiry, 2)

        retrieved = router.dtn_retrieve_for(iid1)

        assert len(retrieved) == 2
        assert len(router.dtn_buffer) == 1
        assert router.dtn_buffer[0].destination_iid == iid2

    def test_eviction_oldest_first(self, router: Router):
        """Buffer evicts oldest messages when full."""
        import time
        expiry = int(time.time()) + 3600
        router.dtn_buffer_max_bytes = 300  # small buffer

        # Add messages until eviction
        for i in range(10):
            router.dtn_buffer_message(
                make_packet("fd00::1"),
                bytes([i] * 8),
                expiry,
                now_ms=i,
            )

        # Should have evicted oldest to stay under limit
        assert router._dtn_buffer_size() <= router.dtn_buffer_max_bytes


class TestForwardingBuffer:
    """Tests for per-source forwarding buffer with backpressure (spec appendix-bufferbloat.md)."""

    def test_buffer_accepts_packet(self, router: Router):
        """try_buffer accepts packet within limits."""
        from lichen.routing.router import ForwardingResult

        source_iid = b"\x01" * 8
        packet = make_packet("fd00::100")
        deadline_ms = 10000

        result = router.forwarding_buffer.try_buffer(
            packet, source_iid, now_ms=0, deadline_ms=deadline_ms
        )

        assert result == ForwardingResult.ACCEPTED
        assert router.forwarding_buffer.count_for_source(source_iid) == 1

    def test_buffer_backpressure_at_per_source_limit(self, router: Router):
        """try_buffer returns BACKPRESSURE when source hits per-source limit."""
        from lichen.routing.router import ForwardingResult

        source_iid = b"\x01" * 8

        # Fill to limit (default MAX_PACKETS_PER_SOURCE=2)
        for i in range(2):
            result = router.forwarding_buffer.try_buffer(
                make_packet("fd00::100"),
                source_iid,
                now_ms=i,
                deadline_ms=10000,
            )
            assert result == ForwardingResult.ACCEPTED

        # Third packet should trigger backpressure
        result = router.forwarding_buffer.try_buffer(
            make_packet("fd00::100"),
            source_iid,
            now_ms=100,
            deadline_ms=10000,
        )

        assert result == ForwardingResult.BACKPRESSURE
        assert router.forwarding_buffer.count_for_source(source_iid) == 2

    def test_buffer_evicts_oldest_source_when_full(self, router: Router):
        """try_buffer evicts oldest source when max sources reached."""
        from lichen.routing.router import ForwardingResult

        # Use small limits for testing
        router.forwarding_buffer.max_sources = 2
        router.forwarding_buffer.max_per_source = 1

        source1 = b"\x01" * 8
        source2 = b"\x02" * 8
        source3 = b"\x03" * 8

        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source1, now_ms=0, deadline_ms=10000
        )
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::2"), source2, now_ms=1, deadline_ms=10000
        )

        # Third source should evict source1 (oldest)
        result = router.forwarding_buffer.try_buffer(
            make_packet("fd00::3"), source3, now_ms=2, deadline_ms=10000
        )

        assert result == ForwardingResult.EVICTED
        assert router.forwarding_buffer.source_count() == 2
        assert router.forwarding_buffer.count_for_source(source1) == 0
        assert router.forwarding_buffer.count_for_source(source2) == 1
        assert router.forwarding_buffer.count_for_source(source3) == 1

    def test_dequeue_returns_oldest_packet(self, router: Router):
        """dequeue returns packets in FIFO order."""
        source_iid = b"\x01" * 8
        p1 = make_packet("fd00::1")
        p2 = make_packet("fd00::2")

        router.forwarding_buffer.try_buffer(p1, source_iid, now_ms=0, deadline_ms=10000)
        router.forwarding_buffer.try_buffer(p2, source_iid, now_ms=1, deadline_ms=10000)

        entry1 = router.forwarding_buffer.dequeue(source_iid)
        entry2 = router.forwarding_buffer.dequeue(source_iid)
        entry3 = router.forwarding_buffer.dequeue(source_iid)

        assert entry1 is not None
        assert entry1.packet == p1
        assert entry2 is not None
        assert entry2.packet == p2
        assert entry3 is None

    def test_dequeue_cleans_up_empty_source(self, router: Router):
        """dequeue removes source from tracking when empty."""
        source_iid = b"\x01" * 8

        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source_iid, now_ms=0, deadline_ms=10000
        )
        assert router.forwarding_buffer.source_count() == 1

        router.forwarding_buffer.dequeue(source_iid)
        assert router.forwarding_buffer.source_count() == 0

    def test_expire_old_removes_past_deadline(self, router: Router):
        """expire_old drops packets past their deadline."""
        source_iid = b"\x01" * 8

        # One packet expires at 100ms, one at 200ms
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source_iid, now_ms=0, deadline_ms=100
        )
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::2"), source_iid, now_ms=1, deadline_ms=200
        )

        # At t=150, first packet is expired
        expired = router.forwarding_buffer.expire_old(now_ms=150)

        assert expired == 1
        assert router.forwarding_buffer.count_for_source(source_iid) == 1

    def test_expire_old_cleans_up_empty_sources(self, router: Router):
        """expire_old removes source when all its packets expire."""
        source_iid = b"\x01" * 8

        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source_iid, now_ms=0, deadline_ms=100
        )

        router.forwarding_buffer.expire_old(now_ms=200)

        assert router.forwarding_buffer.source_count() == 0

    def test_peek_does_not_remove(self, router: Router):
        """peek returns packet without removing it."""
        source_iid = b"\x01" * 8
        packet = make_packet("fd00::1")

        router.forwarding_buffer.try_buffer(
            packet, source_iid, now_ms=0, deadline_ms=10000
        )

        entry = router.forwarding_buffer.peek(source_iid)
        assert entry is not None
        assert entry.packet == packet
        assert router.forwarding_buffer.count_for_source(source_iid) == 1

    def test_total_count(self, router: Router):
        """total_count returns sum across all sources."""
        source1 = b"\x01" * 8
        source2 = b"\x02" * 8

        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source1, now_ms=0, deadline_ms=10000
        )
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::2"), source1, now_ms=1, deadline_ms=10000
        )
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::3"), source2, now_ms=2, deadline_ms=10000
        )

        assert router.forwarding_buffer.total_count() == 3

    def test_get_stats(self, router: Router):
        """get_stats returns diagnostic information."""
        source_iid = b"\x01" * 8

        # Add packets until backpressure
        for i in range(3):
            router.forwarding_buffer.try_buffer(
                make_packet("fd00::1"), source_iid, now_ms=i, deadline_ms=10000
            )

        stats = router.forwarding_buffer.get_stats()

        assert stats["total_packets"] == 2
        assert stats["sources"] == 1
        assert stats["accepted"] == 2
        assert stats["backpressure"] == 1
        assert stats["expired"] == 0
        assert stats["evicted"] == 0

    def test_lru_eviction_order(self, router: Router):
        """Most recently used source survives eviction."""
        from lichen.routing.router import ForwardingResult

        router.forwarding_buffer.max_sources = 2
        router.forwarding_buffer.max_per_source = 2

        source1 = b"\x01" * 8
        source2 = b"\x02" * 8
        source3 = b"\x03" * 8

        # Add to source1, then source2
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::1"), source1, now_ms=0, deadline_ms=10000
        )
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::2"), source2, now_ms=1, deadline_ms=10000
        )
        # Touch source1 again (moves to end of LRU)
        router.forwarding_buffer.try_buffer(
            make_packet("fd00::3"), source1, now_ms=2, deadline_ms=10000
        )

        # Add source3 - should evict source2 (least recently used)
        result = router.forwarding_buffer.try_buffer(
            make_packet("fd00::4"), source3, now_ms=3, deadline_ms=10000
        )

        assert result == ForwardingResult.EVICTED
        assert router.forwarding_buffer.count_for_source(source1) == 2  # survived
        assert router.forwarding_buffer.count_for_source(source2) == 0  # evicted
        assert router.forwarding_buffer.count_for_source(source3) == 1  # new

    def test_default_limits_match_spec(self, router: Router):
        """Default limits match spec appendix-bufferbloat.md."""
        from lichen.routing.router import MAX_FORWARDING_SOURCES, MAX_PACKETS_PER_SOURCE

        assert router.forwarding_buffer.max_sources == MAX_FORWARDING_SOURCES
        assert router.forwarding_buffer.max_per_source == MAX_PACKETS_PER_SOURCE
        assert MAX_FORWARDING_SOURCES == 8
        assert MAX_PACKETS_PER_SOURCE == 2
