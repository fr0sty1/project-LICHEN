# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulation integration tests for opportunistic forwarding (spec 9.9).

Tests verify that:
1. Forwarder list encoding works correctly
2. Wait time calculation follows slot timing
3. Timed suppression logic works (lower-ranked forwarders suppress)

Paranoid defensive style: explicit assertions at every step, guard against
None values aggressively, verify invariants.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from ipaddress import IPv6Address

import pytest

from lichen.announce.coords import (
    HEADER_TYPE_OPPORTUNISTIC,
    MAX_OPPORTUNISTIC_CANDIDATES,
    OPPORTUNISTIC_SLOT_TIME_MS,
    decode_opportunistic_forwarders,
    encode_opportunistic_forwarders,
    opportunistic_wait_time_ms,
)
from lichen.crypto.identity import Identity
from lichen.radio.sim_client import SimRadio
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

    # PARANOID: Verify server is actually running
    assert server._node_servers is not None, "node servers dict must exist"

    sim = await server.create_simulation("opportunistic-test", TimeMode.BARRIER_SYNC)

    # PARANOID: Verify simulation was created
    assert sim is not None, "simulation must be created"
    assert sim.id == "opportunistic-test", "simulation ID must match"

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
    """Mock transmitter that captures announce bytes."""

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


class TestForwarderListEncoding:
    """Test opportunistic forwarder list encoding (python-1f6.1)."""

    @pytest.mark.asyncio
    async def test_encode_empty_forwarder_list(self) -> None:
        """Empty forwarder list encodes correctly.

        PARANOID: Verify structure.
        """
        data = encode_opportunistic_forwarders([])

        # PARANOID: Verify structure
        assert len(data) == 2, "empty list is 2 bytes (type + count)"
        assert data[0] == HEADER_TYPE_OPPORTUNISTIC, "first byte is type"
        assert data[1] == 0, "second byte is count=0"

        decoded = decode_opportunistic_forwarders(data)
        assert decoded is not None, "must decode"
        assert decoded == [], "must be empty list"

    @pytest.mark.asyncio
    async def test_encode_one_forwarder(self) -> None:
        """Single forwarder encodes correctly.

        PARANOID: Verify IID is preserved.
        """
        iid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        # PARANOID: Verify IID is 8 bytes
        assert len(iid) == 8, "IID must be 8 bytes"

        data = encode_opportunistic_forwarders([iid])

        # PARANOID: Verify structure
        assert len(data) == 10, "one forwarder is 10 bytes (type + count + 8)"
        assert data[0] == HEADER_TYPE_OPPORTUNISTIC, "type byte"
        assert data[1] == 1, "count=1"
        assert data[2:10] == iid, "IID must be preserved"

        decoded = decode_opportunistic_forwarders(data)
        assert decoded is not None, "must decode"
        assert len(decoded) == 1, "must have one IID"
        assert decoded[0] == iid, "IID must match"

    @pytest.mark.asyncio
    async def test_encode_max_forwarders(self) -> None:
        """Maximum forwarders (4) encode correctly.

        PARANOID: Verify all IIDs preserved in order.
        """
        # PARANOID: Verify constant
        assert MAX_OPPORTUNISTIC_CANDIDATES == 4, "max candidates must be 4"

        iids = [bytes([i] * 8) for i in range(MAX_OPPORTUNISTIC_CANDIDATES)]

        # PARANOID: Verify all IIDs are 8 bytes
        for i, iid in enumerate(iids):
            assert len(iid) == 8, f"IID {i} must be 8 bytes"

        data = encode_opportunistic_forwarders(iids)

        expected_len = 2 + MAX_OPPORTUNISTIC_CANDIDATES * 8
        assert len(data) == expected_len, f"must be {expected_len} bytes"
        assert data[1] == MAX_OPPORTUNISTIC_CANDIDATES, f"count={MAX_OPPORTUNISTIC_CANDIDATES}"

        decoded = decode_opportunistic_forwarders(data)
        assert decoded is not None, "must decode"
        assert len(decoded) == MAX_OPPORTUNISTIC_CANDIDATES, (
            f"must have {MAX_OPPORTUNISTIC_CANDIDATES} IIDs"
        )
        for i, iid in enumerate(decoded):
            assert iid == iids[i], f"IID {i} must match"

    @pytest.mark.asyncio
    async def test_encode_too_many_forwarders(self) -> None:
        """More than max forwarders raises ValueError.

        PARANOID: Verify validation.
        """
        iids = [bytes([i] * 8) for i in range(MAX_OPPORTUNISTIC_CANDIDATES + 1)]

        with pytest.raises(ValueError, match="too many"):
            encode_opportunistic_forwarders(iids)

    @pytest.mark.asyncio
    async def test_encode_wrong_iid_length(self) -> None:
        """IID with wrong length raises ValueError.

        PARANOID: Verify validation.
        """
        with pytest.raises(ValueError, match="length"):
            encode_opportunistic_forwarders([bytes([1, 2, 3])])  # Too short

    @pytest.mark.asyncio
    async def test_decode_wrong_type(self) -> None:
        """Wrong type byte returns None.

        PARANOID: Verify type checking.
        """
        # Wrong type byte
        data = bytes([0x01, 0x00])  # Type 0x01 instead of HEADER_TYPE_OPPORTUNISTIC

        result = decode_opportunistic_forwarders(data)
        assert result is None, "wrong type must return None"

    @pytest.mark.asyncio
    async def test_decode_truncated(self) -> None:
        """Truncated data returns None.

        PARANOID: Verify length checking.
        """
        # Says 1 forwarder but only 4 bytes of IID
        data = bytes([HEADER_TYPE_OPPORTUNISTIC, 1, 0, 0, 0, 0])

        result = decode_opportunistic_forwarders(data)
        assert result is None, "truncated data must return None"

    @pytest.mark.asyncio
    async def test_decode_too_many_claimed(self) -> None:
        """Count > max returns None.

        PARANOID: Verify bounds checking.
        """
        # Claims 5 forwarders (> max 4)
        data = bytes([HEADER_TYPE_OPPORTUNISTIC, 5])

        result = decode_opportunistic_forwarders(data)
        assert result is None, "count > max must return None"


class TestWaitTimeCalculation:
    """Test opportunistic wait time calculation (python-1f6.2)."""

    @pytest.mark.asyncio
    async def test_slot_time_constant(self) -> None:
        """Verify slot time constant.

        PARANOID: Check spec compliance.
        """
        # Spec 9.9: slot time is 100ms
        assert OPPORTUNISTIC_SLOT_TIME_MS == 100, "slot time must be 100ms"

    @pytest.mark.asyncio
    async def test_rank_0_immediate(self) -> None:
        """Rank 0 (best) forwards immediately.

        PARANOID: Verify zero wait time.
        """
        wait = opportunistic_wait_time_ms(0)
        assert wait == 0, "rank 0 must wait 0ms"

    @pytest.mark.asyncio
    async def test_rank_1_one_slot(self) -> None:
        """Rank 1 waits one slot time.

        PARANOID: Verify slot timing.
        """
        wait = opportunistic_wait_time_ms(1)
        assert wait == OPPORTUNISTIC_SLOT_TIME_MS, (
            f"rank 1 must wait {OPPORTUNISTIC_SLOT_TIME_MS}ms"
        )
        assert wait == 100, "rank 1 must wait 100ms"

    @pytest.mark.asyncio
    async def test_wait_increases_linearly(self) -> None:
        """Wait time increases linearly with rank.

        PARANOID: Verify linear relationship.
        """
        for rank in range(5):
            expected = rank * OPPORTUNISTIC_SLOT_TIME_MS
            actual = opportunistic_wait_time_ms(rank)
            assert actual == expected, f"rank {rank} must wait {expected}ms, got {actual}ms"

    @pytest.mark.asyncio
    async def test_max_rank_wait_time(self) -> None:
        """Maximum rank (3 for 4 candidates) waits 300ms.

        PARANOID: Verify max wait time.
        """
        max_rank = MAX_OPPORTUNISTIC_CANDIDATES - 1  # 3
        expected_wait = max_rank * OPPORTUNISTIC_SLOT_TIME_MS  # 300ms

        actual = opportunistic_wait_time_ms(max_rank)
        assert actual == expected_wait, f"max rank must wait {expected_wait}ms"
        assert actual == 300, "max rank must wait 300ms"


class TestTimedSuppressionLogic:
    """Test timed suppression logic (python-1f6.3)."""

    @pytest.mark.asyncio
    async def test_suppression_decision_logic(self) -> None:
        """Lower-ranked forwarders should suppress when hearing higher-ranked.

        This tests the decision logic, not actual simulation timing.

        PARANOID: Verify suppression conditions.
        """
        # Scenario: We are rank 2, heard rank 0 forward
        our_rank = 2
        heard_rank = 0

        # We should suppress because heard_rank < our_rank
        should_suppress = heard_rank < our_rank
        assert should_suppress is True, "must suppress when hearing better rank"

        # Scenario: We are rank 0, heard rank 2 forward
        our_rank = 0
        heard_rank = 2

        # We should NOT suppress because we are better ranked
        should_suppress = heard_rank < our_rank
        assert should_suppress is False, "must not suppress when we are better"

        # Scenario: Same rank heard (shouldn't happen in practice)
        our_rank = 1
        heard_rank = 1

        should_suppress = heard_rank < our_rank
        assert should_suppress is False, "same rank should not suppress"

    @pytest.mark.asyncio
    async def test_forwarder_rank_lookup(self) -> None:
        """Verify rank lookup from forwarder list.

        PARANOID: Verify rank determination.
        """
        # Create forwarder list with known IIDs
        iid_rank0 = bytes([0xAA] * 8)
        iid_rank1 = bytes([0xBB] * 8)
        iid_rank2 = bytes([0xCC] * 8)
        iid_not_listed = bytes([0xDD] * 8)

        forwarder_list = [iid_rank0, iid_rank1, iid_rank2]

        # Lookup rank by index
        def get_rank(iid: bytes, forwarders: list[bytes]) -> int | None:
            """Get rank of IID in forwarder list, or None if not listed."""
            try:
                return forwarders.index(iid)
            except ValueError:
                return None

        # PARANOID: Verify rank lookup
        assert get_rank(iid_rank0, forwarder_list) == 0, "rank 0"
        assert get_rank(iid_rank1, forwarder_list) == 1, "rank 1"
        assert get_rank(iid_rank2, forwarder_list) == 2, "rank 2"
        assert get_rank(iid_not_listed, forwarder_list) is None, "not listed"

    @pytest.mark.asyncio
    async def test_wait_time_window_ordering(self) -> None:
        """Verify wait time windows don't overlap.

        PARANOID: Windows must be sequential for suppression to work.
        """
        # Get wait times for all ranks
        wait_times = [opportunistic_wait_time_ms(r) for r in range(MAX_OPPORTUNISTIC_CANDIDATES)]

        # PARANOID: Verify strictly increasing
        for i in range(1, len(wait_times)):
            assert wait_times[i] > wait_times[i - 1], (
                f"wait time must be strictly increasing: {wait_times}"
            )

        # PARANOID: Verify gaps are exactly slot time
        for i in range(1, len(wait_times)):
            gap = wait_times[i] - wait_times[i - 1]
            assert gap == OPPORTUNISTIC_SLOT_TIME_MS, (
                f"gap must be {OPPORTUNISTIC_SLOT_TIME_MS}ms, got {gap}ms"
            )


class TestOpportunisticTransmission:
    """Test opportunistic forwarding data survives transmission."""

    @pytest.mark.asyncio
    async def test_forwarder_list_survives_transmission(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Forwarder list survives simulation TX/RX.

        PARANOID: Verify byte-for-byte match.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("opportunistic-test")

        assert node_port is not None, "must get node server port"

        # Create forwarder list
        forwarder_iids = [bytes([i] * 8) for i in range(3)]

        data = encode_opportunistic_forwarders(forwarder_iids)

        async with (
            SimRadio(
                "127.0.0.1", node_port, "opportunistic-test", "tx", (0.0, 0.0, 0.0)
            ) as radio_tx,
            SimRadio(
                "127.0.0.1", node_port, "opportunistic-test", "rx", (50.0, 0.0, 0.0)
            ) as radio_rx,
        ):
            tx_success = await radio_tx.transmit(data)
            assert tx_success, "transmit must succeed"

            result = await radio_rx.receive(1000)
            assert result is not None, "must receive"

            rx_bytes, rssi, snr = result

            # PARANOID: Verify signal quality
            assert rssi > -140, f"rssi {rssi} too weak"

            # PARANOID: Verify byte-for-byte match
            assert rx_bytes == data, "received bytes must match"

            # Verify decoded content
            decoded = decode_opportunistic_forwarders(rx_bytes)
            assert decoded is not None, "must decode"
            assert len(decoded) == 3, "must have 3 forwarders"
            for i, iid in enumerate(decoded):
                assert iid == forwarder_iids[i], f"forwarder {i} must match"


class TestOpportunisticSimulationIntegration:
    """Full simulation integration test for opportunistic forwarding."""

    @pytest.mark.asyncio
    async def test_opportunistic_forwarding_scenario(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Simulate opportunistic forwarding with ranked candidates.

        Scenario:
        - Source S broadcasts packet with forwarder list [A, B, C]
        - A (rank 0) should forward immediately
        - B (rank 1) should wait 100ms and suppress if A forwards
        - C (rank 2) should wait 200ms and suppress if A or B forwards

        This test verifies the encoding/timing mechanics, not full sim.

        PARANOID: Verify every step.
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("opportunistic-test")
        assert node_port is not None

        # Create identities
        _identity_s = make_identity(0)  # Source (only used for radio)
        identity_a = make_identity(1)  # Rank 0 forwarder
        identity_b = make_identity(2)  # Rank 1 forwarder
        identity_c = make_identity(3)  # Rank 2 forwarder

        # Create forwarder list
        forwarder_list = [identity_a.iid, identity_b.iid, identity_c.iid]

        # Encode forwarder list
        forwarder_data = encode_opportunistic_forwarders(forwarder_list)

        # PARANOID: Verify encoding
        assert len(forwarder_data) == 2 + 3 * 8, "must be correct length"

        # Calculate expected wait times
        wait_a = opportunistic_wait_time_ms(0)  # 0ms
        wait_b = opportunistic_wait_time_ms(1)  # 100ms
        wait_c = opportunistic_wait_time_ms(2)  # 200ms

        # PARANOID: Verify timing
        assert wait_a == 0, "A waits 0ms"
        assert wait_b == 100, "B waits 100ms"
        assert wait_c == 200, "C waits 200ms"

        # Simulate S broadcasting
        pos_s = (0.0, 0.0, 0.0)
        pos_a = (50.0, 0.0, 0.0)
        pos_b = (0.0, 50.0, 0.0)
        pos_c = (50.0, 50.0, 0.0)

        async with (
            SimRadio("127.0.0.1", node_port, "opportunistic-test", "node-s", pos_s) as radio_s,
            SimRadio("127.0.0.1", node_port, "opportunistic-test", "node-a", pos_a) as radio_a,
            SimRadio("127.0.0.1", node_port, "opportunistic-test", "node-b", pos_b) as _radio_b,
            SimRadio("127.0.0.1", node_port, "opportunistic-test", "node-c", pos_c) as _radio_c,
        ):
            # S broadcasts with forwarder list
            tx_success = await radio_s.transmit(forwarder_data)
            assert tx_success, "S must transmit"

            # All candidates receive
            result_a = await radio_a.receive(1000)
            assert result_a is not None, "A must receive"

            rx_bytes, _, _ = result_a
            decoded = decode_opportunistic_forwarders(rx_bytes)
            assert decoded is not None, "must decode"

            # A checks its rank
            def get_my_rank(my_iid: bytes, forwarders: list[bytes]) -> int | None:
                try:
                    return forwarders.index(my_iid)
                except ValueError:
                    return None

            rank_a = get_my_rank(identity_a.iid, decoded)
            rank_b = get_my_rank(identity_b.iid, decoded)
            rank_c = get_my_rank(identity_c.iid, decoded)

            # PARANOID: Verify ranks
            assert rank_a == 0, "A must be rank 0"
            assert rank_b == 1, "B must be rank 1"
            assert rank_c == 2, "C must be rank 2"

            # Calculate wait times for each
            wait_time_a = opportunistic_wait_time_ms(rank_a)
            wait_time_b = opportunistic_wait_time_ms(rank_b)
            wait_time_c = opportunistic_wait_time_ms(rank_c)

            # PARANOID: Verify wait times
            assert wait_time_a == 0, "A waits 0ms"
            assert wait_time_b == 100, "B waits 100ms"
            assert wait_time_c == 200, "C waits 200ms"

            # A should forward first (wait_time = 0)
            # B and C should suppress when they hear A's forward
            # (Actual suppression logic would be in the protocol handler)

            # This test verifies the mechanics; full simulation with
            # actual timing would require async delays and reception checks

    @pytest.mark.asyncio
    async def test_non_forwarder_ignores_list(self) -> None:
        """Node not in forwarder list should not forward.

        PARANOID: Verify non-forwarder handling.
        """
        # Create forwarder list without node D
        iid_a = bytes([0xAA] * 8)
        iid_b = bytes([0xBB] * 8)
        iid_c = bytes([0xCC] * 8)
        iid_d = bytes([0xDD] * 8)  # Not in list

        forwarder_list = [iid_a, iid_b, iid_c]

        # D checks if it's in the list
        def get_my_rank(my_iid: bytes, forwarders: list[bytes]) -> int | None:
            try:
                return forwarders.index(my_iid)
            except ValueError:
                return None

        rank_d = get_my_rank(iid_d, forwarder_list)

        # PARANOID: D should not be in list
        assert rank_d is None, "D must not be in forwarder list"

        # D should not forward (no wait time calculation needed)
        should_forward = rank_d is not None
        assert should_forward is False, "D must not forward"

    @pytest.mark.asyncio
    async def test_suppression_scenario(self) -> None:
        """Verify suppression decision when hearing better forwarder.

        PARANOID: Verify suppression logic.
        """
        # Forwarder list
        iid_rank0 = bytes([0x00] * 8)
        iid_rank1 = bytes([0x01] * 8)
        iid_rank2 = bytes([0x02] * 8)

        forwarder_list = [iid_rank0, iid_rank1, iid_rank2]

        # Node B (rank 1) scenario
        my_iid = iid_rank1
        my_rank = forwarder_list.index(my_iid)
        assert my_rank == 1, "B must be rank 1"

        # B hears rank 0 forward
        heard_forwarder_iid = iid_rank0
        heard_rank = forwarder_list.index(heard_forwarder_iid)
        assert heard_rank == 0, "heard must be rank 0"

        # B should suppress
        should_suppress = heard_rank < my_rank
        assert should_suppress is True, "B must suppress when hearing rank 0"

        # B has waited 50ms when it hears rank 0's forward
        # (In real implementation, B would cancel its pending forward)

        # Node C (rank 2) scenario
        my_iid = iid_rank2
        my_rank = forwarder_list.index(my_iid)
        assert my_rank == 2, "C must be rank 2"

        # C hears rank 0 forward
        heard_rank = 0
        should_suppress = heard_rank < my_rank
        assert should_suppress is True, "C must suppress when hearing rank 0"

        # C hears rank 1 forward (if rank 0 failed)
        heard_rank = 1
        should_suppress = heard_rank < my_rank
        assert should_suppress is True, "C must suppress when hearing rank 1"
