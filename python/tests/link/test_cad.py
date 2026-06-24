# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CAD (Channel Activity Detection) and backoff.

Why these tests: CAD is crucial for collision avoidance. Bugs here mean:
- TX without checking channel (collisions)
- Backoff not working (repeated collisions)
- Exponential backoff broken (unfair channel access)
- Giving up too early or never (reliability issues)

Test categories:
1. CAD skip: When disabled, no CAD call made
2. CAD clear: Proceed immediately when channel is clear
3. CAD busy: Backoff and retry when channel is busy
4. Backoff timing: Exponential growth of backoff window
5. Max retries: Give up after exhausting backoff cycles
6. Medium.detect_activity: Returns True when TX is active
"""

import pytest

from lichen.constants import CAD_MAX_BACKOFF_EXPONENT, CAD_MAX_CYCLES
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.link.link_layer import LinkLayer
from lichen.sim.medium import Medium
from lichen.sim.propagation import PropagationModel


class MockRadioWithCADSequence:
    """Mock radio with configurable CAD return sequence.

    Why this class: Need to test various CAD scenarios - channel clear,
    busy then clear, always busy, etc. The sequence allows precise control
    over CAD behavior across multiple calls.

    Attributes:
        cad_sequence: List of bool values to return from cad() calls.
            True = busy, False = clear. If exhausted, returns last value.
        cad_call_count: Number of cad() calls made.
    """

    def __init__(self, cad_sequence: list[bool] | None = None):
        self.tx_history: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []
        self.cad_sequence = cad_sequence if cad_sequence is not None else [False]
        self.cad_call_count: int = 0

    async def transmit(self, payload: bytes) -> bool:
        """Record transmitted frames."""
        self.tx_history.append(payload)
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Return next queued frame or None."""
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """No-op for mock."""
        pass

    async def cad(self, timeout_ms: int) -> bool:
        """Return next value in CAD sequence.

        If sequence is exhausted, returns the last value in the sequence.
        This allows testing "busy forever" with [True] or "busy then clear"
        with [True, True, False].
        """
        idx = min(self.cad_call_count, len(self.cad_sequence) - 1)
        result = self.cad_sequence[idx]
        self.cad_call_count += 1
        return result


@pytest.fixture
def node_identity() -> Identity:
    """Create a test node identity."""
    return Identity.from_seed(bytes(32))


@pytest.fixture
def peer_db(node_identity: Identity) -> dict[bytes, PeerIdentity]:
    """Create a peer database with node as a peer (for loopback)."""
    peer = PeerIdentity.from_pubkey(node_identity.pubkey)
    return {peer.iid: peer}


def make_link_layer(
    radio: MockRadioWithCADSequence,
    identity: Identity,
    cad_enabled: bool = True,
) -> LinkLayer:
    """Create a LinkLayer with the given configuration."""

    def peer_lookup(hint: bytes) -> PeerIdentity | None:
        return PeerIdentity.from_pubkey(identity.pubkey)

    return LinkLayer(
        radio=radio,
        identity=identity,
        peer_lookup=peer_lookup,
        cad_enabled=cad_enabled,
    )


class TestCADDisabled:
    """Tests for cad_enabled=False behavior."""

    @pytest.mark.asyncio
    async def test_cad_disabled_skips_check(self, node_identity: Identity):
        """When cad_enabled=False, no CAD call is made."""
        radio = MockRadioWithCADSequence(cad_sequence=[True])  # Would be busy
        ll = make_link_layer(radio, node_identity, cad_enabled=False)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        assert radio.cad_call_count == 0  # No CAD calls


class TestCADClear:
    """Tests for channel-clear scenarios."""

    @pytest.mark.asyncio
    async def test_cad_clear_proceeds_immediately(self, node_identity: Identity):
        """CAD returns False (clear) -> transmit happens immediately."""
        radio = MockRadioWithCADSequence(cad_sequence=[False])
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        assert radio.cad_call_count == 1  # Only one CAD check needed


class TestCADBusy:
    """Tests for channel-busy scenarios."""

    @pytest.mark.asyncio
    async def test_cad_busy_triggers_backoff(self, node_identity: Identity):
        """CAD returns True (busy) -> backs off and retries."""
        # First call busy, second call clear
        radio = MockRadioWithCADSequence(cad_sequence=[True, False])
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        assert radio.cad_call_count == 2  # Busy, then clear

    @pytest.mark.asyncio
    async def test_backoff_exponential(self, node_identity: Identity):
        """Backoff window grows exponentially: 0, 1, 3, 7, 15, 31 slots max.

        The window sizes are: 2^0=1, 2^1=2, 2^2=4, 2^3=8, 2^4=16, 2^5=32
        which means max slots are: 0, 1, 3, 7, 15, 31

        We verify the algorithm by checking that the expected number of CAD
        calls are made before success (CAD_MAX_BACKOFF_EXPONENT + 1 = 6
        attempts per cycle).
        """
        # Make channel busy for first cycle (6 attempts), then clear
        attempts_per_cycle = CAD_MAX_BACKOFF_EXPONENT + 1  # 6
        busy_sequence = [True] * attempts_per_cycle + [False]
        radio = MockRadioWithCADSequence(cad_sequence=busy_sequence)
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        # 6 busy calls in first cycle + 1 clear call to start second cycle
        assert radio.cad_call_count == attempts_per_cycle + 1


class TestMaxRetries:
    """Tests for retry exhaustion scenarios."""

    @pytest.mark.asyncio
    async def test_tx_fails_after_max_retries(self, node_identity: Identity):
        """3 cycles of all-busy -> send() returns False.

        Each cycle has CAD_MAX_BACKOFF_EXPONENT + 1 = 6 attempts.
        After 3 full cycles (18 attempts), TX should fail.
        """
        # Always busy
        radio = MockRadioWithCADSequence(cad_sequence=[True])
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is False
        assert len(radio.tx_history) == 0  # No TX happened

        # Total CAD calls = cycles * attempts_per_cycle
        attempts_per_cycle = CAD_MAX_BACKOFF_EXPONENT + 1  # 6
        expected_calls = CAD_MAX_CYCLES * attempts_per_cycle  # 3 * 6 = 18
        assert radio.cad_call_count == expected_calls


class TestCADClearAfterBackoff:
    """Tests for busy-then-clear scenarios."""

    @pytest.mark.asyncio
    async def test_cad_clears_after_backoff(self, node_identity: Identity):
        """Channel busy then clear -> eventually succeeds.

        Simulates real-world scenario where another node finishes TX
        after a few backoff attempts.
        """
        # Busy for 5 attempts, then clear
        radio = MockRadioWithCADSequence(cad_sequence=[True] * 5 + [False])
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        assert radio.cad_call_count == 6  # 5 busy + 1 clear

    @pytest.mark.asyncio
    async def test_cad_clears_in_second_cycle(self, node_identity: Identity):
        """Channel clears in second backoff cycle -> succeeds.

        Tests that the algorithm correctly continues to next cycle and
        still succeeds when channel clears.
        """
        attempts_per_cycle = CAD_MAX_BACKOFF_EXPONENT + 1  # 6
        # Full first cycle busy, clear at start of second cycle
        busy_sequence = [True] * attempts_per_cycle + [False]
        radio = MockRadioWithCADSequence(cad_sequence=busy_sequence)
        ll = make_link_layer(radio, node_identity, cad_enabled=True)

        result = await ll.send(b"test")

        assert result is True
        assert len(radio.tx_history) == 1
        # 6 busy calls + 1 clear call
        assert radio.cad_call_count == attempts_per_cycle + 1


class TestMediumDetectActivity:
    """Tests for Medium.detect_activity() behavior."""

    def test_medium_detect_activity_returns_true_when_tx_active(self):
        """Medium.detect_activity() returns True when TX is active."""
        medium = Medium(
            propagation=PropagationModel(),
            noise_floor_dbm=-120.0,
        )

        # Start a transmission
        tx_position = (0.0, 0.0, 0.0)
        medium.start_tx(
            node_id="tx_node",
            payload=b"test_payload",
            tx_power_dbm=14,
            position=tx_position,
            time_us=0,
        )

        # Check activity from a nearby position
        rx_position = (100.0, 0.0, 0.0)  # 100m away
        time_us = 1000  # During transmission

        activity_detected = medium.detect_activity(
            position=rx_position,
            time_us=time_us,
        )

        assert activity_detected is True

    def test_medium_detect_activity_returns_false_when_no_tx(self):
        """Medium.detect_activity() returns False when no TX is active."""
        medium = Medium(
            propagation=PropagationModel(),
            noise_floor_dbm=-120.0,
        )

        # No transmissions started
        rx_position = (100.0, 0.0, 0.0)
        time_us = 1000

        activity_detected = medium.detect_activity(
            position=rx_position,
            time_us=time_us,
        )

        assert activity_detected is False

    def test_medium_detect_activity_returns_false_after_tx_ends(self):
        """Medium.detect_activity() returns False after TX completes."""
        medium = Medium(
            propagation=PropagationModel(),
            noise_floor_dbm=-120.0,
        )

        # Start a transmission
        tx_position = (0.0, 0.0, 0.0)
        tx = medium.start_tx(
            node_id="tx_node",
            payload=b"test_payload",
            tx_power_dbm=14,
            position=tx_position,
            time_us=0,
        )

        # Check activity after transmission ends
        rx_position = (100.0, 0.0, 0.0)
        time_us = tx.end_time_us + 1000  # After transmission ends

        activity_detected = medium.detect_activity(
            position=rx_position,
            time_us=time_us,
        )

        assert activity_detected is False

    def test_medium_detect_activity_returns_false_when_too_far(self):
        """Medium.detect_activity() returns False when signal too weak."""
        medium = Medium(
            propagation=PropagationModel(),
            noise_floor_dbm=-120.0,
        )

        # Start a weak transmission
        tx_position = (0.0, 0.0, 0.0)
        medium.start_tx(
            node_id="tx_node",
            payload=b"test_payload",
            tx_power_dbm=0,  # Low power
            position=tx_position,
            time_us=0,
        )

        # Check activity from very far away
        rx_position = (100_000.0, 0.0, 0.0)  # 100km away
        time_us = 1000

        activity_detected = medium.detect_activity(
            position=rx_position,
            time_us=time_us,
        )

        assert activity_detected is False
