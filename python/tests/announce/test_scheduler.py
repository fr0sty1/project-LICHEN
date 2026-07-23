# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for announce scheduler.
"""

import asyncio

import pytest

from lichen.announce.messages import SIGNATURE_LENGTH, AnnounceMessage
from lichen.announce.scheduler import (
    AnnounceScheduler,
    SchedulerConfig,
)
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import verify


class MockTransmitter:
    """Mock transmitter for testing scheduler without real link layer.

    Why mock: Tests should be fast and deterministic. Mock captures
    what would be transmitted and allows controlling success/failure.
    """

    def __init__(self, success: bool = True):
        self.transmitted: list[bytes] = []
        self.success = success

    async def transmit_announce(self, data: bytes) -> bool:
        """Record transmitted data."""
        self.transmitted.append(data)
        return self.success


@pytest.fixture
def identity() -> Identity:
    """Test identity for the scheduler."""
    return Identity.from_seed(bytes(32))


@pytest.fixture
def transmitter() -> MockTransmitter:
    """Mock transmitter."""
    return MockTransmitter()


@pytest.fixture
def scheduler(identity: Identity, transmitter: MockTransmitter) -> AnnounceScheduler:
    """Create a test scheduler with fast timing."""
    return AnnounceScheduler(
        identity=identity,
        transmitter=transmitter,
        config=SchedulerConfig(
            interval_ms=100,  # 100ms for fast tests
            jitter_ms=0,  # No jitter for determinism
            initial_delay_ms=10,  # 10ms initial delay
        ),
    )


class TestSchedulerConfig:
    @pytest.mark.parametrize("interval_ms", [0, -1])
    def test_rejects_nonpositive_interval(self, interval_ms: int):
        with pytest.raises(ValueError, match="interval_ms must be > 0"):
            SchedulerConfig(interval_ms=interval_ms)

    def test_rejects_negative_jitter(self):
        with pytest.raises(ValueError, match="jitter_ms must be >= 0"):
            SchedulerConfig(jitter_ms=-1)

    def test_rejects_negative_initial_delay(self):
        with pytest.raises(ValueError, match="initial_delay_ms must be >= 0"):
            SchedulerConfig(initial_delay_ms=-1)

class TestSchedulerLifecycle:
    """Tests for scheduler start/stop lifecycle."""

    def test_initial_state(self, scheduler: AnnounceScheduler):
        """Scheduler starts not running."""
        assert scheduler.is_running is False

    @pytest.mark.asyncio
    async def test_start_revalidates_runtime_config(
        self, scheduler: AnnounceScheduler
    ):
        scheduler.config.interval_ms = 0

        with pytest.raises(ValueError, match="interval_ms must be > 0"):
            await scheduler.start()

        assert scheduler.is_running is False
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_runtime_config_error_does_not_wedge_stop(
        self, scheduler: AnnounceScheduler
    ):
        await scheduler.start()
        scheduler.config.interval_ms = 0
        await asyncio.sleep(0)

        assert scheduler._task is not None
        assert scheduler._task.done() is False

        await scheduler.stop()
        assert scheduler.is_running is False
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_start_sets_running(self, scheduler: AnnounceScheduler):
        """start() sets is_running to True."""
        await scheduler.start()
        assert scheduler.is_running is True
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running(self, scheduler: AnnounceScheduler):
        """stop() sets is_running to False."""
        await scheduler.start()
        await scheduler.stop()
        assert scheduler.is_running is False

    @pytest.mark.asyncio
    async def test_start_twice_raises(self, scheduler: AnnounceScheduler):
        """Cannot start() an already running scheduler."""
        await scheduler.start()
        with pytest.raises(RuntimeError, match="already running"):
            await scheduler.start()
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_stop_idempotent(self, scheduler: AnnounceScheduler):
        """stop() is safe to call when not running."""
        await scheduler.stop()  # Should not raise
        assert scheduler.is_running is False

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, scheduler: AnnounceScheduler):
        """stop() cancels the background task."""
        await scheduler.start()
        assert scheduler._task is not None
        await scheduler.stop()
        assert scheduler._task is None


class TestSequenceNumber:
    """Tests for sequence number management."""

    def test_initial_seq_is_zero(self, scheduler: AnnounceScheduler):
        """Sequence number starts at 0."""
        assert scheduler.get_seq_num() == 0

    def test_set_seq_num(self, scheduler: AnnounceScheduler):
        """set_seq_num updates the sequence number."""
        scheduler.set_seq_num(1000)
        assert scheduler.get_seq_num() == 1000

    def test_set_seq_num_validates_range(self, scheduler: AnnounceScheduler):
        """set_seq_num rejects out-of-range values."""
        # Why test: seq_num is 16-bit. Out-of-range would cause issues.
        with pytest.raises(ValueError, match="out of range"):
            scheduler.set_seq_num(-1)

        with pytest.raises(ValueError, match="out of range"):
            scheduler.set_seq_num(0x10000)

    def test_build_announce_increments_seq(self, scheduler: AnnounceScheduler):
        """Each build_announce() increments seq_num."""
        scheduler.build_announce()
        assert scheduler.get_seq_num() == 1

        scheduler.build_announce()
        assert scheduler.get_seq_num() == 2

    def test_seq_num_wraps(self, scheduler: AnnounceScheduler):
        """Sequence number wraps at 0xFFFF."""
        # Why test: Prevents overflow issues.
        scheduler.set_seq_num(0xFFFF)
        scheduler.build_announce()
        assert scheduler.get_seq_num() == 0

    def test_seq_change_callback(self, scheduler: AnnounceScheduler):
        """Callback is invoked on seq_num change."""
        # Why test: Enables persistence without scheduler owning storage.
        changes: list[int] = []
        scheduler.set_on_seq_change(changes.append)

        scheduler.build_announce()
        scheduler.build_announce()

        assert changes == [1, 2]


class TestAnnounceBuild:
    """Tests for announce message building."""

    def test_build_returns_signed_message(
        self, scheduler: AnnounceScheduler, identity: Identity
    ):
        """build_announce() returns a properly signed message."""
        announce = scheduler.build_announce()

        assert len(announce.signature) == SIGNATURE_LENGTH
        assert announce.originator_iid == identity.iid
        assert announce.pubkey == identity.pubkey

    def test_signature_is_valid(
        self, scheduler: AnnounceScheduler, identity: Identity
    ):
        """Signature verifies correctly."""
        # Why test: Invalid signatures would be rejected by receivers.
        announce = scheduler.build_announce()

        is_valid = verify(
            announce.pubkey,
            announce.signed_data(),
            announce.signature,
        )
        assert is_valid is True

    def test_build_includes_app_data(self, identity: Identity, transmitter: MockTransmitter):
        """Announce includes app_data when set."""
        app_data = b"node-name:alice"
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=transmitter,
            app_data=app_data,
        )

        announce = scheduler.build_announce()
        assert announce.app_data == app_data

    def test_hop_count_is_zero(self, scheduler: AnnounceScheduler):
        """Originator's announce has hop_count=0."""
        # Why test: We're the source, so hop_count starts at 0.
        announce = scheduler.build_announce()
        assert announce.hop_count == 0


class TestTransmission:
    """Tests for announce transmission."""

    @pytest.mark.asyncio
    async def test_sends_announce_after_start(
        self, scheduler: AnnounceScheduler, transmitter: MockTransmitter
    ):
        """Scheduler sends announces after starting."""
        await scheduler.start()
        # Wait for initial delay + one interval
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert len(transmitter.transmitted) >= 1

    @pytest.mark.asyncio
    async def test_transmitted_data_is_valid(
        self, scheduler: AnnounceScheduler, transmitter: MockTransmitter
    ):
        """Transmitted data parses as valid AnnounceMessage."""
        await scheduler.start()
        await asyncio.sleep(0.05)
        await scheduler.stop()

        assert len(transmitter.transmitted) >= 1
        data = transmitter.transmitted[0]

        # Should parse without error
        announce = AnnounceMessage.from_bytes(data)
        assert announce.seq_num == 1

    @pytest.mark.asyncio
    async def test_send_now_sends_immediately(
        self, scheduler: AnnounceScheduler, transmitter: MockTransmitter
    ):
        """send_now() sends an announce immediately."""
        await scheduler.start()
        transmitter.transmitted.clear()

        success = await scheduler.send_now()

        assert success is True
        assert len(transmitter.transmitted) == 1
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_send_now_fails_when_stopped(
        self, scheduler: AnnounceScheduler, transmitter: MockTransmitter
    ):
        """send_now() returns False when scheduler not running."""
        # Why test: Prevents unexpected behavior.
        success = await scheduler.send_now()

        assert success is False
        assert len(transmitter.transmitted) == 0

    @pytest.mark.asyncio
    async def test_transmit_failure_continues_loop(
        self, identity: Identity
    ):
        """Transmit failure doesn't stop the scheduler."""
        # Why test: Network issues shouldn't halt announcing.
        failing_transmitter = MockTransmitter(success=False)
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=failing_transmitter,
            config=SchedulerConfig(
                interval_ms=50,
                jitter_ms=0,
                initial_delay_ms=10,
            ),
        )

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        # Should have attempted multiple transmissions despite failures
        assert len(failing_transmitter.transmitted) >= 2


class TestTiming:
    """Tests for scheduler timing behavior."""

    @pytest.mark.asyncio
    async def test_respects_initial_delay(
        self, scheduler: AnnounceScheduler, transmitter: MockTransmitter
    ):
        """No announce sent before initial_delay_ms."""
        # Why test: Initial delay lets node discover peers first.
        await scheduler.start()
        # Check immediately (before initial delay)
        assert len(transmitter.transmitted) == 0
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_multiple_announces_over_time(
        self, identity: Identity, transmitter: MockTransmitter
    ):
        """Multiple announces sent over time at interval."""
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=transmitter,
            config=SchedulerConfig(
                interval_ms=30,  # 30ms interval
                jitter_ms=0,
                initial_delay_ms=5,
            ),
        )

        await scheduler.start()
        await asyncio.sleep(0.1)  # Should get ~3 announces
        await scheduler.stop()

        assert len(transmitter.transmitted) >= 2


class TestPersistence:
    """Tests for sequence number persistence support."""

    def test_restore_seq_num_on_startup(
        self, identity: Identity, transmitter: MockTransmitter
    ):
        """Can restore seq_num before starting."""
        # Why test: Persistence across reboots requires restoring seq_num.
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=transmitter,
        )

        # Simulate restoring from storage
        scheduler.set_seq_num(1000)

        announce = scheduler.build_announce()
        assert announce.seq_num == 1001  # Incremented from restored value

    def test_persistence_callback_for_storage(
        self, identity: Identity, transmitter: MockTransmitter
    ):
        """Callback enables external persistence."""
        # Why test: Shows how to persist seq_num without scheduler owning storage.
        storage: dict[str, int] = {}

        def persist(seq: int) -> None:
            storage["seq_num"] = seq

        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=transmitter,
        )
        scheduler.set_on_seq_change(persist)

        scheduler.build_announce()
        scheduler.build_announce()

        assert storage["seq_num"] == 2
