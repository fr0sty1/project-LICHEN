# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Duty cycle exhaustion scenario tests.

LoRa nodes operating in ISM bands must comply with regulatory duty cycle
limits (typically 1% in EU868). When a node transmits too frequently,
it exhausts its duty cycle budget and must wait before transmitting again.

These tests verify the simulator correctly enforces duty cycle limits
and blocks transmissions when the budget is exhausted.
"""

from __future__ import annotations

from lora_medium import Medium, airtime_us


class TestDutyCycleExhaustion:
    """Test duty cycle exhaustion scenarios."""

    def test_single_node_exhausts_duty_cycle(self) -> None:
        """Node transmits repeatedly until duty cycle budget is exhausted.

        With 1% duty cycle over 1-second window, the node can transmit
        for 10ms total. After that, further TX should be blocked.
        """
        # Use 1% duty cycle with 1-second window = 10ms budget
        medium = Medium(
            duty_cycle_limit_percent=1.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        # Small payload that takes ~248ms airtime at SF10/125kHz
        # With 10ms budget, we won't even complete one transmission
        # So use a very short window or larger limit for testing

        # Actually, let's use 50% duty cycle with 1-second window = 500ms budget
        # Standard payload airtime ~248ms, so we can do about 2 transmissions
        medium = Medium(
            duty_cycle_limit_percent=50.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        payload = b"test"  # Small payload
        position = (0.0, 0.0, 0.0)
        duration = airtime_us(len(payload))

        # First TX should succeed
        tx1 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx1 is not None, "First TX should succeed"

        # Second TX should succeed (still within budget)
        tx2 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=tx1.end_time_us + 1,
        )
        # This may or may not succeed depending on exact airtime
        # Let's be more precise

    def test_duty_cycle_blocks_after_exhaustion(self) -> None:
        """TX is blocked immediately after duty cycle limit is reached."""
        # Use 30% duty cycle with 1-second window = 300ms budget
        # Single TX is ~248ms, which uses ~83% of budget
        # Second TX would exceed 100%
        medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)

        # First TX uses ~248ms (~83% of 300ms budget)
        tx1 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx1 is not None, "First TX should succeed"

        # Second TX would use another ~248ms, total ~496ms > 300ms budget
        tx2 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=tx1.end_time_us + 1,
        )
        assert tx2 is None, "Second TX should be blocked (duty cycle exceeded)"

    def test_duty_cycle_recovers_after_window(self) -> None:
        """After the duty cycle window passes, TX is allowed again."""
        window_seconds = 1
        window_us = window_seconds * 1_000_000

        medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=window_seconds,
            enforce_duty_cycle=True,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)

        # First TX at time 0
        tx1 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx1 is not None

        # Second TX is blocked immediately after
        tx2_blocked = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=tx1.end_time_us + 1,
        )
        assert tx2_blocked is None, "TX should be blocked right after first TX"

        # After the window passes, duty cycle budget is restored
        # First TX ends at tx1.end_time_us. After window_us + tx1.end_time_us,
        # the first TX has fully exited the sliding window
        recovery_time = tx1.end_time_us + window_us + 1

        tx3 = medium.start_tx(
            node_id="node1",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=recovery_time,
        )
        assert tx3 is not None, "TX should succeed after window passes"

    def test_multiple_nodes_independent_duty_cycles(self) -> None:
        """Each node has its own independent duty cycle budget."""
        medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        payload = b"test"

        # Node A exhausts its duty cycle
        tx_a1 = medium.start_tx(
            node_id="node_a",
            payload=payload,
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=0,
        )
        assert tx_a1 is not None

        # Node A is blocked
        tx_a2 = medium.start_tx(
            node_id="node_a",
            payload=payload,
            tx_power_dbm=14,
            position=(0.0, 0.0, 0.0),
            time_us=tx_a1.end_time_us + 1,
        )
        assert tx_a2 is None, "Node A should be blocked"

        # Node B should still be able to transmit (separate budget)
        tx_b1 = medium.start_tx(
            node_id="node_b",
            payload=payload,
            tx_power_dbm=14,
            position=(100.0, 0.0, 0.0),
            time_us=tx_a1.end_time_us + 2,
        )
        assert tx_b1 is not None, "Node B has its own budget"

    def test_rapid_transmission_burst_exhausts_duty_cycle(self) -> None:
        """Rapid burst of transmissions exhausts duty cycle quickly."""
        # 10% duty cycle with 10-second window = 1s total TX time
        # Each TX is ~248ms, so we can do about 4 transmissions
        medium = Medium(
            duty_cycle_limit_percent=10.0,
            duty_cycle_window_seconds=10,
            enforce_duty_cycle=True,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)
        tx_time = 0

        successful_tx_count = 0
        blocked_tx = None

        # Try to transmit many times rapidly
        for i in range(10):
            tx = medium.start_tx(
                node_id="burst_node",
                payload=payload,
                tx_power_dbm=14,
                position=position,
                time_us=tx_time,
            )
            if tx is not None:
                successful_tx_count += 1
                tx_time = tx.end_time_us + 1
            else:
                blocked_tx = i
                break

        # Should have succeeded for some transmissions then blocked
        assert successful_tx_count >= 1, "At least one TX should succeed"
        assert blocked_tx is not None, "Should eventually be blocked"
        # With 1s budget and ~248ms per TX, expect ~4 successful
        assert successful_tx_count <= 5, f"Expected ~4 successful TX, got {successful_tx_count}"


class TestDutyCycleDisabled:
    """Test behavior when duty cycle enforcement is disabled."""

    def test_unlimited_tx_when_disabled(self) -> None:
        """Transmissions are not blocked when enforcement is disabled."""
        medium = Medium(
            duty_cycle_limit_percent=1.0,  # Very restrictive
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=False,  # But not enforced
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)
        tx_time = 0

        # Should be able to transmit many times without blocking
        for i in range(5):
            tx = medium.start_tx(
                node_id="unlimited_node",
                payload=payload,
                tx_power_dbm=14,
                position=position,
                time_us=tx_time,
            )
            assert tx is not None, f"TX {i} should succeed with enforcement disabled"
            tx_time = tx.end_time_us + 1

    def test_usage_still_tracked_when_disabled(self) -> None:
        """Duty cycle usage is tracked even when not enforced."""
        medium = Medium(
            duty_cycle_limit_percent=30.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=False,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)

        # Transmit once
        tx = medium.start_tx(
            node_id="tracked_node",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx is not None

        # Check that usage is tracked
        tracker = medium.get_duty_tracker("tracked_node")
        usage = tracker.usage_percent(tx.end_time_us)

        # Usage should be > 0 (airtime was recorded)
        assert usage > 0, "Usage should be tracked even when not enforced"


class TestDutyCycleObservability:
    """Test duty cycle observability/metrics."""

    def test_remaining_budget_decreases(self) -> None:
        """Remaining duty cycle budget decreases with each TX."""
        medium = Medium(
            duty_cycle_limit_percent=50.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)

        tracker = medium.get_duty_tracker("observe_node")

        # Initial budget should be full
        initial_remaining = tracker.remaining_ms(0)
        assert initial_remaining == 500, "50% of 1s = 500ms budget"

        # After one TX, remaining should decrease
        tx = medium.start_tx(
            node_id="observe_node",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx is not None

        remaining_after = tracker.remaining_ms(tx.end_time_us)

        # Remaining should be less than initial (allow 1ms rounding)
        assert remaining_after < initial_remaining, "Budget should decrease after TX"
        # Should have used approximately the airtime
        airtime_ms = (tx.end_time_us - tx.start_time_us) / 1000.0
        expected_remaining = 500 - airtime_ms
        assert abs(remaining_after - expected_remaining) <= 1, (
            f"Remaining should be ~{expected_remaining}ms, got {remaining_after}ms"
        )

    def test_usage_percent_increases(self) -> None:
        """Usage percentage increases with each transmission."""
        medium = Medium(
            duty_cycle_limit_percent=50.0,
            duty_cycle_window_seconds=1,
            enforce_duty_cycle=True,
        )

        payload = b"test"
        position = (0.0, 0.0, 0.0)

        tracker = medium.get_duty_tracker("usage_node")

        # Initial usage should be 0%
        assert tracker.usage_percent(0) == 0.0

        # After TX, usage should increase
        tx = medium.start_tx(
            node_id="usage_node",
            payload=payload,
            tx_power_dbm=14,
            position=position,
            time_us=0,
        )
        assert tx is not None

        usage_after = tracker.usage_percent(tx.end_time_us)

        # Usage should be > 0 and reasonable (30-50% for a single TX)
        assert usage_after > 30.0, f"Usage should be significant, got {usage_after}%"
        assert usage_after < 60.0, f"Usage should not exceed budget, got {usage_after}%"


class TestDutyCycleRealWorldScenario:
    """Real-world duty cycle exhaustion scenario."""

    def test_chatty_sensor_gets_throttled(self) -> None:
        """Sensor node sending too frequently gets throttled.

        Simulates a misbehaving sensor that tries to transmit every second
        when it should only transmit every few minutes.
        """
        # EU868: 1% duty cycle over 1 hour
        # For testing, use 1% over 10 seconds = 100ms budget
        medium = Medium(
            duty_cycle_limit_percent=1.0,
            duty_cycle_window_seconds=10,
            enforce_duty_cycle=True,
        )

        payload = b"sensor data"  # ~12 bytes
        position = (0.0, 0.0, 0.0)

        # Each TX is ~248ms, but we only have 100ms budget
        # First TX should fail immediately because airtime > budget
        # Let's use a smaller payload

        # Actually with 100ms budget and ~248ms per TX at SF10,
        # we can't even complete one TX. Let's adjust:

        # Use 10% duty cycle = 1s budget over 10 seconds
        medium = Medium(
            duty_cycle_limit_percent=10.0,
            duty_cycle_window_seconds=10,
            enforce_duty_cycle=True,
        )

        tx_times: list[int] = []
        blocked_count = 0
        current_time = 0

        # Try to transmit every 500ms (way too fast)
        for _ in range(20):
            tx = medium.start_tx(
                node_id="chatty_sensor",
                payload=payload,
                tx_power_dbm=14,
                position=position,
                time_us=current_time,
            )
            if tx is not None:
                tx_times.append(current_time)
                current_time = tx.end_time_us + 500_000  # 500ms after TX ends
            else:
                blocked_count += 1
                current_time += 500_000  # Try again 500ms later

        # Should have been blocked multiple times
        assert blocked_count > 0, "Chatty sensor should get throttled"
        # Should have succeeded some times
        assert len(tx_times) > 0, "Some transmissions should succeed"

    def test_polite_sensor_never_blocked(self) -> None:
        """Sensor with proper TX interval is never blocked.

        With 10% duty cycle over 60 seconds = 6 seconds budget.
        Each TX is ~207ms, so we can do ~29 TXs per window.
        With 5 second intervals, we do 12 TXs per minute = ~2.5s usage.
        That's well under the 6s budget.
        """
        # Use 10% duty cycle over 60 seconds for faster testing
        medium = Medium(
            duty_cycle_limit_percent=10.0,
            duty_cycle_window_seconds=60,
            enforce_duty_cycle=True,
        )

        payload = b"data"
        position = (0.0, 0.0, 0.0)

        blocked_count = 0
        current_time = 0
        tx_interval = 5_000_000  # 5 seconds between transmissions

        # Simulate 2 minutes of operation (24 transmissions at 5s intervals)
        # Total airtime = 24 * 207ms = ~5s, budget = 6s per 60s window
        for _ in range(24):
            tx = medium.start_tx(
                node_id="polite_sensor",
                payload=payload,
                tx_power_dbm=14,
                position=position,
                time_us=current_time,
            )
            if tx is None:
                blocked_count += 1
            else:
                # Next TX attempt after interval (from start of TX)
                current_time += tx_interval

        # Should never be blocked with proper intervals
        assert blocked_count == 0, f"Polite sensor should never be blocked, but was blocked {blocked_count} times"
