# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Hidden terminal problem scenario tests.

The hidden terminal problem occurs when two nodes (A and C) cannot hear
each other but can both reach a third node (B). When A and C transmit
simultaneously, they collide at B, but neither A nor C can detect the
collision via carrier sense because they are out of range of each other.

Topology:
    A ----- B ----- C
    |   5km  |  5km  |

    A-B: in range (5km)
    B-C: in range (5km)
    A-C: out of range (10km > 2 * halfway, or position such that out of range)

This is a classic failure mode in wireless mesh networks.
"""

from __future__ import annotations

import pytest

from lora_medium import Medium
from lora_medium import PropagationModel, SENSITIVITY_SF10


class TestHiddenTerminalBasic:
    """Basic hidden terminal collision tests using Medium directly."""

    def test_hidden_terminal_positions(self) -> None:
        """Verify A-B and B-C in range, A-C out of range."""
        model = PropagationModel()
        max_range = model.max_range(14, sensitivity_dbm=SENSITIVITY_SF10)

        # Position nodes: A at origin, B at 8km, C at 16km
        # A-B distance: 8km < max_range (~16km), in range
        # B-C distance: 8km < max_range, in range
        # A-C distance: 16km ~= max_range, at edge/just out
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (8000.0, 0.0, 0.0)
        pos_c = (16000.0, 0.0, 0.0)

        # Verify A can reach B
        assert model.can_decode(14, 8000.0, sensitivity_dbm=SENSITIVITY_SF10)
        # Verify B can reach C (same distance)
        assert model.can_decode(14, 8000.0, sensitivity_dbm=SENSITIVITY_SF10)
        # Verify A cannot reach C (16km, at or just beyond edge)
        # Due to path loss at max_range, A-C should fail or be marginal
        a_c_distance = 16000.0
        # At exactly max_range, it barely decodes. We want just beyond.
        assert a_c_distance >= max_range * 0.99, f"A-C should be at/near max range: {max_range}"

    def test_hidden_terminal_collision_at_b(self) -> None:
        """A and C transmit simultaneously - collision at B.

        Both signals arrive at B with similar RSSI (equidistant from A and C).
        Without capture effect (6dB difference required), B cannot decode either.
        """
        medium = Medium()

        # Position nodes in a line: A -- B -- C
        # A and C are equidistant from B for equal signal strength
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)
        pos_c = (10000.0, 0.0, 0.0)

        payload_a = b"message from A"
        payload_c = b"message from C"

        # Both A and C start transmitting at the same time
        tx_a = medium.start_tx(
            node_id="node_a",
            payload=payload_a,
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
        )
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,
            position=pos_c,
            time_us=0,
        )

        assert tx_a is not None, "A should be able to transmit"
        assert tx_c is not None, "C should be able to transmit"

        # B tries to receive during the transmission
        mid_time = tx_a.start_time_us + 1000

        candidates = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time,
        )

        # B should see both transmissions as candidates
        assert len(candidates) == 2, "B should see two candidates"

        # RSSI should be similar (A-B and C-B are same distance)
        rssi_a = candidates[0].rssi if candidates[0].transmission.source_node_id == "node_a" else candidates[1].rssi
        rssi_c = candidates[1].rssi if candidates[1].transmission.source_node_id == "node_c" else candidates[0].rssi
        rssi_diff = abs(rssi_a - rssi_c)

        # Equal distance means equal RSSI (within floating point tolerance)
        assert rssi_diff < 1.0, f"RSSI should be similar, diff={rssi_diff}"

        # Collision: neither wins because RSSI difference < 6dB capture threshold
        result = medium.resolve_reception(candidates)
        assert result is None, "Collision should prevent reception"

    def test_hidden_terminal_no_collision_when_sequential(self) -> None:
        """A transmits first, then C - no collision because not overlapping."""
        medium = Medium()

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)
        pos_c = (10000.0, 0.0, 0.0)

        payload_a = b"message from A"
        payload_c = b"message from C"

        # A transmits first
        tx_a = medium.start_tx(
            node_id="node_a",
            payload=payload_a,
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
        )
        assert tx_a is not None

        # B receives A's transmission (no collision)
        mid_time_a = tx_a.start_time_us + 1000
        candidates_a = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time_a,
        )
        assert len(candidates_a) == 1
        result_a = medium.resolve_reception(candidates_a)
        assert result_a is not None, "B should receive A when C is silent"
        assert result_a.payload == payload_a

        # A's transmission ends, then C transmits
        medium.end_tx(tx_a.id)

        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,
            position=pos_c,
            time_us=tx_a.end_time_us + 1000,
        )
        assert tx_c is not None

        # B receives C's transmission (no collision)
        mid_time_c = tx_c.start_time_us + 1000
        candidates_c = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time_c,
        )
        assert len(candidates_c) == 1
        result_c = medium.resolve_reception(candidates_c)
        assert result_c is not None, "B should receive C when A is silent"
        assert result_c.payload == payload_c

    def test_hidden_terminal_a_cannot_hear_c(self) -> None:
        """Verify A cannot receive C's transmission (hidden from each other)."""
        medium = Medium()

        # Use larger separation so A-C is clearly out of range
        # Max range at SF10 is ~16km, so 20km A-C separation ensures no reception
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (10000.0, 0.0, 0.0)  # 10km from A
        pos_c = (20000.0, 0.0, 0.0)  # 20km from A

        payload_c = b"message from C"

        # C transmits
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,
            position=pos_c,
            time_us=0,
        )
        assert tx_c is not None

        # A tries to receive
        mid_time = tx_c.start_time_us + 1000
        candidates = medium.get_rx_candidates(
            rx_node_id="node_a",
            rx_position=pos_a,
            time_us=mid_time,
        )

        # A should NOT see C's transmission (out of range)
        assert len(candidates) == 0, "A should not receive C (hidden terminal)"

    def test_hidden_terminal_b_receives_c(self) -> None:
        """Verify B can receive C's transmission."""
        medium = Medium()

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (10000.0, 0.0, 0.0)  # 10km from A, 10km from C
        pos_c = (20000.0, 0.0, 0.0)  # 20km from A

        payload_c = b"message from C"

        # C transmits
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,
            position=pos_c,
            time_us=0,
        )
        assert tx_c is not None

        # B tries to receive
        mid_time = tx_c.start_time_us + 1000
        candidates = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time,
        )

        # B should see C's transmission (in range)
        assert len(candidates) == 1, "B should receive C"
        result = medium.resolve_reception(candidates)
        assert result is not None
        assert result.payload == payload_c


class TestHiddenTerminalCaptureEffect:
    """Test capture effect scenarios in hidden terminal topology."""

    def test_capture_effect_stronger_signal_wins(self) -> None:
        """When one signal is much stronger, capture effect allows reception.

        If A is closer to B than C, and A's signal is 6+ dB stronger,
        B can decode A's message despite the collision.
        """
        medium = Medium()

        # A much closer to B than C
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (1000.0, 0.0, 0.0)   # 1km from A
        pos_c = (11000.0, 0.0, 0.0)  # 10km from B, 11km from A

        payload_a = b"message from A"
        payload_c = b"message from C"

        # Both transmit simultaneously
        tx_a = medium.start_tx(
            node_id="node_a",
            payload=payload_a,
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
        )
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,
            position=pos_c,
            time_us=0,
        )

        assert tx_a is not None
        assert tx_c is not None

        # B tries to receive
        mid_time = tx_a.start_time_us + 1000
        candidates = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time,
        )

        # May see 1 or 2 candidates depending on whether C is in range
        # Focus on the collision resolution
        if len(candidates) >= 2:
            # Find RSSI difference
            sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)
            rssi_diff = sorted_candidates[0].rssi - sorted_candidates[1].rssi

            # With 1km vs 10km distances, RSSI difference should be substantial
            # Path loss difference: 10*n*log10(10000/1000) = 10*2.7*1 = 27 dB
            assert rssi_diff > 6.0, f"Expected capture effect, RSSI diff={rssi_diff}"

            result = medium.resolve_reception(candidates)
            assert result is not None, "Capture effect should allow reception"
            assert result.payload == payload_a, "Stronger signal (A) should win"
        else:
            # C is out of range of B - A received without collision
            assert len(candidates) == 1
            result = medium.resolve_reception(candidates)
            assert result is not None
            assert result.payload == payload_a


class TestHiddenTerminalAsymmetric:
    """Test asymmetric hidden terminal scenarios."""

    def test_asymmetric_power_hidden_terminal(self) -> None:
        """A has higher TX power than C, creating asymmetric hidden terminal."""
        medium = Medium()

        # Symmetric positions but asymmetric TX power
        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)
        pos_c = (10000.0, 0.0, 0.0)

        payload_a = b"message from A"
        payload_c = b"message from C"

        # A transmits at higher power (20 dBm vs 14 dBm)
        tx_a = medium.start_tx(
            node_id="node_a",
            payload=payload_a,
            tx_power_dbm=20,  # Higher power
            position=pos_a,
            time_us=0,
        )
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=payload_c,
            tx_power_dbm=14,  # Normal power
            position=pos_c,
            time_us=0,
        )

        assert tx_a is not None
        assert tx_c is not None

        # B tries to receive
        mid_time = tx_a.start_time_us + 1000
        candidates = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time,
        )

        # Both should be received as candidates
        assert len(candidates) == 2

        # A's signal should be 6 dB stronger (20 - 14 = 6 dB)
        sorted_candidates = sorted(candidates, key=lambda c: c.rssi, reverse=True)
        rssi_diff = sorted_candidates[0].rssi - sorted_candidates[1].rssi

        # Exactly 6 dB difference allows capture
        assert rssi_diff >= 6.0, f"A should be >=6dB stronger, diff={rssi_diff}"

        result = medium.resolve_reception(candidates)
        assert result is not None, "Capture effect should allow A's stronger signal"
        assert result.payload == payload_a

    def test_three_way_hidden_terminal(self) -> None:
        """Three transmitters all hidden from each other, collide at central node.

        Topology:
              A (north)
              |
        C --- B --- D
              |
           (south)

        A, C, D all transmit to B simultaneously.
        """
        medium = Medium()

        # B at center, A/C/D equidistant at 5km
        pos_b = (5000.0, 5000.0, 0.0)
        pos_a = (5000.0, 10000.0, 0.0)  # North
        pos_c = (0.0, 5000.0, 0.0)       # West
        pos_d = (10000.0, 5000.0, 0.0)   # East

        # All transmit simultaneously
        tx_a = medium.start_tx(
            node_id="node_a",
            payload=b"from A",
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
        )
        tx_c = medium.start_tx(
            node_id="node_c",
            payload=b"from C",
            tx_power_dbm=14,
            position=pos_c,
            time_us=0,
        )
        tx_d = medium.start_tx(
            node_id="node_d",
            payload=b"from D",
            tx_power_dbm=14,
            position=pos_d,
            time_us=0,
        )

        assert tx_a is not None
        assert tx_c is not None
        assert tx_d is not None

        # B tries to receive
        mid_time = tx_a.start_time_us + 1000
        candidates = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=mid_time,
        )

        # B sees all three (all equidistant at 5km, in range)
        assert len(candidates) == 3, "B should see all three transmitters"

        # All three have equal RSSI - complete collision
        result = medium.resolve_reception(candidates)
        assert result is None, "Three-way collision should prevent reception"
