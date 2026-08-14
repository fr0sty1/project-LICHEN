# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Jammer interference scenario tests.

Radio jammers transmit continuously on specific frequencies to disrupt
communications. This tests the simulator's JammerRule with channel-specific
jamming, verifying:

1. Channel-specific jamming: jammers only affect configured channels
2. Avoidance by channel hopping: nodes can escape interference by using
   unjammed channels
3. Message delivery degradation: quantify impact on delivery rates

Topology:
    Jammer (J) positioned to affect receiver (B). A transmits to B.

    A ------- B
              ^
              |
              J (jams specific channels)
"""

from __future__ import annotations

from lora_medium import ChaosEngine, JammerRule, Medium


class TestJammerChannelSpecific:
    """Test channel-specific jamming behavior."""

    def test_jammer_affects_only_specified_channels(self) -> None:
        """JammerRule only jams transmissions on configured channels."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer at position (5000, 0, 0) with 10km radius, jamming channels 0, 1
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={0, 1})
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)  # B is right at the jammer

        # Transmit on channel 0 (jammed)
        tx_ch0 = medium.start_tx(
            node_id="node_a",
            payload=b"test on ch0",
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
            channel=0,
        )
        assert tx_ch0 is not None

        # Get candidates for B on channel 0
        candidates_ch0 = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=tx_ch0.start_time_us + 1000,
            channel=0,
        )
        assert len(candidates_ch0) == 1

        # Apply chaos rules - should be jammed
        result_ch0 = chaos.apply_all(
            candidates_ch0[0],
            rx_node_id="node_b",
            rx_position=pos_b,
        )
        assert result_ch0 is None, "Channel 0 should be jammed"

        # Transmit on channel 2 (not jammed)
        medium.end_tx(tx_ch0.id)
        tx_ch2 = medium.start_tx(
            node_id="node_a",
            payload=b"test on ch2",
            tx_power_dbm=14,
            position=pos_a,
            time_us=tx_ch0.end_time_us + 1,
            channel=2,
        )
        assert tx_ch2 is not None

        # Get candidates for B on channel 2
        candidates_ch2 = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=tx_ch2.start_time_us + 1000,
            channel=2,
        )
        assert len(candidates_ch2) == 1

        # Apply chaos rules - should NOT be jammed
        result_ch2 = chaos.apply_all(
            candidates_ch2[0],
            rx_node_id="node_b",
            rx_position=pos_b,
        )
        assert result_ch2 is not None, "Channel 2 should NOT be jammed"

    def test_jammer_with_no_channels_jams_all(self) -> None:
        """JammerRule with channels=None jams all channels."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer with no channel restriction
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels=None)
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        for channel in range(4):
            tx = medium.start_tx(
                node_id="node_a",
                payload=f"test on ch{channel}".encode(),
                tx_power_dbm=14,
                position=pos_a,
                time_us=channel * 1_000_000,
                channel=channel,
            )
            assert tx is not None

            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            assert len(candidates) == 1

            result = chaos.apply_all(
                candidates[0],
                rx_node_id="node_b",
                rx_position=pos_b,
            )
            assert result is None, f"Channel {channel} should be jammed"
            medium.end_tx(tx.id)

    def test_jammer_radius_boundary(self) -> None:
        """Jammer only affects receivers within radius."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer with 3km radius
        jammer = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=3000.0, channels={0})
        chaos.add_rule(jammer)

        pos_a = (10000.0, 0.0, 0.0)  # Transmitter far away

        # Receiver inside jammer radius (2km from jammer)
        pos_inside = (2000.0, 0.0, 0.0)

        # Receiver outside jammer radius (4km from jammer)
        pos_outside = (4000.0, 0.0, 0.0)

        tx = medium.start_tx(
            node_id="node_a",
            payload=b"test",
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
            channel=0,
        )
        assert tx is not None

        # Check receiver inside radius - should be jammed
        candidates_inside = medium.get_rx_candidates(
            rx_node_id="node_inside",
            rx_position=pos_inside,
            time_us=tx.start_time_us + 1000,
            channel=0,
        )
        if candidates_inside:  # Only if in range of transmitter
            result_inside = chaos.apply_all(
                candidates_inside[0],
                rx_node_id="node_inside",
                rx_position=pos_inside,
            )
            assert result_inside is None, "Receiver inside radius should be jammed"

        # Check receiver outside radius - should NOT be jammed
        candidates_outside = medium.get_rx_candidates(
            rx_node_id="node_outside",
            rx_position=pos_outside,
            time_us=tx.start_time_us + 1000,
            channel=0,
        )
        if candidates_outside:  # Only if in range of transmitter
            result_outside = chaos.apply_all(
                candidates_outside[0],
                rx_node_id="node_outside",
                rx_position=pos_outside,
            )
            assert result_outside is not None, "Receiver outside radius should NOT be jammed"


class TestChannelHoppingAvoidance:
    """Test that nodes can avoid interference by channel hopping."""

    def test_channel_hop_escapes_jammer(self) -> None:
        """Transmissions on unjammed channels succeed despite jammer."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer at receiver position, only jamming channels 0-3
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={0, 1, 2, 3})
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        # Track successes per channel
        successes_jammed = 0
        successes_unjammed = 0

        # Test jammed channels (0-3)
        for channel in range(4):
            tx = medium.start_tx(
                node_id="node_a",
                payload=b"test",
                tx_power_dbm=14,
                position=pos_a,
                time_us=channel * 1_000_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    successes_jammed += 1
            medium.end_tx(tx.id)

        # Test unjammed channels (4-7)
        for channel in range(4, 8):
            tx = medium.start_tx(
                node_id="node_a",
                payload=b"test",
                tx_power_dbm=14,
                position=pos_a,
                time_us=channel * 1_000_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    successes_unjammed += 1
            medium.end_tx(tx.id)

        # All jammed channels should fail, all unjammed should succeed
        assert successes_jammed == 0, "Jammed channels should all fail"
        assert successes_unjammed == 4, "Unjammed channels should all succeed"

    def test_partial_channel_jamming(self) -> None:
        """Partial channel jamming - some hops succeed, some fail."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer only jamming odd channels
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={1, 3, 5, 7})
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        # Simulate hopping through channels
        even_success = 0
        odd_success = 0

        for channel in range(8):
            tx = medium.start_tx(
                node_id="node_a",
                payload=b"test",
                tx_power_dbm=14,
                position=pos_a,
                time_us=channel * 1_000_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    if channel % 2 == 0:
                        even_success += 1
                    else:
                        odd_success += 1
            medium.end_tx(tx.id)

        # Even channels (0, 2, 4, 6) should succeed
        assert even_success == 4, f"Expected 4 even channel successes, got {even_success}"
        # Odd channels (1, 3, 5, 7) should fail
        assert odd_success == 0, f"Expected 0 odd channel successes, got {odd_success}"


class TestMessageDeliveryDegradation:
    """Test message delivery rates under jamming conditions."""

    def test_delivery_rate_with_no_jammer(self) -> None:
        """Baseline: 100% delivery with no jammer."""
        medium = Medium()
        chaos = ChaosEngine()

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        deliveries = 0
        attempts = 20

        for i in range(attempts):
            tx = medium.start_tx(
                node_id="node_a",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                position=pos_a,
                time_us=i * 500_000,
                channel=i % 8,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=i % 8,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    deliveries += 1
            medium.end_tx(tx.id)

        delivery_rate = deliveries / attempts
        assert delivery_rate == 1.0, f"Expected 100% delivery, got {delivery_rate * 100}%"

    def test_delivery_rate_with_partial_jammer(self) -> None:
        """50% delivery expected when half channels jammed (uniform hop pattern)."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jam channels 0-3 (half of 8 channels)
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={0, 1, 2, 3})
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        deliveries = 0
        attempts = 40  # 5 cycles through 8 channels

        for i in range(attempts):
            channel = i % 8  # Uniform hopping
            tx = medium.start_tx(
                node_id="node_a",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                position=pos_a,
                time_us=i * 500_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    deliveries += 1
            medium.end_tx(tx.id)

        delivery_rate = deliveries / attempts
        # With half channels jammed and uniform hopping, expect ~50% delivery
        assert 0.4 <= delivery_rate <= 0.6, f"Expected ~50% delivery, got {delivery_rate * 100}%"

    def test_delivery_rate_with_full_jammer(self) -> None:
        """0% delivery expected when all channels jammed."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jam all channels
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels=None)
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        deliveries = 0
        attempts = 20

        for i in range(attempts):
            tx = medium.start_tx(
                node_id="node_a",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                position=pos_a,
                time_us=i * 500_000,
                channel=i % 8,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=i % 8,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    deliveries += 1
            medium.end_tx(tx.id)

        delivery_rate = deliveries / attempts
        assert delivery_rate == 0.0, f"Expected 0% delivery, got {delivery_rate * 100}%"

    def test_smart_hop_avoids_jammed_channels(self) -> None:
        """Smart hopping that avoids known jammed channels achieves 100%."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jam channels 0-3
        jammer = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={0, 1, 2, 3})
        chaos.add_rule(jammer)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        # Smart hopping: only use unjammed channels 4-7
        unjammed_channels = [4, 5, 6, 7]

        deliveries = 0
        attempts = 20

        for i in range(attempts):
            channel = unjammed_channels[i % len(unjammed_channels)]
            tx = medium.start_tx(
                node_id="node_a",
                payload=f"msg{i}".encode(),
                tx_power_dbm=14,
                position=pos_a,
                time_us=i * 500_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is not None:
                    deliveries += 1
            medium.end_tx(tx.id)

        delivery_rate = deliveries / attempts
        msg = f"Smart hopping should achieve 100%, got {delivery_rate * 100}%"
        assert delivery_rate == 1.0, msg


class TestMultipleJammers:
    """Test scenarios with multiple jammers."""

    def test_overlapping_jammers_different_channels(self) -> None:
        """Multiple jammers covering different channel sets."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer 1 covers channels 0, 1
        jammer1 = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={0, 1})
        chaos.add_rule(jammer1)

        # Jammer 2 covers channels 2, 3
        jammer2 = JammerRule(x=5000.0, y=0.0, z=0.0, radius_m=10000.0, channels={2, 3})
        chaos.add_rule(jammer2)

        pos_a = (0.0, 0.0, 0.0)
        pos_b = (5000.0, 0.0, 0.0)

        # Check each channel
        jammed_count = 0
        for channel in range(8):
            tx = medium.start_tx(
                node_id="node_a",
                payload=b"test",
                tx_power_dbm=14,
                position=pos_a,
                time_us=channel * 1_000_000,
                channel=channel,
            )
            candidates = medium.get_rx_candidates(
                rx_node_id="node_b",
                rx_position=pos_b,
                time_us=tx.start_time_us + 1000,
                channel=channel,
            )
            if candidates:
                result = chaos.apply_all(candidates[0], "node_b", pos_b)
                if result is None:
                    jammed_count += 1
            medium.end_tx(tx.id)

        # Channels 0-3 should be jammed (4 channels total)
        assert jammed_count == 4, f"Expected 4 jammed channels, got {jammed_count}"

    def test_geographically_separate_jammers(self) -> None:
        """Jammers at different positions affect different receivers."""
        medium = Medium()
        chaos = ChaosEngine()

        # Jammer near receiver B
        jammer_b = JammerRule(x=1000.0, y=0.0, z=0.0, radius_m=2000.0, channels={0})
        chaos.add_rule(jammer_b)

        # Jammer near receiver C
        jammer_c = JammerRule(x=10000.0, y=0.0, z=0.0, radius_m=2000.0, channels={0})
        chaos.add_rule(jammer_c)

        pos_a = (5000.0, 0.0, 0.0)  # Transmitter in the middle
        pos_b = (1000.0, 0.0, 0.0)  # Near jammer_b
        pos_c = (10000.0, 0.0, 0.0)  # Near jammer_c
        pos_d = (5000.0, 5000.0, 0.0)  # Away from both jammers

        tx = medium.start_tx(
            node_id="node_a",
            payload=b"test",
            tx_power_dbm=14,
            position=pos_a,
            time_us=0,
            channel=0,
        )
        assert tx is not None

        # B is near jammer_b - should be jammed
        candidates_b = medium.get_rx_candidates(
            rx_node_id="node_b",
            rx_position=pos_b,
            time_us=tx.start_time_us + 1000,
            channel=0,
        )
        if candidates_b:
            result_b = chaos.apply_all(candidates_b[0], "node_b", pos_b)
            assert result_b is None, "B should be jammed"

        # C is near jammer_c - should be jammed
        candidates_c = medium.get_rx_candidates(
            rx_node_id="node_c",
            rx_position=pos_c,
            time_us=tx.start_time_us + 1000,
            channel=0,
        )
        if candidates_c:
            result_c = chaos.apply_all(candidates_c[0], "node_c", pos_c)
            assert result_c is None, "C should be jammed"

        # D is away from both - should NOT be jammed
        candidates_d = medium.get_rx_candidates(
            rx_node_id="node_d",
            rx_position=pos_d,
            time_us=tx.start_time_us + 1000,
            channel=0,
        )
        if candidates_d:
            result_d = chaos.apply_all(candidates_d[0], "node_d", pos_d)
            assert result_d is not None, "D should NOT be jammed"
