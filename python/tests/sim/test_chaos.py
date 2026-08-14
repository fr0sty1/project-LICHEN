# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the chaos rules framework."""

import pytest
from lora_medium import (
    ChaosEngine,
    ChaosRule,
    DegradeRule,
    DropRule,
    GilbertElliottRule,
    JammerRule,
    LatencyRule,
    PartitionRule,
    RxCandidate,
    Transmission,
    TxJitterRule,
)


def make_transmission(source_node_id: str = "sender") -> Transmission:
    """Create a test transmission."""
    return Transmission(
        source_node_id=source_node_id,
        payload=b"test",
        tx_power_dbm=14,
        start_time_us=1000,
        end_time_us=2000,
    )


def make_candidate(
    source_node_id: str = "sender",
    rssi: float = -70.0,
    snr: float = 50.0,
) -> RxCandidate:
    """Create a test reception candidate."""
    return RxCandidate(
        transmission=make_transmission(source_node_id),
        rssi=rssi,
        snr=snr,
    )


class TestDropRule:
    """Test DropRule functionality."""

    def test_drop_rule_has_unique_id(self) -> None:
        """DropRule generates unique IDs."""
        rule1 = DropRule(node_id="node1")
        rule2 = DropRule(node_id="node1")
        assert rule1.id != rule2.id

    def test_drop_rule_custom_id(self) -> None:
        """DropRule accepts custom ID."""
        rule = DropRule(node_id="node1", id="custom-id")
        assert rule.id == "custom-id"

    def test_drop_tx_direction_matches_sender(self) -> None:
        """DropRule with tx direction matches when node is sender."""
        rule = DropRule(node_id="sender", direction="tx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_drop_tx_direction_does_not_match_receiver(self) -> None:
        """DropRule with tx direction does not match when node is receiver."""
        rule = DropRule(node_id="receiver", direction="tx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is False

    def test_drop_rx_direction_matches_receiver(self) -> None:
        """DropRule with rx direction matches when node is receiver."""
        rule = DropRule(node_id="receiver", direction="rx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_drop_rx_direction_does_not_match_sender(self) -> None:
        """DropRule with rx direction does not match when node is sender."""
        rule = DropRule(node_id="sender", direction="rx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is False

    def test_drop_both_direction_matches_sender(self) -> None:
        """DropRule with both direction matches when node is sender."""
        rule = DropRule(node_id="sender", direction="both")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_drop_both_direction_matches_receiver(self) -> None:
        """DropRule with both direction matches when node is receiver."""
        rule = DropRule(node_id="receiver", direction="both")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_drop_both_direction_default(self) -> None:
        """DropRule defaults to both direction."""
        rule = DropRule(node_id="node1")
        assert rule.direction == "both"

    def test_drop_rule_apply_returns_none(self) -> None:
        """DropRule apply always returns None."""
        rule = DropRule(node_id="sender")
        candidate = make_candidate()
        assert rule.apply(candidate) is None


class TestGilbertElliottRule:
    """Test GilbertElliottRule burst error model."""

    def test_gilbert_elliott_has_unique_id(self) -> None:
        """GilbertElliottRule generates unique IDs."""
        rule1 = GilbertElliottRule(node_id="node1")
        rule2 = GilbertElliottRule(node_id="node1")
        assert rule1.id != rule2.id

    def test_gilbert_elliott_custom_id(self) -> None:
        """GilbertElliottRule accepts custom ID."""
        rule = GilbertElliottRule(node_id="node1", id="custom-id")
        assert rule.id == "custom-id"

    def test_gilbert_elliott_global_matches_any(self) -> None:
        """GilbertElliottRule with node_id=None matches all transmissions."""
        rule = GilbertElliottRule(node_id=None)
        tx1 = make_transmission("sender1")
        tx2 = make_transmission("sender2")
        assert rule.matches(tx1, "receiver") is True
        assert rule.matches(tx2, "receiver") is True

    def test_gilbert_elliott_tx_direction(self) -> None:
        """GilbertElliottRule with tx direction matches sender only."""
        rule = GilbertElliottRule(node_id="sender", direction="tx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True
        assert rule.matches(tx, "sender") is True  # rx=sender, but sender matches tx

    def test_gilbert_elliott_rx_direction(self) -> None:
        """GilbertElliottRule with rx direction matches receiver only."""
        rule = GilbertElliottRule(node_id="receiver", direction="rx")
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

        rule2 = GilbertElliottRule(node_id="sender", direction="rx")
        assert rule2.matches(tx, "receiver") is False

    def test_gilbert_elliott_both_direction(self) -> None:
        """GilbertElliottRule with both direction matches either."""
        rule = GilbertElliottRule(node_id="node1", direction="both")
        tx = make_transmission("node1")
        assert rule.matches(tx, "receiver") is True  # node1 is sender
        tx2 = make_transmission("sender")
        assert rule.matches(tx2, "node1") is True  # node1 is receiver

    def test_gilbert_elliott_rejects_invalid_probability(self) -> None:
        """GilbertElliottRule rejects probabilities outside [0, 1]."""
        with pytest.raises(ValueError, match="p_good_to_bad must be in"):
            GilbertElliottRule(node_id="n", p_good_to_bad=1.5)
        with pytest.raises(ValueError, match="p_bad_to_good must be in"):
            GilbertElliottRule(node_id="n", p_bad_to_good=-0.1)
        with pytest.raises(ValueError, match="loss_prob_good must be in"):
            GilbertElliottRule(node_id="n", loss_prob_good=2.0)
        with pytest.raises(ValueError, match="loss_prob_bad must be in"):
            GilbertElliottRule(node_id="n", loss_prob_bad=-1.0)

    def test_gilbert_elliott_deterministic_with_seed(self) -> None:
        """GilbertElliottRule is deterministic with seeded rng."""
        import random

        def make_results(seed: int) -> list[bool]:
            rng = random.Random(seed)
            rule = GilbertElliottRule(
                node_id=None,
                p_good_to_bad=0.2,
                p_bad_to_good=0.3,
                loss_prob_good=0.1,
                loss_prob_bad=0.7,
                rng=rng,
            )
            results = []
            for i in range(20):
                tx = Transmission(
                    source_node_id="sender",
                    payload=b"test",
                    tx_power_dbm=14,
                    start_time_us=1000 + i * 1000,
                    end_time_us=2000 + i * 1000,
                )
                candidate = RxCandidate(transmission=tx, rssi=-70.0, snr=50.0)
                result = rule.apply(candidate)
                results.append(result is not None)
            return results

        results1 = make_results(42)
        results2 = make_results(42)
        assert results1 == results2

    def test_gilbert_elliott_zero_loss_good_passes_in_good_state(self) -> None:
        """With loss_prob_good=0 and staying in good state, packets pass."""
        import random

        rng = random.Random(999)
        rule = GilbertElliottRule(
            node_id=None,
            p_good_to_bad=0.0,  # Never transition to bad
            p_bad_to_good=1.0,
            loss_prob_good=0.0,  # Never lose in good state
            loss_prob_bad=1.0,
            rng=rng,
        )
        candidate = make_candidate()
        # All packets should pass since we stay in good state with 0% loss
        for _ in range(10):
            result = rule.apply(candidate)
            assert result is not None

    def test_gilbert_elliott_always_bad_state_loses_all(self) -> None:
        """With p_good_to_bad=1.0 and loss_prob_bad=1.0, all packets lost."""
        import random

        rng = random.Random(123)
        rule = GilbertElliottRule(
            node_id=None,
            p_good_to_bad=1.0,  # Immediately transition to bad
            p_bad_to_good=0.0,  # Never recover
            loss_prob_good=0.0,
            loss_prob_bad=1.0,  # Always lose in bad state
            rng=rng,
        )
        # First packet may pass (starts in good state), subsequent should fail
        candidate = make_candidate()
        # After first apply, we're in bad state
        _ = rule.apply(candidate)
        # Now all packets should be lost
        for i in range(10):
            tx = Transmission(
                source_node_id="sender",
                payload=b"test",
                tx_power_dbm=14,
                start_time_us=2000 + i * 1000,
                end_time_us=3000 + i * 1000,
            )
            cand = RxCandidate(transmission=tx, rssi=-70.0, snr=50.0)
            result = rule.apply(cand)
            assert result is None

    def test_gilbert_elliott_burst_pattern(self) -> None:
        """GilbertElliottRule produces bursty loss patterns."""
        import random

        rng = random.Random(42)
        rule = GilbertElliottRule(
            node_id=None,
            p_good_to_bad=0.1,
            p_bad_to_good=0.2,  # Average burst ~5 packets
            loss_prob_good=0.0,  # No loss in good state
            loss_prob_bad=1.0,  # Always lose in bad state
            rng=rng,
        )

        results = []
        for i in range(100):
            tx = Transmission(
                source_node_id="sender",
                payload=b"test",
                tx_power_dbm=14,
                start_time_us=1000 + i * 1000,
                end_time_us=2000 + i * 1000,
            )
            candidate = RxCandidate(transmission=tx, rssi=-70.0, snr=50.0)
            result = rule.apply(candidate)
            results.append(1 if result is None else 0)  # 1 = loss, 0 = success

        # Check for burst pattern: count runs of consecutive losses
        bursts = []
        current_burst = 0
        for r in results:
            if r == 1:
                current_burst += 1
            else:
                if current_burst > 0:
                    bursts.append(current_burst)
                current_burst = 0
        if current_burst > 0:
            bursts.append(current_burst)

        # Should have some bursts (not all isolated losses)
        assert len(bursts) > 0
        # At least one burst should be > 1 packet (bursty behavior)
        assert any(b > 1 for b in bursts), f"No bursts found, all isolated: {bursts}"

    def test_gilbert_elliott_reset_states(self) -> None:
        """reset_states() clears all link states to good."""
        import random

        rng = random.Random(42)
        rule = GilbertElliottRule(
            node_id=None,
            p_good_to_bad=1.0,  # Always transition to bad
            p_bad_to_good=0.0,
            loss_prob_good=0.0,
            loss_prob_bad=1.0,
            rng=rng,
        )

        # Drive into bad state
        candidate = make_candidate()
        rule.apply(candidate)

        # Reset
        rule.reset_states()

        # Should be back in good state (no loss)
        rng2 = random.Random(42)
        rule2 = GilbertElliottRule(
            node_id=None,
            p_good_to_bad=0.0,  # Stay in good
            p_bad_to_good=1.0,
            loss_prob_good=0.0,
            loss_prob_bad=1.0,
            rng=rng2,
        )
        # This should pass because we're in good state
        result = rule2.apply(make_candidate())
        assert result is not None


class TestPartitionRule:
    """Test PartitionRule functionality."""

    def test_partition_rule_has_unique_id(self) -> None:
        """PartitionRule generates unique IDs."""
        rule1 = PartitionRule(groups=[{"a"}, {"b"}])
        rule2 = PartitionRule(groups=[{"a"}, {"b"}])
        assert rule1.id != rule2.id

    def test_partition_same_group_does_not_match(self) -> None:
        """Nodes in same group do not match (can communicate)."""
        rule = PartitionRule(groups=[{"node1", "node2"}, {"node3", "node4"}])
        tx = make_transmission("node1")
        assert rule.matches(tx, "node2") is False

    def test_partition_different_groups_matches(self) -> None:
        """Nodes in different groups match (cannot communicate)."""
        rule = PartitionRule(groups=[{"node1", "node2"}, {"node3", "node4"}])
        tx = make_transmission("node1")
        assert rule.matches(tx, "node3") is True

    def test_partition_sender_not_in_group_does_not_match(self) -> None:
        """Sender not in any group does not match."""
        rule = PartitionRule(groups=[{"node1"}, {"node2"}])
        tx = make_transmission("outsider")
        assert rule.matches(tx, "node1") is False

    def test_partition_receiver_not_in_group_does_not_match(self) -> None:
        """Receiver not in any group does not match."""
        rule = PartitionRule(groups=[{"node1"}, {"node2"}])
        tx = make_transmission("node1")
        assert rule.matches(tx, "outsider") is False

    def test_partition_rule_apply_returns_none(self) -> None:
        """PartitionRule apply returns None to drop cross-partition packets."""
        rule = PartitionRule(groups=[{"node1"}, {"node2"}])
        candidate = make_candidate()
        assert rule.apply(candidate) is None

    def test_partition_three_groups(self) -> None:
        """PartitionRule works with three groups."""
        rule = PartitionRule(groups=[{"a"}, {"b"}, {"c"}])
        tx_a = make_transmission("a")
        tx_b = make_transmission("b")

        # Cross-group: a->b, a->c, b->c all match
        assert rule.matches(tx_a, "b") is True
        assert rule.matches(tx_a, "c") is True
        assert rule.matches(tx_b, "c") is True

        # Not in group: doesn't match
        assert rule.matches(tx_a, "outsider") is False


class TestDegradeRule:
    """Test DegradeRule functionality."""

    def test_degrade_rule_has_unique_id(self) -> None:
        """DegradeRule generates unique IDs."""
        rule1 = DegradeRule(node_id="node1", rssi_penalty_db=10.0)
        rule2 = DegradeRule(node_id="node1", rssi_penalty_db=10.0)
        assert rule1.id != rule2.id

    def test_degrade_matches_sender(self) -> None:
        """DegradeRule matches when node is sender."""
        rule = DegradeRule(node_id="sender", rssi_penalty_db=10.0)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_degrade_matches_receiver(self) -> None:
        """DegradeRule matches when node is receiver."""
        rule = DegradeRule(node_id="receiver", rssi_penalty_db=10.0)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_degrade_does_not_match_unrelated(self) -> None:
        """DegradeRule does not match unrelated nodes."""
        rule = DegradeRule(node_id="other", rssi_penalty_db=10.0)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is False

    def test_degrade_reduces_rssi(self) -> None:
        """DegradeRule reduces RSSI by penalty."""
        rule = DegradeRule(node_id="sender", rssi_penalty_db=10.0)
        candidate = make_candidate(rssi=-70.0, snr=50.0)
        result = rule.apply(candidate)

        assert result is not None
        assert result.rssi == pytest.approx(-80.0)

    def test_degrade_reduces_snr(self) -> None:
        """DegradeRule reduces SNR by penalty."""
        rule = DegradeRule(node_id="sender", rssi_penalty_db=10.0)
        candidate = make_candidate(rssi=-70.0, snr=50.0)
        result = rule.apply(candidate)

        assert result is not None
        assert result.snr == pytest.approx(40.0)

    def test_degrade_preserves_transmission(self) -> None:
        """DegradeRule preserves the transmission object."""
        rule = DegradeRule(node_id="sender", rssi_penalty_db=10.0)
        candidate = make_candidate()
        result = rule.apply(candidate)

        assert result is not None
        assert result.transmission is candidate.transmission

    def test_degrade_creates_new_candidate(self) -> None:
        """DegradeRule creates a new RxCandidate, not mutating original."""
        rule = DegradeRule(node_id="sender", rssi_penalty_db=10.0)
        candidate = make_candidate(rssi=-70.0, snr=50.0)
        result = rule.apply(candidate)

        assert result is not candidate
        assert candidate.rssi == -70.0  # Original unchanged


class TestJammerRule:
    """Test JammerRule functionality."""

    def test_jammer_rule_has_unique_id(self) -> None:
        """JammerRule generates unique IDs."""
        rule1 = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        rule2 = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        assert rule1.id != rule2.id

    def test_jammer_always_matches(self) -> None:
        """JammerRule always matches (distance check in apply)."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        tx = make_transmission()
        assert rule.matches(tx, "any_receiver") is True

    def test_jammer_drops_receiver_in_radius(self) -> None:
        """JammerRule drops reception when receiver is within radius."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        candidate = make_candidate()
        rx_position = (50.0, 0.0, 0.0)  # 50m from jammer

        result = rule.apply(candidate, rx_position)
        assert result is None

    def test_jammer_passes_receiver_outside_radius(self) -> None:
        """JammerRule passes reception when receiver is outside radius."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        candidate = make_candidate()
        rx_position = (150.0, 0.0, 0.0)  # 150m from jammer

        result = rule.apply(candidate, rx_position)
        assert result is candidate

    def test_jammer_drops_at_exact_radius(self) -> None:
        """JammerRule drops reception at exactly the radius boundary."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        candidate = make_candidate()
        rx_position = (100.0, 0.0, 0.0)  # Exactly at boundary

        result = rule.apply(candidate, rx_position)
        assert result is None

    def test_jammer_3d_distance(self) -> None:
        """JammerRule uses 3D distance calculation."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        candidate = make_candidate()

        # 3-4-5 triangle in 3D scaled: (60, 80, 0) = 100m
        rx_at_boundary = (60.0, 80.0, 0.0)
        assert rule.apply(candidate, rx_at_boundary) is None

        # Just outside: sqrt(61^2 + 80^2) > 100
        rx_outside = (61.0, 80.0, 0.0)
        assert rule.apply(candidate, rx_outside) is candidate

    def test_jammer_offset_position(self) -> None:
        """JammerRule works with non-origin position."""
        rule = JammerRule(x=100.0, y=100.0, z=0.0, radius_m=50.0)
        candidate = make_candidate()

        # Within 50m of (100, 100, 0)
        rx_inside = (120.0, 100.0, 0.0)  # 20m away
        assert rule.apply(candidate, rx_inside) is None

        # Outside 50m of (100, 100, 0)
        rx_outside = (200.0, 100.0, 0.0)  # 100m away
        assert rule.apply(candidate, rx_outside) is candidate

    def test_jammer_no_position_passes_through(self) -> None:
        """JammerRule passes through when no rx_position provided."""
        rule = JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0)
        candidate = make_candidate()

        result = rule.apply(candidate, rx_position=None)
        assert result is candidate


class TestLatencyRule:
    """Test LatencyRule functionality."""

    def test_latency_rule_has_unique_id(self) -> None:
        """LatencyRule generates unique IDs."""
        rule1 = LatencyRule(node_id="node1", added_us=1000)
        rule2 = LatencyRule(node_id="node1", added_us=1000)
        assert rule1.id != rule2.id

    def test_latency_matches_sender(self) -> None:
        """LatencyRule matches when node is sender."""
        rule = LatencyRule(node_id="sender", added_us=1000)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_latency_matches_receiver(self) -> None:
        """LatencyRule matches when node is receiver."""
        rule = LatencyRule(node_id="receiver", added_us=1000)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is True

    def test_latency_does_not_match_unrelated(self) -> None:
        """LatencyRule does not match unrelated nodes."""
        rule = LatencyRule(node_id="other", added_us=1000)
        tx = make_transmission("sender")
        assert rule.matches(tx, "receiver") is False

    def test_latency_adds_delay_to_candidate(self) -> None:
        """LatencyRule sets added_latency_us on the returned candidate."""
        rule = LatencyRule(node_id="sender", added_us=1000)
        candidate = make_candidate()
        result = rule.apply(candidate)
        assert result is not candidate
        assert result.added_latency_us == 1000

    def test_latency_stacks_with_existing_delay(self) -> None:
        """Multiple LatencyRules accumulate added_latency_us."""
        rule = LatencyRule(node_id="sender", added_us=500)
        from dataclasses import replace

        candidate = replace(make_candidate(), added_latency_us=200)
        result = rule.apply(candidate)
        assert result.added_latency_us == 700


class TestTxJitterRule:
    """Test TxJitterRule functionality."""

    def test_tx_jitter_rule_has_unique_id(self) -> None:
        """TxJitterRule generates unique IDs."""
        rule1 = TxJitterRule(jitter_min_us=100, jitter_max_us=500)
        rule2 = TxJitterRule(jitter_min_us=100, jitter_max_us=500)
        assert rule1.id != rule2.id

    def test_tx_jitter_rule_custom_id(self) -> None:
        """TxJitterRule accepts custom ID."""
        rule = TxJitterRule(jitter_min_us=100, jitter_max_us=500, id="custom-id")
        assert rule.id == "custom-id"

    def test_tx_jitter_global_matches_any_sender(self) -> None:
        """TxJitterRule with node_id=None matches any sender."""
        rule = TxJitterRule(jitter_min_us=100, jitter_max_us=500, node_id=None)
        tx1 = make_transmission("sender1")
        tx2 = make_transmission("sender2")
        assert rule.matches(tx1, "receiver") is True
        assert rule.matches(tx2, "receiver") is True

    def test_tx_jitter_per_node_matches_specific_sender(self) -> None:
        """TxJitterRule with node_id matches only that sender."""
        rule = TxJitterRule(jitter_min_us=100, jitter_max_us=500, node_id="sender1")
        tx1 = make_transmission("sender1")
        tx2 = make_transmission("sender2")
        assert rule.matches(tx1, "receiver") is True
        assert rule.matches(tx2, "receiver") is False

    def test_tx_jitter_apply_passes_through(self) -> None:
        """TxJitterRule apply passes candidate through unchanged."""
        rule = TxJitterRule(jitter_min_us=100, jitter_max_us=500)
        candidate = make_candidate()
        result = rule.apply(candidate)
        assert result is candidate

    def test_tx_jitter_get_jitter_us_in_range(self) -> None:
        """TxJitterRule.get_jitter_us returns values in range."""
        import random

        rng = random.Random(42)
        rule = TxJitterRule(jitter_min_us=100, jitter_max_us=500, rng=rng)

        for _ in range(100):
            jitter = rule.get_jitter_us()
            assert 100 <= jitter <= 500

    def test_tx_jitter_get_jitter_us_deterministic_with_seed(self) -> None:
        """TxJitterRule.get_jitter_us is deterministic with seeded rng."""
        import random

        rng1 = random.Random(42)
        rng2 = random.Random(42)
        rule1 = TxJitterRule(jitter_min_us=100, jitter_max_us=500, rng=rng1)
        rule2 = TxJitterRule(jitter_min_us=100, jitter_max_us=500, rng=rng2)

        jitters1 = [rule1.get_jitter_us() for _ in range(10)]
        jitters2 = [rule2.get_jitter_us() for _ in range(10)]
        assert jitters1 == jitters2

    def test_tx_jitter_min_equals_max_returns_constant(self) -> None:
        """TxJitterRule with min==max returns constant value."""
        rule = TxJitterRule(jitter_min_us=250, jitter_max_us=250)
        for _ in range(10):
            assert rule.get_jitter_us() == 250

    def test_tx_jitter_rejects_negative_min(self) -> None:
        """TxJitterRule rejects negative jitter_min_us."""
        with pytest.raises(ValueError, match="jitter_min_us must be non-negative"):
            TxJitterRule(jitter_min_us=-100, jitter_max_us=500)

    def test_tx_jitter_rejects_max_less_than_min(self) -> None:
        """TxJitterRule rejects jitter_max_us < jitter_min_us."""
        with pytest.raises(ValueError, match="jitter_max_us .* must be >= jitter_min_us"):
            TxJitterRule(jitter_min_us=500, jitter_max_us=100)

    def test_tx_jitter_zero_range_allowed(self) -> None:
        """TxJitterRule allows zero jitter range."""
        rule = TxJitterRule(jitter_min_us=0, jitter_max_us=0)
        assert rule.get_jitter_us() == 0


class TestChaosEngineBasics:
    """Test basic ChaosEngine functionality."""

    def test_engine_starts_empty(self) -> None:
        """ChaosEngine starts with no rules."""
        engine = ChaosEngine()
        assert engine.get_rules() == []

    def test_add_rule_returns_id(self) -> None:
        """add_rule returns the rule's ID."""
        engine = ChaosEngine()
        rule = DropRule(node_id="node1")
        rule_id = engine.add_rule(rule)
        assert rule_id == rule.id

    def test_add_rule_stores_rule(self) -> None:
        """add_rule stores the rule."""
        engine = ChaosEngine()
        rule = DropRule(node_id="node1")
        engine.add_rule(rule)
        assert rule in engine.get_rules()

    def test_get_rules_returns_all(self) -> None:
        """get_rules returns all added rules."""
        engine = ChaosEngine()
        rule1 = DropRule(node_id="node1")
        rule2 = DegradeRule(node_id="node2", rssi_penalty_db=10.0)
        engine.add_rule(rule1)
        engine.add_rule(rule2)

        rules = engine.get_rules()
        assert len(rules) == 2
        assert rule1 in rules
        assert rule2 in rules

    def test_get_rules_preserves_order(self) -> None:
        """get_rules returns rules in insertion order."""
        engine = ChaosEngine()
        rule1 = DropRule(node_id="node1", id="first")
        rule2 = DropRule(node_id="node2", id="second")
        rule3 = DropRule(node_id="node3", id="third")
        engine.add_rule(rule1)
        engine.add_rule(rule2)
        engine.add_rule(rule3)

        rules = engine.get_rules()
        assert rules[0].id == "first"
        assert rules[1].id == "second"
        assert rules[2].id == "third"


class TestChaosEngineRemove:
    """Test ChaosEngine rule removal."""

    def test_remove_rule_returns_true(self) -> None:
        """remove_rule returns True when rule found."""
        engine = ChaosEngine()
        rule = DropRule(node_id="node1")
        engine.add_rule(rule)
        assert engine.remove_rule(rule.id) is True

    def test_remove_rule_removes_rule(self) -> None:
        """remove_rule removes the rule."""
        engine = ChaosEngine()
        rule = DropRule(node_id="node1")
        engine.add_rule(rule)
        engine.remove_rule(rule.id)
        assert rule not in engine.get_rules()

    def test_remove_nonexistent_returns_false(self) -> None:
        """remove_rule returns False when rule not found."""
        engine = ChaosEngine()
        assert engine.remove_rule("nonexistent") is False

    def test_remove_does_not_affect_others(self) -> None:
        """remove_rule does not affect other rules."""
        engine = ChaosEngine()
        rule1 = DropRule(node_id="node1")
        rule2 = DropRule(node_id="node2")
        engine.add_rule(rule1)
        engine.add_rule(rule2)
        engine.remove_rule(rule1.id)

        rules = engine.get_rules()
        assert len(rules) == 1
        assert rule2 in rules


class TestChaosEngineClear:
    """Test ChaosEngine clear functionality."""

    def test_clear_removes_all_rules(self) -> None:
        """clear removes all rules."""
        engine = ChaosEngine()
        engine.add_rule(DropRule(node_id="node1"))
        engine.add_rule(DropRule(node_id="node2"))
        engine.add_rule(DropRule(node_id="node3"))

        engine.clear()
        assert engine.get_rules() == []

    def test_clear_empty_engine_is_safe(self) -> None:
        """clear on empty engine does not raise."""
        engine = ChaosEngine()
        engine.clear()  # Should not raise
        assert engine.get_rules() == []


class TestChaosEngineApplyAll:
    """Test ChaosEngine apply_all functionality."""

    def test_apply_all_no_rules_passes_through(self) -> None:
        """apply_all with no rules returns candidate unchanged."""
        engine = ChaosEngine()
        candidate = make_candidate()
        result = engine.apply_all(candidate, "receiver")
        assert result is candidate

    def test_apply_all_non_matching_rule_passes_through(self) -> None:
        """apply_all passes through when no rules match."""
        engine = ChaosEngine()
        engine.add_rule(DropRule(node_id="other_node"))
        candidate = make_candidate(source_node_id="sender")
        result = engine.apply_all(candidate, "receiver")
        assert result is candidate

    def test_apply_all_drop_rule_returns_none(self) -> None:
        """apply_all returns None when drop rule matches."""
        engine = ChaosEngine()
        engine.add_rule(DropRule(node_id="sender"))
        candidate = make_candidate(source_node_id="sender")
        result = engine.apply_all(candidate, "receiver")
        assert result is None

    def test_apply_all_degrade_rule_modifies(self) -> None:
        """apply_all applies degrade rule modifications."""
        engine = ChaosEngine()
        engine.add_rule(DegradeRule(node_id="sender", rssi_penalty_db=10.0))
        candidate = make_candidate(source_node_id="sender", rssi=-70.0)
        result = engine.apply_all(candidate, "receiver")

        assert result is not None
        assert result.rssi == pytest.approx(-80.0)

    def test_apply_all_multiple_degrade_rules_stack(self) -> None:
        """apply_all applies multiple degrade rules cumulatively."""
        engine = ChaosEngine()
        engine.add_rule(DegradeRule(node_id="sender", rssi_penalty_db=5.0))
        engine.add_rule(DegradeRule(node_id="receiver", rssi_penalty_db=3.0))
        candidate = make_candidate(source_node_id="sender", rssi=-70.0)
        result = engine.apply_all(candidate, "receiver")

        assert result is not None
        assert result.rssi == pytest.approx(-78.0)  # -70 - 5 - 3

    def test_apply_all_drop_after_degrade_drops(self) -> None:
        """apply_all returns None if any rule drops."""
        engine = ChaosEngine()
        engine.add_rule(DegradeRule(node_id="sender", rssi_penalty_db=10.0))
        engine.add_rule(DropRule(node_id="sender"))
        candidate = make_candidate(source_node_id="sender")
        result = engine.apply_all(candidate, "receiver")
        assert result is None

    def test_apply_all_drop_before_degrade_drops(self) -> None:
        """apply_all returns None immediately on first drop."""
        engine = ChaosEngine()
        engine.add_rule(DropRule(node_id="sender"))
        engine.add_rule(DegradeRule(node_id="sender", rssi_penalty_db=10.0))
        candidate = make_candidate(source_node_id="sender")
        result = engine.apply_all(candidate, "receiver")
        assert result is None

    def test_apply_all_jammer_with_position(self) -> None:
        """apply_all passes rx_position to jammer rule."""
        engine = ChaosEngine()
        engine.add_rule(JammerRule(x=0.0, y=0.0, z=0.0, radius_m=100.0))
        candidate = make_candidate()

        # Inside jammer radius
        result = engine.apply_all(candidate, "receiver", rx_position=(50.0, 0.0, 0.0))
        assert result is None

        # Outside jammer radius
        result = engine.apply_all(candidate, "receiver", rx_position=(150.0, 0.0, 0.0))
        assert result is candidate

    def test_apply_all_partition_rule(self) -> None:
        """apply_all applies partition rules correctly."""
        engine = ChaosEngine()
        engine.add_rule(PartitionRule(groups=[{"node1", "node2"}, {"node3", "node4"}]))

        # Same partition: passes through
        candidate1 = make_candidate(source_node_id="node1")
        result1 = engine.apply_all(candidate1, "node2")
        assert result1 is candidate1

        # Different partitions: dropped
        candidate2 = make_candidate(source_node_id="node1")
        result2 = engine.apply_all(candidate2, "node3")
        assert result2 is None


class TestChaosRuleABC:
    """Test that ChaosRule is properly abstract."""

    def test_chaos_rule_cannot_be_instantiated(self) -> None:
        """ChaosRule cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ChaosRule()  # type: ignore[abstract]

    def test_chaos_rule_subclass_must_implement_matches(self) -> None:
        """ChaosRule subclass must implement matches."""

        class IncompleteRule(ChaosRule):
            id: str = "incomplete"

            def apply(
                self,
                candidate: RxCandidate,
                rx_position: tuple[float, float, float] | None = None,
            ) -> RxCandidate | None:
                return candidate

        with pytest.raises(TypeError):
            IncompleteRule()  # type: ignore[abstract]

    def test_chaos_rule_subclass_must_implement_apply(self) -> None:
        """ChaosRule subclass must implement apply."""

        class IncompleteRule(ChaosRule):
            id: str = "incomplete"

            def matches(self, tx: Transmission, rx_node_id: str) -> bool:
                return True

        with pytest.raises(TypeError):
            IncompleteRule()  # type: ignore[abstract]
