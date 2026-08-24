# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SOS re-broadcast with TTL-limited deduplication."""

from __future__ import annotations

import pytest

from lichen.coap.sos_relay import (
    DEFAULT_INITIAL_TTL,
    DEFAULT_MAX_TTL,
    SEEN_EXPIRY_S,
    SEEN_MAX_SIZE,
    SosId,
    SosRelay,
    add_ttl_to_sos_payload,
    get_sos_id_from_payload,
    get_ttl_from_payload,
)

_VALID_NODE = "0102030405060708"
_T0 = 1_700_000_000.0


# ---------------------------------------------------------------------------
# SosId tests
# ---------------------------------------------------------------------------


class TestSosId:
    """Tests for SosId dataclass."""

    def test_valid_sos_id(self) -> None:
        """Valid node and seq should create SosId."""
        sos_id = SosId(node=_VALID_NODE, seq=1)
        assert sos_id.node == _VALID_NODE
        assert sos_id.seq == 1

    def test_sos_id_hashable(self) -> None:
        """SosId should be hashable for use as dict key."""
        sos_id = SosId(node=_VALID_NODE, seq=1)
        d = {sos_id: "value"}
        assert d[sos_id] == "value"

    def test_sos_id_equality(self) -> None:
        """Equal SosIds should be equal."""
        id1 = SosId(node=_VALID_NODE, seq=1)
        id2 = SosId(node=_VALID_NODE, seq=1)
        assert id1 == id2

    def test_sos_id_inequality_node(self) -> None:
        """Different nodes should not be equal."""
        id1 = SosId(node=_VALID_NODE, seq=1)
        id2 = SosId(node="0807060504030201", seq=1)
        assert id1 != id2

    def test_sos_id_inequality_seq(self) -> None:
        """Different seqs should not be equal."""
        id1 = SosId(node=_VALID_NODE, seq=1)
        id2 = SosId(node=_VALID_NODE, seq=2)
        assert id1 != id2

    def test_invalid_node_length(self) -> None:
        """Node with wrong length should raise ValueError."""
        with pytest.raises(ValueError, match="16-char hex string"):
            SosId(node="0102", seq=1)

    def test_invalid_node_type(self) -> None:
        """Non-string node should raise ValueError."""
        with pytest.raises(ValueError, match="16-char hex string"):
            SosId(node=12345, seq=1)  # type: ignore[arg-type]

    def test_negative_seq(self) -> None:
        """Negative seq should raise ValueError."""
        with pytest.raises(ValueError, match="non-negative int"):
            SosId(node=_VALID_NODE, seq=-1)

    def test_non_int_seq(self) -> None:
        """Non-int seq should raise ValueError."""
        with pytest.raises(ValueError, match="non-negative int"):
            SosId(node=_VALID_NODE, seq="1")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SosRelay deduplication tests
# ---------------------------------------------------------------------------


class TestSosRelayDeduplication:
    """Tests for SOS deduplication logic."""

    def test_first_sos_relayed(self) -> None:
        """First SOS from a node should be relayed."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.should_relay is True
        assert result.new_ttl == 4
        assert "relaying" in result.reason.lower()

    def test_duplicate_sos_not_relayed(self) -> None:
        """Same SOS ID should not be relayed twice."""
        relay = SosRelay()
        # First relay
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        # Second attempt - should be blocked
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.should_relay is False
        assert result.new_ttl is None
        assert "already relayed" in result.reason.lower()

    def test_different_seq_relayed(self) -> None:
        """Different seq from same node should be relayed."""
        relay = SosRelay()
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        result = relay.check_relay(node=_VALID_NODE, seq=2, ttl=5)
        assert result.should_relay is True
        assert result.new_ttl == 4

    def test_different_node_relayed(self) -> None:
        """Same seq from different node should be relayed."""
        relay = SosRelay()
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        result = relay.check_relay(node="0807060504030201", seq=1, ttl=5)
        assert result.should_relay is True
        assert result.new_ttl == 4

    def test_mark_seen_prevents_relay(self) -> None:
        """mark_seen() should prevent subsequent relay."""
        relay = SosRelay()
        relay.mark_seen(node=_VALID_NODE, seq=1)
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.should_relay is False
        assert "already relayed" in result.reason.lower()

    def test_is_seen_returns_true_for_seen(self) -> None:
        """is_seen() should return True for seen SOS IDs."""
        relay = SosRelay()
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert relay.is_seen(node=_VALID_NODE, seq=1) is True

    def test_is_seen_returns_false_for_unseen(self) -> None:
        """is_seen() should return False for unseen SOS IDs."""
        relay = SosRelay()
        assert relay.is_seen(node=_VALID_NODE, seq=1) is False

    def test_is_seen_returns_false_for_invalid_node(self) -> None:
        """is_seen() should return False for invalid node format."""
        relay = SosRelay()
        assert relay.is_seen(node="invalid", seq=1) is False

    def test_clear_removes_all_entries(self) -> None:
        """clear() should remove all seen entries."""
        relay = SosRelay()
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        relay.check_relay(node=_VALID_NODE, seq=2, ttl=5)
        count = relay.clear()
        assert count == 2
        assert len(relay) == 0
        # Can relay again after clear
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.should_relay is True


# ---------------------------------------------------------------------------
# SosRelay TTL tests
# ---------------------------------------------------------------------------


class TestSosRelayTtl:
    """Tests for SOS TTL handling."""

    def test_ttl_decremented(self) -> None:
        """TTL should be decremented by 1 on relay."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.new_ttl == 4

    def test_ttl_zero_not_relayed(self) -> None:
        """TTL=0 should not be relayed."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=0)
        assert result.should_relay is False
        assert result.new_ttl is None
        assert "ttl exhausted" in result.reason.lower()

    def test_ttl_negative_not_relayed(self) -> None:
        """Negative TTL should not be relayed."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=-1)
        assert result.should_relay is False
        assert "ttl exhausted" in result.reason.lower()

    def test_ttl_one_results_in_zero(self) -> None:
        """TTL=1 should result in new_ttl=0 (final hop)."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=1)
        assert result.should_relay is True
        assert result.new_ttl == 0

    def test_ttl_exceeds_max_clamped(self) -> None:
        """TTL exceeding max should be clamped."""
        relay = SosRelay(max_ttl=5)
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=100)
        assert result.should_relay is True
        assert result.new_ttl == 4  # Clamped to 5, then decremented

    def test_custom_max_ttl(self) -> None:
        """Custom max_ttl should be honored."""
        relay = SosRelay(max_ttl=3)
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=10)
        assert result.new_ttl == 2


# ---------------------------------------------------------------------------
# SosRelay expiry tests
# ---------------------------------------------------------------------------


class TestSosRelayExpiry:
    """Tests for SOS seen entry expiry."""

    def test_entries_expire_after_timeout(self) -> None:
        """Seen entries should expire after SEEN_EXPIRY_S."""
        current_time = [_T0]
        relay = SosRelay(time_func=lambda: current_time[0])
        # First relay
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert relay.is_seen(node=_VALID_NODE, seq=1) is True
        # Advance time past expiry
        current_time[0] = _T0 + SEEN_EXPIRY_S + 1
        # Entry should now be expired
        assert relay.is_seen(node=_VALID_NODE, seq=1) is False
        # Can relay again
        result = relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        assert result.should_relay is True

    def test_entries_not_expired_before_timeout(self) -> None:
        """Seen entries should not expire before SEEN_EXPIRY_S."""
        current_time = [_T0]
        relay = SosRelay(time_func=lambda: current_time[0])
        relay.check_relay(node=_VALID_NODE, seq=1, ttl=5)
        # Advance time but not past expiry
        current_time[0] = _T0 + SEEN_EXPIRY_S - 1
        # Entry should still be valid
        assert relay.is_seen(node=_VALID_NODE, seq=1) is True


# ---------------------------------------------------------------------------
# SosRelay capacity tests
# ---------------------------------------------------------------------------


class TestSosRelayCapacity:
    """Tests for SOS seen entry capacity limits."""

    def test_capacity_limit_enforced(self) -> None:
        """Oldest entries should be evicted when capacity is exceeded."""
        relay = SosRelay()
        # Fill up to capacity + 1
        for i in range(SEEN_MAX_SIZE + 1):
            node = f"{i:016x}"
            relay.check_relay(node=node, seq=1, ttl=5)
        # Should have evicted oldest half
        assert len(relay) <= SEEN_MAX_SIZE

    def test_lru_eviction_removes_oldest(self) -> None:
        """LRU eviction should remove oldest entries first."""
        relay = SosRelay()
        # Add entries
        for i in range(SEEN_MAX_SIZE + 10):
            node = f"{i:016x}"
            relay.check_relay(node=node, seq=1, ttl=5)
        # Newest entries should still be present
        newest = f"{SEEN_MAX_SIZE + 9:016x}"
        assert relay.is_seen(node=newest, seq=1) is True


# ---------------------------------------------------------------------------
# SosRelay validation tests
# ---------------------------------------------------------------------------


class TestSosRelayValidation:
    """Tests for SOS input validation."""

    def test_invalid_node_not_relayed(self) -> None:
        """Invalid node format should not be relayed."""
        relay = SosRelay()
        result = relay.check_relay(node="invalid", seq=1, ttl=5)
        assert result.should_relay is False
        assert "invalid node" in result.reason.lower()

    def test_invalid_seq_not_relayed(self) -> None:
        """Invalid seq should not be relayed."""
        relay = SosRelay()
        result = relay.check_relay(node=_VALID_NODE, seq=-1, ttl=5)
        assert result.should_relay is False
        assert "invalid seq" in result.reason.lower()


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestAddTtlToSosPayload:
    """Tests for add_ttl_to_sos_payload helper."""

    def test_adds_ttl_to_payload(self) -> None:
        """Should add TTL field to payload."""
        payload = {"type": "sos", "node": _VALID_NODE, "seq": 1}
        result = add_ttl_to_sos_payload(payload)
        assert result["ttl"] == DEFAULT_INITIAL_TTL
        assert result is payload  # Same object

    def test_custom_ttl(self) -> None:
        """Should use custom TTL value."""
        payload = {"type": "sos"}
        add_ttl_to_sos_payload(payload, ttl=3)
        assert payload["ttl"] == 3

    def test_overwrites_existing_ttl(self) -> None:
        """Should overwrite existing TTL."""
        payload = {"ttl": 10}
        add_ttl_to_sos_payload(payload, ttl=5)
        assert payload["ttl"] == 5


class TestGetSosIdFromPayload:
    """Tests for get_sos_id_from_payload helper."""

    def test_extracts_valid_sos_id(self) -> None:
        """Should extract (node, seq) from valid payload."""
        payload = {"node": _VALID_NODE, "seq": 1}
        result = get_sos_id_from_payload(payload)
        assert result == (_VALID_NODE, 1)

    def test_returns_none_for_missing_node(self) -> None:
        """Should return None if node is missing."""
        payload = {"seq": 1}
        assert get_sos_id_from_payload(payload) is None

    def test_returns_none_for_missing_seq(self) -> None:
        """Should return None if seq is missing."""
        payload = {"node": _VALID_NODE}
        assert get_sos_id_from_payload(payload) is None

    def test_returns_none_for_invalid_node_length(self) -> None:
        """Should return None if node has wrong length."""
        payload = {"node": "0102", "seq": 1}
        assert get_sos_id_from_payload(payload) is None

    def test_returns_none_for_non_string_node(self) -> None:
        """Should return None if node is not a string."""
        payload = {"node": 12345, "seq": 1}
        assert get_sos_id_from_payload(payload) is None

    def test_returns_none_for_negative_seq(self) -> None:
        """Should return None if seq is negative."""
        payload = {"node": _VALID_NODE, "seq": -1}
        assert get_sos_id_from_payload(payload) is None

    def test_returns_none_for_non_int_seq(self) -> None:
        """Should return None if seq is not an int."""
        payload = {"node": _VALID_NODE, "seq": "1"}
        assert get_sos_id_from_payload(payload) is None


class TestGetTtlFromPayload:
    """Tests for get_ttl_from_payload helper."""

    def test_extracts_ttl(self) -> None:
        """Should extract TTL from payload."""
        payload = {"ttl": 5}
        assert get_ttl_from_payload(payload) == 5

    def test_returns_default_if_missing(self) -> None:
        """Should return default if TTL is missing."""
        payload = {}
        assert get_ttl_from_payload(payload) == DEFAULT_INITIAL_TTL

    def test_custom_default(self) -> None:
        """Should use custom default."""
        payload = {}
        assert get_ttl_from_payload(payload, default=3) == 3

    def test_clamps_negative_to_zero(self) -> None:
        """Should clamp negative TTL to 0."""
        payload = {"ttl": -5}
        assert get_ttl_from_payload(payload) == 0

    def test_returns_default_for_non_int_ttl(self) -> None:
        """Should return default if TTL is not an int."""
        payload = {"ttl": "not-an-int"}
        assert get_ttl_from_payload(payload) == DEFAULT_INITIAL_TTL

    def test_zero_ttl_preserved(self) -> None:
        """Should preserve TTL=0."""
        payload = {"ttl": 0}
        assert get_ttl_from_payload(payload) == 0


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for module constants."""

    def test_default_max_ttl_reasonable(self) -> None:
        """DEFAULT_MAX_TTL should be reasonable for mesh networks."""
        assert 1 <= DEFAULT_MAX_TTL <= 15

    def test_default_initial_ttl_equals_max(self) -> None:
        """DEFAULT_INITIAL_TTL should equal DEFAULT_MAX_TTL."""
        assert DEFAULT_INITIAL_TTL == DEFAULT_MAX_TTL

    def test_seen_expiry_is_4_hours(self) -> None:
        """SEEN_EXPIRY_S should be 4 hours per spec."""
        assert SEEN_EXPIRY_S == 4 * 3600

    def test_seen_max_size_reasonable(self) -> None:
        """SEEN_MAX_SIZE should be reasonable."""
        assert 64 <= SEEN_MAX_SIZE <= 1024
