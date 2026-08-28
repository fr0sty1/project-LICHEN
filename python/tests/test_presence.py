# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Domain tests for presence/status (spec 18.5).

Encoding oracles are the committed hex strings in
``test/vectors/presence_cbor.json``. Automatic-status oracles are the
condition table in spec/12-apps.md 18.5.3.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.presence import (
    AWAY_AFTER_S,
    LOW_BATTERY_PCT,
    MAX_CACHE_ENTRIES,
    MAX_MSG_LEN,
    STATIONARY_AFTER_S,
    Presence,
    PresenceCache,
    PresenceError,
    age_s_at,
    apply_automatic_status,
)

VECTORS_PATH = Path(__file__).parents[2] / "test" / "vectors" / "presence_cbor.json"
_T0 = 1_716_742_800


def _load_vectors() -> list[dict]:
    with open(VECTORS_PATH) as f:
        return json.load(f)["vectors"]


def _parse_vector(vector: dict) -> Presence | PresenceCache:
    if "cache" in vector["name"]:
        return PresenceCache.from_mapping(vector["input"])
    return Presence.from_mapping(vector["input"])


class TestPresenceCodec:
    def test_vectors_encode_to_committed_hex(self) -> None:
        for vector in _load_vectors():
            encoded = _parse_vector(vector).to_cbor()
            assert encoded.hex() == vector["encoded_hex"], vector["name"]

    def test_vectors_decode_to_input_map(self) -> None:
        for vector in _load_vectors():
            raw = bytes.fromhex(vector["encoded_hex"])
            if "cache" in vector["name"]:
                decoded = PresenceCache.from_cbor(raw)
            else:
                decoded = Presence.from_cbor(raw)
            assert decoded.to_map() == vector["input"], vector["name"]

    def test_round_trip_all_fields(self) -> None:
        original = Presence(
            status="available",
            ts=_T0,
            activity="moving",
            msg="On patrol",
            battery=87,
        )
        assert Presence.from_cbor(original.to_cbor()) == original

    def test_omits_unset_optional_fields(self) -> None:
        document = Presence(status="available", ts=_T0).to_map()
        assert set(document) == {"status", "ts"}

    def test_rejects_unknown_status(self) -> None:
        with pytest.raises(PresenceError, match="status"):
            Presence.from_mapping({"status": "invisible", "ts": _T0})

    def test_rejects_unknown_activity(self) -> None:
        with pytest.raises(PresenceError, match="activity"):
            Presence.from_mapping({"status": "available", "activity": "running", "ts": _T0})

    def test_rejects_battery_out_of_range(self) -> None:
        with pytest.raises(PresenceError, match="battery"):
            Presence.from_mapping({"status": "available", "battery": 101, "ts": _T0})
        with pytest.raises(PresenceError, match="battery"):
            Presence.from_mapping({"status": "available", "battery": -1, "ts": _T0})

    def test_rejects_bool_battery_and_ts(self) -> None:
        with pytest.raises(PresenceError, match="battery"):
            Presence.from_mapping({"status": "available", "battery": True, "ts": _T0})
        with pytest.raises(PresenceError, match="ts"):
            Presence.from_mapping({"status": "available", "ts": True})

    def test_rejects_unknown_field(self) -> None:
        with pytest.raises(PresenceError, match="unexpected"):
            Presence.from_mapping({"status": "available", "ts": _T0, "rank": 1})

    def test_rejects_msg_exceeding_max_length(self) -> None:
        # Exactly at limit should pass
        ok_msg = "a" * MAX_MSG_LEN
        p = Presence.from_mapping({"status": "available", "ts": _T0, "msg": ok_msg})
        assert p.msg == ok_msg
        # One byte over should fail
        too_long = "a" * (MAX_MSG_LEN + 1)
        with pytest.raises(PresenceError, match="msg exceeds"):
            Presence.from_mapping({"status": "available", "ts": _T0, "msg": too_long})

    def test_rejects_missing_status_or_ts(self) -> None:
        with pytest.raises(PresenceError, match="status"):
            Presence.from_mapping({"ts": _T0})
        with pytest.raises(PresenceError, match="ts"):
            Presence.from_mapping({"status": "available"})

    def test_rejects_non_bytes_payload(self) -> None:
        with pytest.raises(PresenceError, match="bytes"):
            Presence.from_cbor(bytearray(b"\xa0"))  # type: ignore[arg-type]

    def test_rejects_invalid_cbor(self) -> None:
        with pytest.raises(PresenceError, match="CBOR"):
            Presence.from_cbor(b"\xa1")


class TestPresenceCacheCodec:
    def test_small_mapping_parses(self) -> None:
        cache = PresenceCache.from_mapping(
            {"nodes": [{"addr": "0200::1", "status": "available", "age_s": 5}]}
        )
        assert len(cache.nodes) == 1
        assert cache.nodes[0].addr == "0200::1"
        assert cache.nodes[0].status == "available"
        assert cache.nodes[0].age_s == 5

    def test_rejects_oversized_nodes_array(self) -> None:
        # Exactly at limit should pass
        entry = {"addr": "0200::1", "status": "available", "age_s": 0}
        ok = PresenceCache.from_mapping({"nodes": [entry] * MAX_CACHE_ENTRIES})
        assert len(ok.nodes) == MAX_CACHE_ENTRIES
        # One entry over should fail
        with pytest.raises(PresenceError, match="exceeds maximum"):
            PresenceCache.from_mapping({"nodes": [entry] * (MAX_CACHE_ENTRIES + 1)})

    def test_rejects_non_list_nodes(self) -> None:
        with pytest.raises(PresenceError, match="nodes"):
            PresenceCache.from_mapping({"nodes": {}})

    def test_rejects_missing_entry_fields(self) -> None:
        with pytest.raises(PresenceError, match="addr"):
            PresenceCache.from_mapping({"nodes": [{"status": "available", "age_s": 1}]})

    def test_rejects_negative_age_s(self) -> None:
        with pytest.raises(PresenceError, match="age_s"):
            PresenceCache.from_mapping(
                {"nodes": [{"addr": "0200::1", "status": "available", "age_s": -1}]}
            )

    def test_rejects_non_bytes_payload(self) -> None:
        with pytest.raises(PresenceError, match="bytes"):
            PresenceCache.from_cbor(bytearray(b"\xa0"))  # type: ignore[arg-type]

    def test_rejects_invalid_cbor(self) -> None:
        with pytest.raises(PresenceError, match="CBOR"):
            PresenceCache.from_cbor(b"\xa1")


class TestAgeS:
    def test_positive_delta(self) -> None:
        assert age_s_at(_T0 + 45, _T0) == 45

    def test_clamps_negative_when_clock_goes_backwards(self) -> None:
        assert age_s_at(_T0 - 50, _T0) == 0

    def test_rejects_non_finite(self) -> None:
        with pytest.raises(PresenceError):
            age_s_at(float("nan"), _T0)


class TestAutomaticStatus:
    def _base(self) -> Presence:
        return Presence(status="busy", ts=_T0, activity="working", msg="In meeting", battery=50)

    def test_gps_motion_sets_available_moving(self) -> None:
        updated = apply_automatic_status(self._base(), _T0 + 1, moving=True)
        assert updated.status == "available"
        assert updated.activity == "moving"
        assert updated.ts == _T0 + 1

    def test_gps_stationary_after_five_minutes(self) -> None:
        updated = apply_automatic_status(
            self._base(),
            _T0 + STATIONARY_AFTER_S + 1,
            moving=False,
            last_motion_at=_T0,
        )
        assert updated.status == "available"
        assert updated.activity == "stationary"

    def test_gps_stationary_at_exactly_five_minutes_does_not_fire(self) -> None:
        updated = apply_automatic_status(
            self._base(),
            _T0 + STATIONARY_AFTER_S,
            moving=False,
            last_motion_at=_T0,
        )
        assert updated.status == "busy"
        assert updated.activity == "working"

    def test_inactivity_after_thirty_minutes_sets_away(self) -> None:
        updated = apply_automatic_status(
            self._base(),
            _T0 + AWAY_AFTER_S + 1,
            last_interaction_at=_T0,
        )
        assert updated.status == "away"
        assert updated.activity == "working"

    def test_motion_overrides_inactivity(self) -> None:
        updated = apply_automatic_status(
            self._base(),
            _T0 + AWAY_AFTER_S + 1,
            moving=True,
            last_interaction_at=_T0,
        )
        assert updated.status == "available"
        assert updated.activity == "moving"

    def test_sos_sets_emergency_and_wins_over_gps(self) -> None:
        updated = apply_automatic_status(
            self._base(),
            _T0 + 1,
            moving=True,
            sos_active=True,
        )
        assert updated.status == "emergency"
        assert updated.activity == "working"

    def test_low_battery_flag_when_below_ten(self) -> None:
        # Spec 18.5.3: low_battery must be True when battery < 10
        current = Presence(
            status="available", ts=_T0, battery=LOW_BATTERY_PCT - 1, low_battery=True
        )
        updated = apply_automatic_status(current, _T0)
        assert updated.status == "available"
        assert updated.battery == 9
        assert updated.low_battery is True

    def test_no_low_battery_flag_at_ten_percent(self) -> None:
        current = Presence(status="available", ts=_T0, battery=LOW_BATTERY_PCT)
        updated = apply_automatic_status(current, _T0)
        assert updated.low_battery is None
        assert updated == current

    def test_unchanged_document_keeps_ts(self) -> None:
        current = Presence(status="available", ts=_T0, battery=50)
        updated = apply_automatic_status(current, _T0 + 10)
        assert updated.ts == _T0
        assert updated is current
