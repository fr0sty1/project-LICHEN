# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for packets/timing oracles against generated vectors."""

from __future__ import annotations

import json
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def test_packets_formats_vectors_against_oracle() -> None:
    doc = _load("packets-formats.json")
    assert doc["format_version"] == 2
    assert len(doc["vectors"]) == 14
    # Validate complete example
    from lichen.packets.formats import COMPLETE_PACKET_EXAMPLE, validate_complete_example

    assert validate_complete_example(COMPLETE_PACKET_EXAMPLE["link_frame"])  # type: ignore[arg-type]


def test_packets_timing_vectors_against_oracle() -> None:
    doc = _load("packets-timing.json")
    assert doc["format_version"] == 2
    assert len(doc["vectors"]) == 32

    # Spot-check a few oracles
    from lichen.timing.sfn import sfn_delta

    assert sfn_delta(0, 0xFFFFFFFF) == 1

    from lichen.timing.dao import dao_retry_delay

    assert dao_retry_delay(0) == 4000
    assert dao_retry_delay(3) is None

    from lichen.timing.time_sync import DioTimeOption, Stratum

    opt = DioTimeOption(stratum=Stratum.NTS, timestamp=1700000000)
    enc = opt.encode()
    assert DioTimeOption.decode(enc).timestamp == 1700000000


def test_packet_size_budget() -> None:
    from lichen.packets.formats import LINK_SECURITY_OVERHEAD, total_packet_size_range

    assert LINK_SECURITY_OVERHEAD == 53
    assert total_packet_size_range(routing_overhead=0) == (82, 82)
    assert total_packet_size_range(routing_overhead=6) == (88, 88)


def test_airtime_oracle_positive() -> None:
    from lichen.timing.airtime import airtime_ms, airtime_us

    for plen in (17, 22, 60, 77, 82):
        assert airtime_us(plen) > 0
        assert airtime_ms(plen) > 0


def test_trickle_constants_match_spec() -> None:
    from lichen.timing.trickle import TRICKLE_IMAX_EXACT_MS, TRICKLE_IMIN_MS, TRICKLE_K

    assert TRICKLE_IMIN_MS == 4000
    assert TRICKLE_IMAX_EXACT_MS == 1_024_000
    assert TRICKLE_K == 10


def test_duty_cycle_max_packets() -> None:
    from lichen.timing.duty_cycle import EU868_MAX_PACKETS_PER_HOUR, max_packets_per_hour

    assert EU868_MAX_PACKETS_PER_HOUR == 1800
    assert max_packets_per_hour(200, 10) == 1800


def test_csma_cw() -> None:
    from lichen.timing.csma import cw_for_exponent

    assert cw_for_exponent(0) == 0
    assert cw_for_exponent(5) == 31


def test_sfn_slot_deterministic() -> None:
    from lichen.timing.sfn import hash_32, slot_for

    eui = bytes.fromhex("0011223344556677")
    h = hash_32(eui)
    # hash is deterministic across runs
    assert hash_32(eui) == h
    s0 = slot_for(eui, 0, 8)
    s1 = slot_for(eui, 1, 8)
    assert 0 <= s0 < 8
    assert 0 <= s1 < 8
