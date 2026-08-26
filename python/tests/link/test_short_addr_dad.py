# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DAD message/state tests for short-address assignment."""

from __future__ import annotations

import json
import random
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

import pytest

from lichen.ipv6.icmpv6 import (
    ALL_NODES_MULTICAST,
    ND_HOP_LIMIT,
    Icmpv6Message,
    NeighborAdvertisement,
    NeighborSolicitation,
    handle_icmpv6,
    parse_dad_conflict,
)
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.link.short_addr import (
    DAD_JITTER_MAX_MS,
    DAD_MAX_SEED,
    SHORT_ADDR_MAX_INCREMENTAL,
    DadConflict,
    DadProbe,
    DadProbeSequence,
    dad_jitter_ms,
    dad_probe_schedule,
    dad_retry,
    dad_retry_incremental,
    derive_short_addr,
    derive_short_addr_with_seed,
    short_addr_dad_target,
)

VECTORS = Path(__file__).parents[3] / "test" / "vectors" / "short_addr_dad.json"


def _vector(name: str) -> dict[str, Any]:
    document = json.loads(VECTORS.read_text())
    return next(vector for vector in document["vectors"] if vector["name"] == name)


def test_canonical_dad_neighbor_exchange_vector() -> None:
    vector = _vector("dad_neighbor_exchange_short_1234")
    target = short_addr_dad_target(int(vector["short_addr"]))
    sequence = DadProbeSequence(
        bytes.fromhex(str(vector["eui64"])),
        int(vector["short_addr"]),
        tuple(vector["jitters_ms"]),
    )

    probe = sequence.next_probe().to_packet()
    assert str(target) == vector["target"]
    assert str(probe.header.src_addr) == vector["probe_source"]
    assert str(probe.header.dst_addr) == vector["probe_destination"]
    assert probe.header.hop_limit == vector["probe_hop_limit"]
    assert probe.payload.hex() == vector["probe_icmp_hex"]
    assert probe.to_bytes().hex() == vector["probe_ipv6_hex"]

    parsed_probe = IPv6Packet.from_bytes(bytes.fromhex(str(vector["probe_ipv6_hex"])), strict=True)
    solicitation = NeighborSolicitation.from_message(Icmpv6Message.from_bytes(parsed_probe.payload))
    assert solicitation.target == target

    conflict = handle_icmpv6(parsed_probe, local_addr=target)
    assert conflict is not None
    assert str(conflict.header.src_addr) == vector["conflict_source"]
    assert str(conflict.header.dst_addr) == vector["conflict_destination"]
    assert conflict.header.hop_limit == vector["conflict_hop_limit"]
    assert conflict.payload.hex() == vector["conflict_icmp_hex"]
    assert conflict.to_bytes().hex() == vector["conflict_ipv6_hex"]
    assert sequence.record_conflict(conflict)
    assert sequence.conflict_detected
    assert not sequence.succeeded
    assert not sequence.cancel()
    with pytest.raises(RuntimeError, match="after a conflict"):
        sequence.next_probe()
    with pytest.raises(RuntimeError, match="after a conflict"):
        sequence.finish()


def test_three_probe_state_accepts_boundary_jitters_and_completes() -> None:
    sequence = DadProbeSequence(
        bytes.fromhex("0011223344556677"),
        0x1234,
        (0, 250, 500),
    )
    probes = [sequence.next_probe() for _ in range(3)]
    assert [probe.jitter_ms for probe in probes] == [0, 250, 500]
    assert not sequence.succeeded
    assert sequence.finish()
    assert sequence.succeeded
    with pytest.raises(StopIteration, match="already complete"):
        sequence.next_probe()


@pytest.mark.parametrize(
    "jitters",
    [(), (1, 2), (1, 2, 3, 4), (-1, 2, 3), (1, 2, 501)],
)
def test_three_probe_state_rejects_invalid_jitter_inputs(jitters: tuple[int, ...]) -> None:
    with pytest.raises(ValueError, match="DAD requires exactly|jitter values"):
        DadProbeSequence(bytes.fromhex("0011223344556677"), 0x1234, jitters)


def test_randomized_three_probe_state_uses_injected_rng() -> None:
    sequence = DadProbeSequence.randomized(
        bytes.fromhex("0011223344556677"), 0x1234, random.Random(12345)
    )
    assert sequence.jitters_ms == (213, 375, 5)


def test_jitter_endpoint_vector_uses_full_unbiased_randrange() -> None:
    vector = _vector("dad_jitter_inclusive_endpoints")

    class ScriptedSource:
        def __init__(self, values: list[int]) -> None:
            self.values = iter(values)
            self.stops: list[int] = []

        def randrange(self, stop: int, /) -> int:
            self.stops.append(stop)
            return next(self.values)

    source = ScriptedSource(list(vector["source_values"]))
    assert dad_probe_schedule(rng=source) == vector["jitters_ms"]
    assert source.stops == [int(vector["randrange_stop"])] * int(vector["count"])
    assert int(vector["inclusive_min_ms"]) == 0
    assert int(vector["inclusive_max_ms"]) == DAD_JITTER_MAX_MS


@pytest.mark.parametrize("source_value", [-1, 501, True, 1.5])
def test_jitter_source_rejects_invalid_results(source_value: object) -> None:
    class InvalidSource:
        def randrange(self, stop: int, /) -> int:
            del stop
            return source_value  # type: ignore[return-value]

    error = TypeError if isinstance(source_value, (bool, float)) else ValueError
    with pytest.raises(error):
        dad_jitter_ms(InvalidSource())


def test_three_probe_state_cannot_finish_early() -> None:
    sequence = DadProbeSequence(bytes.fromhex("0011223344556677"), 0x1234, (0, 0, 0))
    sequence.next_probe()
    with pytest.raises(RuntimeError, match="before all three probes"):
        sequence.finish()


def test_three_probe_cancellation_vector_suppresses_remaining_probes() -> None:
    vector = _vector("dad_three_probe_cancellation")
    sequence = DadProbeSequence(
        bytes.fromhex(str(vector["eui64"])),
        int(vector["short_addr"]),
        tuple(vector["jitters_ms"]),
    )
    emitted = [sequence.next_probe() for _ in range(int(vector["cancel_after_probes"]))]
    assert [probe.jitter_ms for probe in emitted] == vector["emitted_jitters_ms"]
    assert sequence.cancel()
    assert sequence.cancelled is vector["cancelled"]
    assert sequence.completed is vector["completed"]
    assert sequence.succeeded is vector["succeeded"]
    assert len(vector["jitters_ms"]) - sequence.probes_sent == vector["remaining_suppressed"]
    assert not sequence.cancel()
    with pytest.raises(RuntimeError, match="cancelled"):
        sequence.next_probe()
    with pytest.raises(RuntimeError, match="cancelled"):
        sequence.finish()


def test_conflict_parser_rejects_solicited_or_unrelated_advertisement() -> None:
    target = short_addr_dad_target(0x1234)
    other_target = short_addr_dad_target(0x1235)
    source = target

    solicited = NeighborAdvertisement(target, solicited=True, override=True)
    solicited_packet = IPv6Packet(
        header=IPv6Header(
            source,
            ALL_NODES_MULTICAST,
            NextHeader.ICMPV6,
            hop_limit=ND_HOP_LIMIT,
        ),
        payload=solicited.to_message().to_bytes(source, ALL_NODES_MULTICAST),
    )
    assert parse_dad_conflict(solicited_packet, target) is None

    unrelated = NeighborAdvertisement(other_target, override=True)
    unrelated_packet = IPv6Packet(
        header=IPv6Header(
            source,
            ALL_NODES_MULTICAST,
            NextHeader.ICMPV6,
            hop_limit=ND_HOP_LIMIT,
        ),
        payload=unrelated.to_message().to_bytes(source, ALL_NODES_MULTICAST),
    )
    assert parse_dad_conflict(unrelated_packet, target) is None


def test_retry_reaches_seed_255_boundary_then_exhausts() -> None:
    eui64 = bytes.fromhex("0011223344556677")
    existing = {derive_short_addr(eui64)}
    existing.update(derive_short_addr_with_seed(eui64, seed) for seed in range(1, DAD_MAX_SEED))
    final_candidate = derive_short_addr_with_seed(eui64, DAD_MAX_SEED)
    assert final_candidate not in existing
    assert dad_retry(eui64, existing) == final_candidate
    existing.add(final_candidate)
    assert dad_retry(eui64, existing) is None


def test_incremental_retry_wrap_and_exhaustion_boundaries() -> None:
    assert dad_retry_incremental(SHORT_ADDR_MAX_INCREMENTAL, set()) == 1
    assert (
        dad_retry_incremental(
            0,
            set(range(1, SHORT_ADDR_MAX_INCREMENTAL + 1)),
        )
        is None
    )


def test_incremental_retry_repeated_collision_vector() -> None:
    vector = _vector("incremental_retry_repeated_collisions")
    current = int(vector["start"])
    existing = {current}
    actual: list[int] = []

    for collided in vector["collisions"]:
        candidate = dad_retry_incremental(current, existing)
        assert candidate is not None
        assert candidate == collided
        actual.append(candidate)
        existing.add(candidate)
        current = candidate

    final_candidate = dad_retry_incremental(current, existing)
    assert final_candidate is not None
    actual.append(final_candidate)
    assert actual == vector["results"]
    assert [f"0x{candidate:04x}" for candidate in actual] == vector["result_hex"]


def test_incremental_retry_reserved_boundary_vector() -> None:
    vector = _vector("incremental_retry_reserved_boundaries")
    usable = set(range(int(vector["usable_min"]), int(vector["usable_max"]) + 1))

    for case in vector["cases"]:
        if "only_free" in case:
            existing = usable - {int(case["only_free"])}
        else:
            existing = set(case["existing"])
        result = dad_retry_incremental(int(case["start"]), existing)
        assert result == case["result"], case["kind"]


def test_logical_dad_messages_validate_identity_and_address_boundaries() -> None:
    eui64 = bytes.fromhex("0011223344556677")
    other = bytes.fromhex("8899aabbccddeeff")
    assert DadProbe(eui64, 1, 0).target == IPv6Address("fe80::ff:fe00:1")
    assert DadConflict(1, eui64, other).short_addr == 1
    with pytest.raises(ValueError, match="distinct"):
        DadConflict(1, eui64, eui64)
    for reserved in (0, 0xFFFE, 0xFFFF):
        with pytest.raises(ValueError, match="invalid DAD short address"):
            DadProbe(eui64, reserved)
