# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: no-silent-drops component vectors.

Covers the ForwardingBuffer, Router pending-queue, and ICMPv6
resource-exhausted vectors from ``test/vectors/no_silent_drops.json``
(the TxQueue component vectors live in tests/timing/test_tx_queue_vectors.py).
"""

from __future__ import annotations

import json
import logging
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.gradient import GradientTable
from lichen.ipv6.addr import IPv6Address as LicIPv6Address
from lichen.ipv6.icmpv6 import DestUnreachableCode, Icmpv6Type, make_resource_exhausted
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.link.forwarding_buffer import BufferResult, ForwardingBuffer
from lichen.routing.router import Router

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "no_silent_drops.json"


def _load() -> dict:
    return json.loads(_VECTORS_PATH.read_text())


def _by_name(name: str) -> dict:
    return next(v for v in _load()["vectors"] if v["name"] == name)


class TestForwardingBufferVectors:
    def test_backpressure_per_source(self) -> None:
        case = _by_name("forwarding_buffer_backpressure_per_source")
        scenario = case["scenario"]
        buf = ForwardingBuffer(max_sources=4, max_per_source=scenario["max_per_source"])
        src = bytes.fromhex(scenario["source_iid"])
        for i in range(scenario["initial_packets"]):
            assert buf.try_buffer(f"p{i}".encode(), src, 0, 10_000) is (BufferResult.ACCEPTED)
        result = buf.try_buffer(b"incoming", src, 1, 10_000)
        assert result is BufferResult.BACKPRESSURE, case["description"]
        assert buf.stats.packets_backpressure == case["expected"]["stats"]["packets_backpressure"]

    def test_eviction_logged_at_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        case = _by_name("forwarding_buffer_eviction_logged")
        scenario = case["scenario"]
        buf = ForwardingBuffer(
            max_sources=scenario["max_sources"],
            max_per_source=scenario["max_per_source"],
        )
        for iid in scenario["initial_sources"]:
            assert buf.try_buffer(b"data", bytes.fromhex(iid), 0, 10_000) is BufferResult.ACCEPTED
        with caplog.at_level(logging.WARNING):
            result = buf.try_buffer(
                b"incoming",
                bytes.fromhex(scenario["incoming"]["source_iid"]),
                1,
                10_000,
            )
        assert result is BufferResult.EVICTED, case["description"]
        assert buf.stats.packets_evicted == case["expected"]["stats"]["packets_evicted"]
        assert any(
            r.levelno == logging.WARNING and "evict" in r.message.lower() for r in caplog.records
        ), "eviction must be logged at WARNING (no silent drops)"


class TestIcmpv6ResourceExhausted:
    def test_nack_is_dest_unreachable_admin_prohibited(self) -> None:
        case = _by_name("icmpv6_resource_exhausted_nack")
        invoking = bytes.fromhex(case["scenario"]["invoking_packet_hex"])
        nack = make_resource_exhausted(invoking)
        expected = case["expected"]
        assert int(nack.type) == expected["type"] == int(Icmpv6Type.DEST_UNREACHABLE)
        assert nack.code == expected["code"] == int(DestUnreachableCode.ADMIN_PROHIBITED)


class TestRouterPendingQueue:
    def test_drop_oldest_logged_at_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        case = _by_name("pending_queue_drop_logged")
        scenario = case["scenario"]
        router = Router(
            node_address=LicIPv6Address("fd00::1"),
            gradient_table=GradientTable(),
            max_pending_per_dest=scenario["max_pending_per_dest"],
        )
        dst = IPv6Address(scenario["destination"])

        def packet(tag: bytes) -> IPv6Packet:
            return IPv6Packet(
                header=IPv6Header(
                    src_addr=LicIPv6Address("fd00::99"),
                    dst_addr=LicIPv6Address(scenario["destination"]),
                    next_header=17,
                ),
                payload=tag,
            )

        for i in range(scenario["initial_packets"]):
            router._queue_pending(packet(f"p{i}".encode()), dst, now_ms=i * 10)

        with caplog.at_level(logging.WARNING):
            router._queue_pending(packet(b"incoming"), dst, now_ms=999)

        queue = router.get_pending(dst)
        assert len(queue) == scenario["max_pending_per_dest"], case["description"]
        assert all(p.packet.payload != b"p0" for p in queue), "oldest dropped"
        assert any(
            r.levelno == logging.WARNING and "dropped oldest" in r.message.lower()
            for r in caplog.records
        ), "pending drop must be logged at WARNING (no silent drops)"
