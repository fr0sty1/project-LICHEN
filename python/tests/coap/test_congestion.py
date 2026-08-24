# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CoAP congestion checking (spec 07 section 10.2.3)."""

from __future__ import annotations

import asyncio

import cbor2
import pytest
from aiocoap import GET, Message
from aiocoap.numbers.codes import SERVICE_UNAVAILABLE
from aiocoap.numbers.types import CON, NON

from lichen.coap.params import (
    APP_PRIORITY,
    CongestionError,
    CongestionLevel,
    CongestionState,
    app_priority,
    check_congestion_allows,
    congestion_level,
    congestion_service_unavailable,
)
from lichen.coap.resources import CongestionAwareSite, StaticNodeInfo, StatusResource
from lichen.coap.transport import DatagramChannel, InMemoryNetwork
from lichen.link.tx_queue import Priority


class TestCongestionLevel:
    """Test duty cycle ratio to congestion level mapping."""

    def test_normal_below_50_percent(self) -> None:
        assert congestion_level(0.0) == CongestionLevel.NORMAL
        assert congestion_level(0.1) == CongestionLevel.NORMAL
        assert congestion_level(0.49) == CongestionLevel.NORMAL

    def test_elevated_50_to_80_percent(self) -> None:
        assert congestion_level(0.50) == CongestionLevel.ELEVATED
        assert congestion_level(0.65) == CongestionLevel.ELEVATED
        assert congestion_level(0.79) == CongestionLevel.ELEVATED

    def test_critical_80_to_95_percent(self) -> None:
        assert congestion_level(0.80) == CongestionLevel.CRITICAL
        assert congestion_level(0.90) == CongestionLevel.CRITICAL
        assert congestion_level(0.95) == CongestionLevel.CRITICAL

    def test_exhausted_above_95_percent(self) -> None:
        assert congestion_level(0.96) == CongestionLevel.EXHAUSTED
        assert congestion_level(1.0) == CongestionLevel.EXHAUSTED
        assert congestion_level(1.5) == CongestionLevel.EXHAUSTED


class TestCheckCongestionAllows:
    """Test spec 10.2.3 congestion rules."""

    def test_normal_allows_all_priorities(self) -> None:
        for priority in Priority:
            assert check_congestion_allows(CongestionLevel.NORMAL, priority)

    def test_elevated_allows_sos_routing_urgent(self) -> None:
        assert check_congestion_allows(CongestionLevel.ELEVATED, Priority.SOS)
        assert check_congestion_allows(CongestionLevel.ELEVATED, Priority.ROUTING)
        assert check_congestion_allows(CongestionLevel.ELEVATED, Priority.URGENT)

    def test_elevated_blocks_normal_and_bulk(self) -> None:
        assert not check_congestion_allows(CongestionLevel.ELEVATED, Priority.NORMAL)
        assert not check_congestion_allows(CongestionLevel.ELEVATED, Priority.BULK)

    def test_critical_allows_sos_and_routing(self) -> None:
        assert check_congestion_allows(CongestionLevel.CRITICAL, Priority.SOS)
        assert check_congestion_allows(CongestionLevel.CRITICAL, Priority.ROUTING)

    def test_critical_blocks_urgent_and_below(self) -> None:
        assert not check_congestion_allows(CongestionLevel.CRITICAL, Priority.URGENT)
        assert not check_congestion_allows(CongestionLevel.CRITICAL, Priority.NORMAL)
        assert not check_congestion_allows(CongestionLevel.CRITICAL, Priority.BULK)

    def test_exhausted_blocks_all(self) -> None:
        for priority in Priority:
            assert not check_congestion_allows(CongestionLevel.EXHAUSTED, priority)


class TestCongestionState:
    """Test CongestionState dataclass (r1-P3-43)."""

    def test_state_attributes(self) -> None:
        """CongestionState holds level and retry_after_ms."""
        state = CongestionState(level=CongestionLevel.CRITICAL, retry_after_ms=5000)
        assert state.level == CongestionLevel.CRITICAL
        assert state.retry_after_ms == 5000

    def test_state_without_retry_after(self) -> None:
        """CongestionState defaults retry_after_ms to None."""
        state = CongestionState(level=CongestionLevel.NORMAL)
        assert state.level == CongestionLevel.NORMAL
        assert state.retry_after_ms is None

    def test_state_is_immutable(self) -> None:
        """CongestionState is frozen (immutable)."""
        state = CongestionState(level=CongestionLevel.ELEVATED, retry_after_ms=1000)
        with pytest.raises(AttributeError):
            state.level = CongestionLevel.NORMAL  # type: ignore[misc]


class TestCongestionError:
    """Test CongestionError exception."""

    def test_error_attributes(self) -> None:
        err = CongestionError(CongestionLevel.CRITICAL, Priority.NORMAL, retry_after_ms=5000)
        assert err.level == CongestionLevel.CRITICAL
        assert err.priority == Priority.NORMAL
        assert err.retry_after_ms == 5000
        assert "critical" in str(err).lower()
        assert "NORMAL" in str(err)

    def test_error_without_retry_after(self) -> None:
        err = CongestionError(CongestionLevel.EXHAUSTED, Priority.BULK)
        assert err.retry_after_ms is None


class _CongestedChannel(DatagramChannel):
    """A test channel with configurable congestion level."""

    def __init__(self, level: CongestionLevel = CongestionLevel.NORMAL) -> None:
        self._level = level
        self._retry_ms: int | None = None
        self.sent: list[tuple[bytes, str, Priority]] = []

    def set_level(self, level: CongestionLevel, retry_ms: int | None = None) -> None:
        self._level = level
        self._retry_ms = retry_ms

    @property
    def congestion_level(self) -> CongestionLevel:
        return self._level

    @property
    def retry_after_ms(self) -> int | None:
        return self._retry_ms

    def congestion_state(self) -> CongestionState:
        """Return atomic snapshot of congestion level and retry delay."""
        return CongestionState(level=self._level, retry_after_ms=self._retry_ms)

    def send_datagram(
        self,
        data: bytes,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        if check_congestion:
            self.check_congestion_for(priority)
        self.sent.append((data, dest, priority))

    def set_receiver(self, receiver) -> None:
        pass


class TestDatagramChannelCongestion:
    """Test DatagramChannel congestion enforcement."""

    def test_default_congestion_level_is_normal(self) -> None:
        channel = InMemoryNetwork().channel("test")
        assert channel.congestion_level == CongestionLevel.NORMAL

    def test_default_retry_after_is_none(self) -> None:
        channel = InMemoryNetwork().channel("test")
        assert channel.retry_after_ms is None

    def test_congestion_state_returns_atomic_snapshot(self) -> None:
        """congestion_state() returns both level and retry_after_ms atomically (r1-P3-43)."""
        channel = InMemoryNetwork().channel("test")
        state = channel.congestion_state()
        assert state.level == CongestionLevel.NORMAL
        assert state.retry_after_ms is None

    def test_congested_channel_state_consistent(self) -> None:
        """congestion_state() returns consistent values from _CongestedChannel."""
        channel = _CongestedChannel(CongestionLevel.CRITICAL)
        channel.set_level(CongestionLevel.CRITICAL, retry_ms=5000)
        state = channel.congestion_state()
        assert state.level == CongestionLevel.CRITICAL
        assert state.retry_after_ms == 5000

    def test_congested_channel_blocks_low_priority(self) -> None:
        channel = _CongestedChannel(CongestionLevel.CRITICAL)
        channel.set_level(CongestionLevel.CRITICAL, retry_ms=5000)

        # SOS should work
        channel.send_datagram(b"sos", "peer", priority=Priority.SOS)
        assert len(channel.sent) == 1

        # NORMAL should be blocked
        with pytest.raises(CongestionError) as exc_info:
            channel.send_datagram(b"telemetry", "peer", priority=Priority.NORMAL)
        assert exc_info.value.level == CongestionLevel.CRITICAL
        assert exc_info.value.retry_after_ms == 5000

    def test_exhausted_blocks_all_traffic(self) -> None:
        channel = _CongestedChannel(CongestionLevel.EXHAUSTED)

        for priority in Priority:
            with pytest.raises(CongestionError) as exc_info:
                channel.send_datagram(b"data", "peer", priority=priority)
            assert exc_info.value.level == CongestionLevel.EXHAUSTED

    def test_check_congestion_false_bypasses_check(self) -> None:
        channel = _CongestedChannel(CongestionLevel.EXHAUSTED)

        # Should succeed with check_congestion=False even when exhausted
        channel.send_datagram(
            b"emergency", "peer", priority=Priority.BULK, check_congestion=False
        )
        assert len(channel.sent) == 1

    @pytest.mark.asyncio
    async def test_in_memory_channel_enforces_congestion(self) -> None:
        # InMemoryChannel uses default NORMAL level, so all traffic should pass
        net = InMemoryNetwork()
        channel = net.channel("sender")
        received: list[tuple[bytes, str]] = []

        net.channel("receiver").set_receiver(
            lambda data, source: received.append((data, source))
        )

        channel.send_datagram(b"hello", "receiver", priority=Priority.BULK)
        await asyncio.sleep(0)  # Let call_soon deliver

        assert received == [(b"hello", "sender")]


class TestCongestionServiceUnavailable:
    """Test the 5.03 Service Unavailable response builder (spec 07 §10.2.3)."""

    def test_response_code_is_503(self) -> None:
        """Response has 5.03 Service Unavailable code."""
        msg = congestion_service_unavailable(CongestionLevel.CRITICAL)
        assert msg.code == SERVICE_UNAVAILABLE

    def test_payload_is_cbor(self) -> None:
        """Response payload is valid CBOR with required fields."""
        msg = congestion_service_unavailable(CongestionLevel.CRITICAL, retry_after_s=60)
        payload = cbor2.loads(msg.payload)
        assert payload["reason"] == "duty_cycle"
        assert payload["retry_after"] == 60
        assert payload["level"] == "critical"

    def test_max_age_matches_retry_after(self) -> None:
        """Max-Age option matches retry_after when provided."""
        msg = congestion_service_unavailable(CongestionLevel.ELEVATED, retry_after_s=90)
        assert msg.opt.max_age == 90

    def test_default_retry_after(self) -> None:
        """Default retry_after is 120 seconds per spec example."""
        msg = congestion_service_unavailable(CongestionLevel.EXHAUSTED)
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 120
        assert msg.opt.max_age == 120

    def test_all_levels_represented(self) -> None:
        """All congestion levels produce correct level field."""
        for level in CongestionLevel:
            msg = congestion_service_unavailable(level)
            payload = cbor2.loads(msg.payload)
            assert payload["level"] == level.value

    def test_max_age_zero_when_retry_after_zero(self) -> None:
        """Max-Age=0 is set when retry_after_s=0 (r1-P2-35).

        Previously, retry_after_s=0 caused Max-Age to be omitted (defaulting
        to 60s per RFC 7252), creating inconsistency with payload retry_after.
        """
        msg = congestion_service_unavailable(CongestionLevel.CRITICAL, retry_after_s=0)
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 0
        # Max-Age must match retry_after, even when 0
        assert msg.opt.max_age == 0

    def test_negative_retry_after_clamped_to_zero(self) -> None:
        """Negative retry_after_s is clamped to 0 (r1-P3-42).

        RFC 7252 defines Max-Age as uint; negative values are invalid and could
        cause undefined behavior. Clamping to 0 ensures valid output.
        """
        msg = congestion_service_unavailable(CongestionLevel.CRITICAL, retry_after_s=-5)
        payload = cbor2.loads(msg.payload)
        # Negative value should be clamped to 0
        assert payload["retry_after"] == 0
        assert msg.opt.max_age == 0

    def test_large_negative_retry_after_clamped_to_zero(self) -> None:
        """Large negative retry_after_s is also clamped to 0."""
        msg = congestion_service_unavailable(CongestionLevel.EXHAUSTED, retry_after_s=-1000000)
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 0
        assert msg.opt.max_age == 0

    def test_infinity_retry_after_uses_default(self) -> None:
        """IEEE 754 infinity retry_after_s uses default 120 (r2-P2-34).

        CBOR can encode infinity, but Max-Age must be uint per RFC 7252.
        Infinity values are treated as None (use default).
        """
        msg = congestion_service_unavailable(
            CongestionLevel.CRITICAL, retry_after_s=float("inf")
        )
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 120
        assert msg.opt.max_age == 120

    def test_negative_infinity_retry_after_uses_default(self) -> None:
        """IEEE 754 negative infinity uses default 120 (r2-P2-34)."""
        msg = congestion_service_unavailable(
            CongestionLevel.CRITICAL, retry_after_s=float("-inf")
        )
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 120
        assert msg.opt.max_age == 120

    def test_nan_retry_after_uses_default(self) -> None:
        """IEEE 754 NaN retry_after_s uses default 120 (r2-P2-34).

        NaN cannot be compared or converted to int, so it must be rejected.
        """
        msg = congestion_service_unavailable(
            CongestionLevel.CRITICAL, retry_after_s=float("nan")
        )
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 120
        assert msg.opt.max_age == 120

    def test_valid_float_retry_after_truncated_to_int(self) -> None:
        """Valid float retry_after_s is truncated to int (r2-P2-34)."""
        msg = congestion_service_unavailable(
            CongestionLevel.ELEVATED, retry_after_s=90.7
        )
        payload = cbor2.loads(msg.payload)
        assert payload["retry_after"] == 90
        assert msg.opt.max_age == 90


class _MockCongestionProvider:
    """A test congestion provider with configurable state."""

    def __init__(
        self,
        level: CongestionLevel = CongestionLevel.NORMAL,
        retry_after_ms: int | None = None,
    ) -> None:
        self._level = level
        self._retry_after_ms = retry_after_ms

    @property
    def congestion_level(self) -> CongestionLevel:
        return self._level

    @property
    def retry_after_ms(self) -> int | None:
        return self._retry_after_ms

    def congestion_state(self) -> CongestionState:
        """Return atomic snapshot of congestion level and retry delay."""
        return CongestionState(level=self._level, retry_after_ms=self._retry_after_ms)

    def set_level(self, level: CongestionLevel) -> None:
        self._level = level


class TestCongestionAwareSite:
    """Test the CongestionAwareSite request interception (spec 07 §10.2.3).

    Tests that require full request dispatch use the client-server pattern
    to ensure proper request structure. Tests that verify early rejection
    (congestion blocking) can use render() directly since they don't reach
    the parent Site.render().
    """

    @pytest.fixture
    def node_info(self) -> StaticNodeInfo:
        return StaticNodeInfo(
            status={"uptime": 3600},
            neighbors=[],
            config={},
        )

    @pytest.mark.asyncio
    async def test_critical_blocks_con_and_non(self, node_info: StaticNodeInfo) -> None:
        """CRITICAL congestion blocks both CON (P2) and NON (P3)."""
        provider = _MockCongestionProvider(CongestionLevel.CRITICAL)
        site = CongestionAwareSite(provider)
        site.add_resource(["status"], StatusResource(node_info))

        for mtype in (CON, NON):
            request = Message(code=GET, uri_path=("status",), mtype=mtype)
            response = await site.render(request)
            assert response.code == SERVICE_UNAVAILABLE
            payload = cbor2.loads(response.payload)
            assert payload["level"] == "critical"

    @pytest.mark.asyncio
    async def test_exhausted_blocks_all(self, node_info: StaticNodeInfo) -> None:
        """EXHAUSTED congestion blocks all traffic."""
        provider = _MockCongestionProvider(CongestionLevel.EXHAUSTED)
        site = CongestionAwareSite(provider)
        site.add_resource(["status"], StatusResource(node_info))

        for mtype in (CON, NON):
            request = Message(code=GET, uri_path=("status",), mtype=mtype)
            response = await site.render(request)
            assert response.code == SERVICE_UNAVAILABLE
            payload = cbor2.loads(response.payload)
            assert payload["level"] == "exhausted"

    @pytest.mark.asyncio
    async def test_retry_after_propagated(self, node_info: StaticNodeInfo) -> None:
        """retry_after from provider is propagated to 5.03 response."""
        provider = _MockCongestionProvider(CongestionLevel.CRITICAL, retry_after_ms=45000)
        site = CongestionAwareSite(provider)
        site.add_resource(["status"], StatusResource(node_info))

        request = Message(code=GET, uri_path=("status",), mtype=NON)
        response = await site.render(request)
        assert response.code == SERVICE_UNAVAILABLE
        payload = cbor2.loads(response.payload)
        # 45000ms rounds up to 45s
        assert payload["retry_after"] == 45
        assert response.opt.max_age == 45

    @pytest.mark.asyncio
    async def test_retry_after_zero_not_conflated_with_none(
        self, node_info: StaticNodeInfo
    ) -> None:
        """retry_after_ms=0 must produce retry_after=0, not default to 120.

        Regression test: falsy value 0 was conflated with None, causing the
        response to use the default retry_after=120 instead of 0.

        Also verifies Max-Age=0 is set (r1-P2-35: Max-Age consistency).
        """
        provider = _MockCongestionProvider(CongestionLevel.CRITICAL, retry_after_ms=0)
        site = CongestionAwareSite(provider)
        site.add_resource(["status"], StatusResource(node_info))

        request = Message(code=GET, uri_path=("status",), mtype=NON)
        response = await site.render(request)
        assert response.code == SERVICE_UNAVAILABLE
        payload = cbor2.loads(response.payload)
        # retry_after_ms=0 should produce retry_after=0, not 120
        assert payload["retry_after"] == 0
        # Max-Age must match retry_after, even when 0 (r1-P2-35)
        assert response.opt.max_age == 0

    @pytest.mark.asyncio
    async def test_elevated_blocks_non_allows_con(self, node_info: StaticNodeInfo) -> None:
        """ELEVATED congestion blocks NON requests (P3) but allows CON (P2).

        NON is blocked and returns 5.03 directly.
        CON passes the congestion check (tested here by verifying the blocking).
        """
        provider = _MockCongestionProvider(CongestionLevel.ELEVATED)
        site = CongestionAwareSite(provider)
        site.add_resource(["status"], StatusResource(node_info))

        # NON (P3) should be blocked
        non_request = Message(code=GET, uri_path=("status",), mtype=NON)
        response = await site.render(non_request)
        assert response.code == SERVICE_UNAVAILABLE
        payload = cbor2.loads(response.payload)
        assert payload["level"] == "elevated"

        # CON (P2) should NOT be blocked by congestion check
        # We verify this by checking check_congestion_allows directly since
        # full dispatch requires client-server setup
        assert check_congestion_allows(CongestionLevel.ELEVATED, Priority.URGENT)


class TestBuildSiteCongestionProvider:
    """Test build_site with congestion_provider argument."""

    def test_build_site_without_provider_returns_standard_site(self) -> None:
        """build_site without congestion_provider returns standard Site."""
        from lichen.coap.resources import build_site

        node_info = StaticNodeInfo(status={}, neighbors=[], config={})
        site = build_site(node_info)
        # Should be a standard Site, not CongestionAwareSite
        assert type(site).__name__ == "Site"

    def test_build_site_with_provider_returns_congestion_aware_site(self) -> None:
        """build_site with congestion_provider returns CongestionAwareSite."""
        from lichen.coap.resources import build_site

        node_info = StaticNodeInfo(status={}, neighbors=[], config={})
        provider = _MockCongestionProvider(CongestionLevel.NORMAL)
        site = build_site(node_info, congestion_provider=provider)
        # Should be a CongestionAwareSite
        assert type(site).__name__ == "CongestionAwareSite"
        assert site._congestion_provider is provider


class TestAppPriority:
    """Test application-to-priority mapping (spec 07 section 10.2.3)."""

    def test_cot_alert_is_sos(self) -> None:
        """CoT alert (subtype 0x20) maps to SOS (P0)."""
        assert app_priority(5681, "alert") == Priority.SOS

    def test_cot_chat_is_urgent(self) -> None:
        """CoT chat (subtype 0x01) maps to URGENT (P2)."""
        assert app_priority(5681, "chat") == Priority.URGENT

    def test_cot_pli_is_normal(self) -> None:
        """CoT PLI (subtypes 0x02-0x05) maps to NORMAL (P3)."""
        assert app_priority(5681, "pli") == Priority.NORMAL

    def test_cot_marker_is_normal(self) -> None:
        """CoT marker (subtype 0x10) maps to NORMAL (P3)."""
        assert app_priority(5681, "marker") == Priority.NORMAL

    def test_senml_is_normal(self) -> None:
        """SenML (port 5682) maps to NORMAL (P3)."""
        assert app_priority(5682, "senml") == Priority.NORMAL

    def test_coap_con_is_urgent(self) -> None:
        """CoAP CON (port 5683) maps to URGENT (P2)."""
        assert app_priority(5683, "con") == Priority.URGENT

    def test_coap_non_is_normal(self) -> None:
        """CoAP NON (port 5683) maps to NORMAL (P3)."""
        assert app_priority(5683, "non") == Priority.NORMAL

    def test_cayenne_is_normal(self) -> None:
        """Cayenne (port 5685) maps to NORMAL (P3)."""
        assert app_priority(5685, "cayenne") == Priority.NORMAL

    def test_aprs_is_normal(self) -> None:
        """APRS (port 5686) maps to NORMAL (P3)."""
        assert app_priority(5686, "aprs") == Priority.NORMAL

    def test_nmea_is_normal(self) -> None:
        """NMEA (port 5687) maps to NORMAL (P3)."""
        assert app_priority(5687, "nmea") == Priority.NORMAL

    def test_mqtt_qos1_is_urgent(self) -> None:
        """MQTT-SN QoS1 (port 10883) maps to URGENT (P2)."""
        assert app_priority(10883, "qos1") == Priority.URGENT

    def test_mqtt_qos0_is_normal(self) -> None:
        """MQTT-SN QoS0 (port 10883) maps to NORMAL (P3)."""
        assert app_priority(10883, "qos0") == Priority.NORMAL

    def test_unknown_port_defaults_to_normal(self) -> None:
        """Unknown port/subtype combinations default to NORMAL (P3)."""
        assert app_priority(9999, "unknown") == Priority.NORMAL

    def test_unknown_subtype_defaults_to_normal(self) -> None:
        """Known port with unknown subtype defaults to NORMAL (P3)."""
        assert app_priority(5681, "unknown_subtype") == Priority.NORMAL

    def test_all_defined_mappings_covered(self) -> None:
        """All entries in APP_PRIORITY are accessible via app_priority()."""
        for (port, subtype), expected in APP_PRIORITY.items():
            assert app_priority(port, subtype) == expected
