# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the shared LCI client model."""

from __future__ import annotations

from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Any

import cbor2
import pytest

from lichen.client import (
    AiocoapResourceTransport,
    CoapResult,
    DeliveryState,
    IpCoapConfig,
    LciClient,
    LciClientError,
    LciSecurityError,
    MessageDraft,
    MessageReceipt,
    RawDiagnosticState,
    ReceiptStatus,
)
from lichen.client.lci import (
    _float_or_none,
    _int_or_none,
    normalize_message,
    parse_link_format,
)
from lichen.coap.resources import MessagesResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


class FakeSubscription:
    def __init__(self, results: list[CoapResult]) -> None:
        self._results = results
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    async def _results_iter(self) -> AsyncIterator[CoapResult]:
        for result in self._results:
            yield result

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results_iter()


class FakeResourceTransport:
    def __init__(self, responses: dict[tuple[str, str], CoapResult]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, bytes, int | None, bool]] = []
        self.observes: list[tuple[str, str]] = []
        self.subscriptions: dict[str, FakeSubscription] = {}
        self.connected = False

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        self.requests.append((method, path, payload, content_format, observe))
        return self.responses.get((method, path), CoapResult(code="4.04"))

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.connected = False

    async def observe(self, path: str, *, method: str = "GET") -> FakeSubscription:
        self.observes.append((method, path))
        subscription = self.subscriptions.get(path)
        if subscription is None:
            response = self.responses.get((method, path), CoapResult(code="4.04"))
            subscription = FakeSubscription([response])
            self.subscriptions[path] = subscription
        return subscription


class RecordingResourceTransport:
    def __init__(self, inner: AiocoapResourceTransport) -> None:
        self.inner = inner
        self.requests: list[tuple[str, str]] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        self.requests.append((method, path))
        return await self.inner.request(
            method,
            path,
            payload=payload,
            content_format=content_format,
            observe=observe,
        )

    async def connect(self) -> None:
        await self.inner.connect()

    async def close(self) -> None:
        await self.inner.close()

    async def observe(self, path: str, *, method: str = "GET") -> FakeSubscription:
        raise NotImplementedError


def test_parse_link_format_discovers_resources_observe_and_quoted_params() -> None:
    caps = parse_link_format(
        '</config>;rt="config",'
        '</status>;rt="status";obs,'
        '</status/neighbors>;rt="status neighbors";title="mesh;peers";obs,'
        '</logs>;rt="log";title="quoted \\", comma";obs'
    )

    assert caps.has("/config")
    assert caps.can_observe("/status")
    assert caps.can_observe("/status/neighbors")
    assert caps.can_observe("/logs")
    assert caps.resource_types["/status/neighbors"] == ("status", "neighbors")
    assert caps.resource_types["/logs"] == ("log",)


def test_parse_link_format_rejects_unclosed_quote() -> None:
    with pytest.raises(LciClientError, match="unclosed quote"):
        parse_link_format('</foo>;rt="bar')


async def test_lci_client_normalizes_core_resources() -> None:
    transport = FakeResourceTransport(
        {
            ("GET", "/status"): CoapResult(
                code="2.05",
                payload={
                    "uptime_s": 42,
                    "battery_pct": 87,
                    "battery_mv": 3950,
                    "dodag": {"joined": True},
                    "radio": {"rx_packets": 3},
                },
            ),
            ("GET", "/config"): CoapResult(
                code="2.05",
                payload={"name": "node-a", "role": "router", "radio": "/config/radio"},
            ),
            ("GET", "/config/radio"): CoapResult(
                code="2.05",
                payload={
                    "freq_mhz": 906.875,
                    "bw_khz": 125,
                    "sf": 10,
                    "cr": "4/5",
                    "tx_power_dbm": 17,
                    "sync_word": "0x34",
                },
            ),
            ("GET", "/config/identity"): CoapResult(
                code="2.05",
                payload={
                    "eui64": "0x0011223344556677",
                    "pubkey_fingerprint": "SHA256:abc",
                    "addrs": {"link_local": "fe80::1"},
                },
            ),
        }
    )
    client = LciClient(transport)

    await client.connect()
    status = await client.get_status()
    config = await client.get_config()
    radio = await client.get_radio_config()
    identity = await client.identify_node()
    await client.disconnect()

    assert transport.connected is False
    assert status.battery_pct == 87
    assert status.dodag == {"joined": True}
    assert config.name == "node-a"
    assert config.radio_path == "/config/radio"
    assert radio.freq_mhz == 906.875
    assert radio.tx_power_dbm == 17
    assert identity.eui64 == "0x0011223344556677"
    assert identity.addrs == {"link_local": "fe80::1"}


async def test_lci_client_preserves_error_details() -> None:
    transport = FakeResourceTransport(
        {("GET", "/status"): CoapResult(code="4.01", payload={"error": "locked"})}
    )
    client = LciClient(transport)

    with pytest.raises(LciClientError) as exc_info:
        await client.get_status()

    assert exc_info.value.method == "GET"
    assert exc_info.value.path == "/status"
    assert exc_info.value.code == "4.01"
    assert exc_info.value.payload == {"error": "locked"}


async def test_lci_client_lists_neighbors_routes_and_inbox() -> None:
    transport = FakeResourceTransport(
        {
            ("GET", "/status/neighbors"): CoapResult(
                code="2.05",
                payload={
                    "neighbors": [
                        {
                            "addr": "fe80::2",
                            "rssi_dbm": -80,
                            "snr_db": 7.5,
                            "etx": 1.2,
                            "last_seen_s": 30,
                            "trust": "tofu",
                        }
                    ]
                },
            ),
            ("GET", "/status/routes"): CoapResult(
                code="2.05",
                payload={
                    "routes": [
                        {
                            "prefix": "fd00::/64",
                            "via": "fe80::2",
                            "metric": 512,
                            "lifetime_s": 1800,
                        }
                    ],
                    "default_route": "fe80::2",
                },
            ),
            ("GET", "/msg/inbox"): CoapResult(
                code="2.05",
                payload={
                    "messages": [
                        {
                            "id": 17,
                            "from": "fd00::1",
                            "to": "fd00::2",
                            "body": "hello",
                            "received": "2026-05-26T14:35:00Z",
                        }
                    ]
                },
            ),
        }
    )
    client = LciClient(transport)

    neighbors = await client.list_neighbors()
    routes = await client.list_routes()
    messages = await client.inbox()

    assert neighbors[0].addr == "fe80::2"
    assert neighbors[0].rssi_dbm == -80
    assert neighbors[0].snr_db == 7.5
    assert neighbors[0].etx == 1.2
    assert neighbors[0].last_seen_s == 30
    assert neighbors[0].trust == "tofu"
    assert routes[0].prefix == "fd00::/64"
    assert routes[0].via == "fe80::2"
    assert routes[0].metric == 512
    assert routes[0].lifetime_s == 1800
    assert messages[0].message_id == 17
    assert messages[0].body == "hello"


async def test_send_message_uses_discovered_payload_shape() -> None:
    transport = FakeResourceTransport(
        {
            ("POST", "/msg/inbox"): CoapResult(
                code="2.01",
                location_path=("msg", "sent", "42"),
            )
        }
    )
    client = LciClient(transport)

    result = await client.send_message(MessageDraft(to="fd00::2", body="hello", ack=True))

    assert result.state is DeliveryState.ACCEPTED
    assert result.location_path == ("msg", "sent", "42")
    method, path, payload, content_format, observe = transport.requests[-1]
    assert (method, path, content_format, observe) == ("POST", "/msg/inbox", 60, False)
    assert cbor2.loads(payload) == {"to": "fd00::2", "body": "hello", "ack": True}


async def test_share_waypoint_posts_cbor_directly_to_unicast_peer() -> None:
    peer_uri = "coap://[200::2222]/waypoints"
    transport = FakeResourceTransport(
        {
            ("POST", peer_uri): CoapResult(
                code="2.01",
                location_path=("waypoints", "wpt-003"),
            )
        }
    )
    client = LciClient(transport)
    waypoint = {
        "name": "Rally Point Alpha",
        "lat": 37.774929,
        "lon": -122.419416,
        "notes": "Meet here at 1400",
        "creator": "0200::1111",
    }

    result = await client.share_waypoint("0200::2222", waypoint)

    assert result.state is DeliveryState.ACCEPTED
    assert result.coap_code == "2.01"
    assert result.location_path == ("waypoints", "wpt-003")
    method, path, payload, content_format, observe = transport.requests[-1]
    assert (method, path, content_format, observe) == ("POST", peer_uri, 60, False)
    assert cbor2.loads(payload) == waypoint


@pytest.mark.parametrize(
    ("peer", "waypoint", "detail"),
    [
        ("ff02::1", {"name": "All", "lat": 0.0, "lon": 0.0}, "unicast"),
        ("not-an-address", {"name": "Peer", "lat": 0.0, "lon": 0.0}, "IPv6"),
        ("0200::2", {"name": "", "lat": 0.0, "lon": 0.0}, "name"),
        ("0200::2", {"name": "North", "lat": 91.0, "lon": 0.0}, "lat"),
        ("0200::2", {"name": "East", "lat": 0.0, "lon": float("inf")}, "lon"),
    ],
)
async def test_share_waypoint_rejects_invalid_peer_or_payload_without_request(
    peer: str,
    waypoint: dict[str, Any],
    detail: str,
) -> None:
    transport = FakeResourceTransport({})
    client = LciClient(transport)

    result = await client.share_waypoint(peer, waypoint)

    assert result.state is DeliveryState.VALIDATION_ERROR
    assert detail in (result.detail or "")
    assert transport.requests == []


async def test_share_waypoint_preserves_peer_rejection_details() -> None:
    peer_uri = "coap://[200::2222]/waypoints"
    transport = FakeResourceTransport(
        {("POST", peer_uri): CoapResult(code="4.00", payload={"error": "expired"})}
    )
    client = LciClient(transport)

    result = await client.share_waypoint(
        "0200::2222",
        {"name": "Expired", "lat": 1.0, "lon": 2.0},
    )

    assert result.state is DeliveryState.REJECTED
    assert result.coap_code == "4.00"
    assert result.detail == "expired"


async def test_lci_client_defaults_interoperate_with_simulator_messages_resource() -> None:
    network = InMemoryNetwork()
    messages = MessagesResource()
    site = build_site(StaticNodeInfo(status={"rank": 256}), messages_resource=messages)
    server = await create_lichen_context(network.channel("srv"), "srv", site=site)
    context = await create_lichen_context(network.channel("::1"), "::1")
    transport = RecordingResourceTransport(
        AiocoapResourceTransport(
            config=IpCoapConfig(base_uri="coap://srv"),
            context=context,
        )
    )
    client = LciClient(transport)
    try:
        messages.deliver({"from": "fd00::1", "to": "all", "text": "legacy", "t": 1.5})

        inbox = await client.inbox()
        result = await client.send_message(MessageDraft(to="fd00::2", body="hello", ack=True))

        assert inbox[0].body == "legacy"
        assert inbox[0].timestamp == 1.5
        assert result.state is DeliveryState.ACCEPTED
        assert result.location_path == ("msg", "sent", "1")
        assert transport.requests == [("GET", "/msg/inbox"), ("POST", "/msg/inbox")]
        assert messages.sent_messages()[0]["body"] == "hello"
        assert messages.sent_messages()[0]["ack"] is True
    finally:
        await transport.close()
        await context.shutdown()
        await server.shutdown()


async def test_lci_client_can_use_legacy_messages_alias_explicitly() -> None:
    network = InMemoryNetwork()
    messages = MessagesResource()
    site = build_site(StaticNodeInfo(status={"rank": 256}), messages_resource=messages)
    server = await create_lichen_context(network.channel("srv"), "srv", site=site)
    context = await create_lichen_context(network.channel("::1"), "::1")
    transport = AiocoapResourceTransport(
        config=IpCoapConfig(base_uri="coap://srv"),
        context=context,
    )
    client = LciClient(transport)
    try:
        messages.deliver({"from": "fd00::1", "to": "all", "text": "legacy", "t": 1.5})

        inbox = await client.inbox("/messages")
        result = await client.send_message(
            MessageDraft(to="fd00::2", body="compat"),
            path="/messages",
        )

        assert inbox[0].body == "legacy"
        assert result.state is DeliveryState.ACCEPTED
        assert messages.sent_messages()[0]["body"] == "compat"
        legacy_rows = await client.inbox("/messages")
        assert legacy_rows[-1].body == "compat"
        assert legacy_rows[-1].raw["text"] == "compat"
    finally:
        await transport.close()
        await context.shutdown()
        await server.shutdown()


async def test_config_writes_logs_diagnostics_and_observe_inbox() -> None:
    inbox_subscription = FakeSubscription(
        [
            CoapResult(
                code="2.05",
                payload={"messages": [{"id": 18, "from": "a", "body": "updated"}]},
            )
        ]
    )
    log_subscription = FakeSubscription([CoapResult(code="2.05", payload={"records": []})])
    transport = FakeResourceTransport(
        {
            ("PUT", "/config"): CoapResult(code="2.04"),
            ("PUT", "/config/radio"): CoapResult(code="2.04"),
            ("GET", "/diag"): CoapResult(code="2.05", payload={"ok": True}),
        }
    )
    transport.subscriptions["/msg/inbox"] = inbox_subscription
    transport.subscriptions["/logs"] = log_subscription
    client = LciClient(transport)

    config_result = await client.set_config({"name": "new-name"})
    radio_result = await client.set_radio_config({"sf": 10})
    logs_subscription = await client.subscribe_logs()
    diag = await client.get_diagnostics()
    inbox_updates = await client.observe_inbox()

    assert config_result.code == "2.04"
    assert radio_result.code == "2.04"
    assert diag == {"ok": True}
    assert transport.requests[0][:4] == ("PUT", "/config", cbor2.dumps({"name": "new-name"}), 60)
    assert transport.requests[1][:4] == ("PUT", "/config/radio", cbor2.dumps({"sf": 10}), 60)
    assert transport.observes == [("GET", "/logs"), ("GET", "/msg/inbox")]
    assert logs_subscription is log_subscription
    async for messages in inbox_updates.messages():
        assert messages[0].message_id == 18
        assert messages[0].body == "updated"
        break
    await inbox_updates.close()
    assert inbox_subscription.closed is True


async def test_raw_rx_status_normalizes_supported_payload() -> None:
    transport = FakeResourceTransport(
        {
            ("GET", "/diag/raw/rx"): CoapResult(
                code="2.05",
                payload={"enabled": True, "remaining_s": 59, "max_ttl_s": 300},
            )
        }
    )
    client = LciClient(transport)

    status = await client.get_raw_rx_status()

    assert status.state is RawDiagnosticState.OK
    assert status.enabled is True
    assert status.remaining_s == 59
    assert status.max_ttl_s == 300
    assert transport.requests[-1][:2] == ("GET", "/diag/raw/rx")


@pytest.mark.parametrize("code", ["4.04", "5.01"])
async def test_raw_rx_status_maps_optional_unsupported_codes(code: str) -> None:
    transport = FakeResourceTransport(
        {("GET", "/diag/raw/rx"): CoapResult(code=code, payload={"error": "disabled"})}
    )
    client = LciClient(transport)

    status = await client.get_raw_rx_status()

    assert status.state is RawDiagnosticState.UNSUPPORTED
    assert status.coap_code == code
    assert status.detail == "disabled"


async def test_arm_raw_rx_puts_finite_cbor_ttl_payload() -> None:
    transport = FakeResourceTransport({("PUT", "/diag/raw/rx"): CoapResult(code="2.04")})
    client = LciClient(transport)

    result = await client.arm_raw_rx(ttl_s=60, include_payload=True)

    assert result.state is RawDiagnosticState.OK
    method, path, payload, content_format, observe = transport.requests[-1]
    assert (method, path, content_format, observe) == ("PUT", "/diag/raw/rx", 60, False)
    assert cbor2.loads(payload) == {
        "enabled": True,
        "ttl_s": 60,
        "include_payload": True,
    }


async def test_raw_rx_events_observe_normalizes_and_closes() -> None:
    subscription = FakeSubscription(
        [
            CoapResult(
                code="2.05",
                payload={
                    "frame": b"\xc1\x02\x03\x04",
                    "rssi_dbm": -85,
                    "snr_db": 7.5,
                    "freq_hz": 906875000,
                    "crc_ok": True,
                    "uptime_ms": 1234,
                },
            )
        ]
    )
    transport = FakeResourceTransport({})
    transport.subscriptions["/diag/raw/rx/events"] = subscription
    client = LciClient(transport)

    updates = await client.observe_raw_rx_events()
    async for event in updates.events():
        assert event.state is RawDiagnosticState.OK
        assert event.frame == b"\xc1\x02\x03\x04"
        assert event.rssi_dbm == -85
        assert event.snr_db == 7.5
        assert event.freq_hz == 906875000
        assert event.crc_ok is True
        assert event.uptime_ms == 1234
        break
    await updates.close()

    assert transport.observes == [("GET", "/diag/raw/rx/events")]
    assert subscription.closed is True


@pytest.mark.parametrize("code", ["4.04", "5.01"])
async def test_raw_rx_events_observe_unsupported_is_explicit(code: str) -> None:
    subscription = FakeSubscription([CoapResult(code=code, payload={"error": "unsupported"})])
    transport = FakeResourceTransport({})
    transport.subscriptions["/diag/raw/rx/events"] = subscription
    client = LciClient(transport)

    updates = await client.observe_raw_rx_events()

    async for event in updates.events():
        assert event.state is RawDiagnosticState.UNSUPPORTED
        assert event.coap_code == code
        assert event.detail == "unsupported"
        break


async def test_raw_tx_posts_cbor_frame_payload() -> None:
    transport = FakeResourceTransport({("POST", "/diag/raw/tx"): CoapResult(code="2.04")})
    client = LciClient(transport)

    result = await client.send_raw_tx(b"\xc1\x02\x03\x04", wait=True)

    assert result.state is RawDiagnosticState.OK
    method, path, payload, content_format, observe = transport.requests[-1]
    assert (method, path, content_format, observe) == ("POST", "/diag/raw/tx", 60, False)
    assert cbor2.loads(payload) == {"frame": b"\xc1\x02\x03\x04", "wait": True}


@pytest.mark.parametrize("code", ["4.04", "5.01"])
async def test_raw_tx_unsupported_codes_are_explicit(code: str) -> None:
    transport = FakeResourceTransport(
        {("POST", "/diag/raw/tx"): CoapResult(code=code, payload={"error": "unsupported"})}
    )
    client = LciClient(transport)

    result = await client.send_raw_tx(b"\xc1")

    assert result.state is RawDiagnosticState.UNSUPPORTED
    assert result.coap_code == code
    assert result.detail == "unsupported"


async def test_raw_tx_rejected_code_is_error_state() -> None:
    transport = FakeResourceTransport(
        {("POST", "/diag/raw/tx"): CoapResult(code="4.01", payload={"error": "admin required"})}
    )
    client = LciClient(transport)

    result = await client.send_raw_tx(b"\xc1")

    assert result.state is RawDiagnosticState.ERROR
    assert result.coap_code == "4.01"
    assert result.detail == "admin required"


async def test_send_message_receipt_posts_cbor_payload() -> None:
    transport = FakeResourceTransport({("POST", "/msg/ack"): CoapResult(code="2.04")})
    client = LciClient(transport)

    result = await client.send_message_receipt(
        MessageReceipt(message_id=12345, status=ReceiptStatus.DELIVERED, ts=1_716_742_900)
    )

    assert result.state is DeliveryState.ACCEPTED
    assert result.coap_code == "2.04"
    method, path, payload, content_format, observe = transport.requests[-1]
    assert (method, path, content_format, observe) == ("POST", "/msg/ack", 60, False)
    assert cbor2.loads(payload) == {
        "id": 12345,
        "status": "delivered",
        "ts": 1_716_742_900,
    }


@pytest.mark.parametrize("code", ["4.04", "5.01"])
async def test_send_message_receipt_optional_unsupported_states(code: str) -> None:
    transport = FakeResourceTransport(
        {("POST", "/msg/ack"): CoapResult(code=code, payload={"error": "unsupported"})}
    )
    client = LciClient(transport)

    result = await client.send_message_receipt(
        MessageReceipt(message_id=12345, status=ReceiptStatus.READ, ts=1_716_742_901)
    )

    assert result.state is DeliveryState.UNSUPPORTED
    assert result.coap_code == code
    assert result.detail == "unsupported"


async def test_send_message_receipt_validation_and_rejection_states() -> None:
    rejected_transport = FakeResourceTransport(
        {("POST", "/msg/ack"): CoapResult(code="4.00", payload={"error": "bad receipt"})}
    )
    rejected_client = LciClient(rejected_transport)
    validation_client = LciClient(FakeResourceTransport({}))

    rejected = await rejected_client.send_message_receipt(
        MessageReceipt(message_id=1, status=ReceiptStatus.FAILED, ts=1)
    )
    validation_id = await validation_client.send_message_receipt(
        MessageReceipt(message_id=-1, status=ReceiptStatus.FAILED, ts=1)
    )
    validation_ts = await validation_client.send_message_receipt(
        MessageReceipt(message_id=1, status=ReceiptStatus.FAILED, ts=-1)
    )
    validation_status = await validation_client.send_message_receipt(
        MessageReceipt(message_id=1, status="failed", ts=1)  # type: ignore[arg-type]
    )

    assert rejected.state is DeliveryState.REJECTED
    assert rejected.coap_code == "4.00"
    assert rejected.detail == "bad receipt"
    assert validation_id.state is DeliveryState.VALIDATION_ERROR
    assert validation_id.detail == "receipt id and timestamp must be unsigned integers"
    assert validation_ts.state is DeliveryState.VALIDATION_ERROR
    assert validation_ts.detail == "receipt id and timestamp must be unsigned integers"
    assert validation_status.state is DeliveryState.VALIDATION_ERROR
    assert validation_status.detail == "receipt status is invalid"


async def test_send_message_validation_and_rejection_states() -> None:
    client = LciClient(FakeResourceTransport({}))

    validation = await client.send_message(MessageDraft(to="", body="hello"))
    rejected = await client.send_message(MessageDraft(to="fd00::2", body="hello"))

    assert validation.state is DeliveryState.VALIDATION_ERROR
    assert rejected.state is DeliveryState.REJECTED
    assert rejected.coap_code == "4.04"


def test_legacy_message_text_normalizes_to_body() -> None:
    record = normalize_message({"from": "a", "to": "b", "text": "legacy", "t": 1.5})

    assert record.sender == "a"
    assert record.recipient == "b"
    assert record.body == "legacy"
    assert record.timestamp == 1.5


@pytest.mark.parametrize("payload", [None, [], "bad"])
def test_normalize_message_rejects_non_map(payload: Any) -> None:
    with pytest.raises(LciClientError):
        normalize_message(payload)


# LESC Security Tests (spec 17.5.4)


class SecurityCheckingTransport:
    """Transport that tracks security check calls."""

    def __init__(
        self,
        responses: dict[tuple[str, str], CoapResult],
        *,
        fail_security_for: set[str] | None = None,
    ) -> None:
        self.responses = responses
        self.fail_security_for = fail_security_for or set()
        self.security_checks: list[str] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        return self.responses.get((method, path), CoapResult(code="4.04"))

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def observe(self, path: str, *, method: str = "GET") -> FakeSubscription:
        response = self.responses.get((method, path), CoapResult(code="4.04"))
        return FakeSubscription([response])

    def check_security_for_path(self, path: str) -> None:
        self.security_checks.append(path)
        if path in self.fail_security_for:
            raise LciSecurityError(
                f"LESC required for {path}",
                path=path,
                required_level="LESC",
                actual_level="UNKNOWN",
            )


async def test_lci_client_checks_security_for_raw_rx_status() -> None:
    """get_raw_rx_status checks security before accessing /diag/raw/rx."""
    transport = SecurityCheckingTransport(
        {("GET", "/diag/raw/rx"): CoapResult(code="2.05", payload={"enabled": False})}
    )
    client = LciClient(transport)

    await client.get_raw_rx_status()

    assert "/diag/raw/rx" in transport.security_checks


async def test_lci_client_checks_security_for_arm_raw_rx() -> None:
    """arm_raw_rx checks security before accessing /diag/raw/rx."""
    transport = SecurityCheckingTransport(
        {("PUT", "/diag/raw/rx"): CoapResult(code="2.04")}
    )
    client = LciClient(transport)

    await client.arm_raw_rx(ttl_s=60)

    assert "/diag/raw/rx" in transport.security_checks


async def test_lci_client_checks_security_for_observe_raw_rx_events() -> None:
    """observe_raw_rx_events checks security before accessing /diag/raw/rx/events."""
    transport = SecurityCheckingTransport(
        {("GET", "/diag/raw/rx/events"): CoapResult(code="2.05", payload={})}
    )
    client = LciClient(transport)

    subscription = await client.observe_raw_rx_events()
    await subscription.close()

    assert "/diag/raw/rx/events" in transport.security_checks


async def test_lci_client_checks_security_for_send_raw_tx() -> None:
    """send_raw_tx checks security before accessing /diag/raw/tx."""
    transport = SecurityCheckingTransport(
        {("POST", "/diag/raw/tx"): CoapResult(code="2.04")}
    )
    client = LciClient(transport)

    await client.send_raw_tx(b"\xc1\x02")

    assert "/diag/raw/tx" in transport.security_checks


async def test_lci_client_raises_lci_security_error_for_raw_diagnostics() -> None:
    """LciSecurityError is raised when transport fails security check."""
    transport = SecurityCheckingTransport(
        {("GET", "/diag/raw/rx"): CoapResult(code="2.05", payload={"enabled": False})},
        fail_security_for={"/diag/raw/rx"},
    )
    client = LciClient(transport)

    with pytest.raises(LciSecurityError) as exc_info:
        await client.get_raw_rx_status()

    assert exc_info.value.path == "/diag/raw/rx"
    assert exc_info.value.required_level == "LESC"
    assert exc_info.value.actual_level == "UNKNOWN"


async def test_lci_client_does_not_check_security_for_non_diag_paths() -> None:
    """Security is not checked for non-diagnostic paths."""
    transport = SecurityCheckingTransport(
        {
            ("GET", "/status"): CoapResult(code="2.05", payload={"uptime_s": 42}),
            ("GET", "/config"): CoapResult(code="2.05", payload={"name": "node"}),
            ("GET", "/diag"): CoapResult(code="2.05", payload={"available": True}),
        }
    )
    client = LciClient(transport)

    await client.get_status()
    await client.get_config()
    await client.get_diagnostics()

    # /diag alone doesn't require LESC (only /diag/raw/* does)
    assert transport.security_checks == []


async def test_lci_client_skips_security_check_for_transports_without_method() -> None:
    """Transports without check_security_for_path are assumed secure (USB/serial)."""
    transport = FakeResourceTransport(
        {("GET", "/diag/raw/rx"): CoapResult(code="2.05", payload={"enabled": False})}
    )
    client = LciClient(transport)

    # Should not raise - FakeResourceTransport doesn't implement check_security_for_path
    result = await client.get_raw_rx_status()

    assert result.enabled is False


# OverflowError handling in helper functions (r2-P1-18)


def test_int_or_none_handles_overflow_from_decimal_infinity() -> None:
    """_int_or_none returns None for Decimal('inf'), not OverflowError (r2-P1-18).

    CBOR tag 4 (decimal fraction) can decode to Decimal('inf'). Calling int()
    on Decimal('inf') raises OverflowError, not ValueError.
    """
    assert _int_or_none(Decimal("inf")) is None
    assert _int_or_none(Decimal("-inf")) is None


def test_float_or_none_handles_overflow_from_large_integer() -> None:
    """_float_or_none returns None for huge integers, not OverflowError (r2-P1-18).

    CBOR bignum tags (tag 2/3) can decode to arbitrarily large Python ints.
    Calling float() on integers larger than ~10^308 raises OverflowError.
    """
    huge_int = 10**1000
    assert _float_or_none(huge_int) is None
    assert _float_or_none(-huge_int) is None
