# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared fixtures for native TUI tests."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping

from lichen.client import (
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    DeliveryState,
    DeviceStatus,
    Identity,
    MessageDraft,
    MessageRecord,
    Neighbor,
    RadioConfig,
    RawDiagnosticResult,
    RawDiagnosticState,
    RawRxEvent,
    RawRxStatus,
    Route,
    SendResult,
)


class FakeMessageSubscription:
    def __init__(self, snapshots: list[list[MessageRecord]], *, keep_open: bool = False) -> None:
        self.snapshots = snapshots
        self.keep_open = keep_open
        self.closed = False

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        return self._messages()

    async def close(self) -> None:
        self.closed = True

    async def _messages(self) -> AsyncIterator[list[MessageRecord]]:
        for snapshot in self.snapshots:
            yield snapshot
        if self.keep_open:
            await asyncio.Event().wait()


class FakeRawRxSubscription:
    def __init__(self, events: list[RawRxEvent], *, keep_open: bool = False) -> None:
        self.event_rows = events
        self.keep_open = keep_open
        self.closed = False

    def events(self) -> AsyncIterator[RawRxEvent]:
        return self._events()

    async def close(self) -> None:
        self.closed = True

    async def _events(self) -> AsyncIterator[RawRxEvent]:
        for event in self.event_rows:
            yield event
        if self.keep_open:
            await asyncio.Event().wait()


class FakeResourceSubscription:
    def __init__(self, results: list[CoapResult] | None = None) -> None:
        self._result_rows = results or [
            CoapResult(
                code="2.05",
                payload=[
                    {
                        "from": "fd00::1",
                        "to": "fd00::2",
                        "body": "observed from transport",
                        "received": "2026-07-02T04:00:00Z",
                    }
                ],
            )
        ]
        self.closed = False

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def close(self) -> None:
        self.closed = True

    async def _results(self) -> AsyncIterator[CoapResult]:
        for result in self._result_rows:
            yield result


class FakeMessagingClient:
    def __init__(
        self,
        *,
        inbox: list[MessageRecord] | None = None,
        observe: list[list[MessageRecord]] | None = None,
        keep_observe_open: bool = False,
        result: SendResult | None = None,
        inbox_error: Exception | None = None,
        observe_error: Exception | None = None,
        send_error: Exception | None = None,
        status_error: Exception | None = None,
        config_write_result: CoapResult | None = None,
        raw_rx_status: RawRxStatus | None = None,
        raw_available: bool = True,
        raw_events: list[RawRxEvent] | None = None,
        raw_arm_result: RawDiagnosticResult | None = None,
        raw_tx_result: RawDiagnosticResult | None = None,
        connect_error: Exception | None = None,
        disconnect_error: Exception | None = None,
    ) -> None:
        self.inbox_rows = inbox or []
        self.observe_rows = observe or []
        self.keep_observe_open = keep_observe_open
        self.result = result or SendResult(state=DeliveryState.ACCEPTED, coap_code="2.04")
        self.inbox_error = inbox_error
        self.observe_error = observe_error
        self.send_error = send_error
        self.status_error = status_error
        self.connect_error = connect_error
        self.disconnect_error = disconnect_error
        self.config_write_result = config_write_result or CoapResult(code="2.04")
        self.raw_rx_status = raw_rx_status or RawRxStatus(
            state=RawDiagnosticState.OK,
            raw={"enabled": True, "remaining_s": 60, "max_ttl_s": 300},
            enabled=True,
            remaining_s=60,
            max_ttl_s=300,
            coap_code="2.05",
        )
        self.raw_available = raw_available
        self.raw_arm_result = raw_arm_result or RawDiagnosticResult(
            state=RawDiagnosticState.OK,
            coap_code="2.04",
        )
        self.raw_tx_result = raw_tx_result or RawDiagnosticResult(
            state=RawDiagnosticState.OK,
            coap_code="2.04",
        )
        self.raw_events = raw_events or [
            RawRxEvent(
                state=RawDiagnosticState.OK,
                raw={"frame": b"\xc1\x02\x03\x04", "rssi_dbm": -85, "snr_db": 7.5},
                frame=b"\xc1\x02\x03\x04",
                rssi_dbm=-85,
                snr_db=7.5,
            )
        ]
        self.inbox_calls: list[str] = []
        self.observe_calls: list[str] = []
        self.send_calls: list[tuple[MessageDraft, str]] = []
        self.status_calls = 0
        self.config_calls = 0
        self.radio_calls = 0
        self.identity_calls = 0
        self.discover_calls = 0
        self.neighbor_calls = 0
        self.route_calls = 0
        self.config_writes: list[dict[str, object]] = []
        self.radio_writes: list[dict[str, object]] = []
        self.log_calls: list[str] = []
        self.diagnostics_calls: list[str] = []
        self.raw_rx_calls: list[str] = []
        self.raw_rx_arm_calls: list[tuple[int, bool, bool, str]] = []
        self.raw_tx_calls: list[tuple[bytes, bool, str]] = []
        self.raw_observe_calls: list[str] = []
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.subscription: FakeMessageSubscription | None = None
        self.log_subscription = FakeResourceSubscription(
            [
                CoapResult(
                    code="2.05",
                    payload={
                        "records": [{"level": "warn", "module": "coap", "message": "timeout"}]
                    },
                )
            ]
        )
        self.raw_subscription = FakeRawRxSubscription(self.raw_events)

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_error is not None:
            raise self.connect_error

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        if self.disconnect_error is not None:
            raise self.disconnect_error

    async def inbox(self, path: str = "/msg/inbox") -> list[MessageRecord]:
        self.inbox_calls.append(path)
        if self.inbox_error is not None:
            raise self.inbox_error
        return self.inbox_rows

    async def observe_inbox(self, path: str = "/msg/inbox") -> FakeMessageSubscription:
        self.observe_calls.append(path)
        if self.observe_error is not None:
            raise self.observe_error
        self.subscription = FakeMessageSubscription(
            self.observe_rows,
            keep_open=self.keep_observe_open,
        )
        return self.subscription

    async def send_message(self, draft: MessageDraft, path: str = "/msg/inbox") -> SendResult:
        self.send_calls.append((draft, path))
        if self.send_error is not None:
            raise self.send_error
        return self.result

    async def discover(self) -> Capabilities:
        self.discover_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return Capabilities(
            resources=frozenset({"/status", "/config", "/logs"}),
            observable=frozenset({"/logs"}),
        )

    async def get_status(self) -> DeviceStatus:
        self.status_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return DeviceStatus(
            raw={},
            uptime_s=42,
            battery_pct=87,
            battery_mv=3950,
            mem_free_kb=128,
            dodag={"joined": True},
            radio={"rx_packets": 3, "tx_packets": 2},
        )

    async def get_config(self) -> ConfigSnapshot:
        self.config_calls += 1
        return ConfigSnapshot(raw={}, name="node-a", role="router", radio_path="/config/radio")

    async def get_radio_config(self) -> RadioConfig:
        self.radio_calls += 1
        return RadioConfig(
            raw={},
            freq_mhz=906.875,
            bw_khz=125,
            sf=10,
            cr="4/5",
            tx_power_dbm=17,
            sync_word="0x34",
        )

    async def get_identity(self) -> Identity:
        self.identity_calls += 1
        return Identity(
            raw={"private_key": "DO_NOT_PRINT"},
            eui64="0x0011223344556677",
            pubkey="PUBLIC_KEY_SHOULD_NOT_RENDER",
            pubkey_fingerprint="SHA256:abc",
            addrs={"link_local": "fe80::1"},
        )

    async def list_neighbors(self) -> list[Neighbor]:
        self.neighbor_calls += 1
        return [
            Neighbor(
                raw={},
                addr="fe80::2",
                rssi_dbm=-80,
                snr_db=7.5,
                etx=1.2,
                trust="tofu",
                last_seen_s=30,
            )
        ]

    async def list_routes(self) -> list[Route]:
        self.route_calls += 1
        return [Route(raw={}, prefix="fd00::/64", via="fe80::2", metric=512, lifetime_s=1800)]

    async def set_config(self, values: Mapping[str, object]) -> CoapResult:
        self.config_writes.append(dict(values))
        return self.config_write_result

    async def set_radio_config(self, values: Mapping[str, object]) -> CoapResult:
        self.radio_writes.append(dict(values))
        return self.config_write_result

    async def subscribe_logs(self, path: str = "/logs") -> FakeResourceSubscription:
        self.log_calls.append(path)
        return self.log_subscription

    async def get_diagnostics(self, path: str = "/diag") -> object:
        self.diagnostics_calls.append(path)
        raw = (
            {
                "available": True,
                "rx": "/diag/raw/rx",
                "rx_events": "/diag/raw/rx/events",
                "tx": "/diag/raw/tx",
                "max_frame_len": 255,
            }
            if self.raw_available
            else {"available": False}
        )
        return {
            "ok": True,
            "raw": raw,
            "nested": {"queue": 3},
            "private_key": "DO_NOT_PRINT",
            "raw_payload": "DO_NOT_PRINT_RAW",
            "blob": b"DO_NOT_PRINT_BYTES",
            "frame": "c1020304",
            "tokens": ["DO_NOT_PRINT"],
        }

    async def get_raw_rx_status(self, path: str = "/diag/raw/rx") -> RawRxStatus:
        self.raw_rx_calls.append(path)
        return self.raw_rx_status

    async def arm_raw_rx(
        self,
        *,
        ttl_s: int,
        include_payload: bool = False,
        enabled: bool = True,
        path: str = "/diag/raw/rx",
    ) -> RawDiagnosticResult:
        self.raw_rx_arm_calls.append((ttl_s, include_payload, enabled, path))
        return self.raw_arm_result

    async def send_raw_tx(
        self,
        frame: bytes | bytearray | memoryview,
        *,
        wait: bool = True,
        path: str = "/diag/raw/tx",
    ) -> RawDiagnosticResult:
        self.raw_tx_calls.append((bytes(frame), wait, path))
        return self.raw_tx_result

    async def observe_raw_rx_events(
        self,
        path: str = "/diag/raw/rx/events",
    ) -> FakeRawRxSubscription:
        self.raw_observe_calls.append(path)
        self.raw_subscription = FakeRawRxSubscription(self.raw_events)
        return self.raw_subscription


class FakeResourceTransport:
    def __init__(self) -> None:
        self.connected = False
        self.closed = False
        self.requests: list[tuple[str, str]] = []

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

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
        return CoapResult(
            code="2.05",
            payload=[
                {
                    "from": "fd00::1",
                    "to": "fd00::2",
                    "body": "from ip transport",
                    "received": "2026-07-02T04:00:00Z",
                }
            ],
        )

    async def observe(self, path: str, *, method: str = "GET") -> FakeResourceSubscription:
        return FakeResourceSubscription()


def message_record(
    body: str,
    *,
    sender: str | None = "fd00::1",
    recipient: str | None = "fd00::2",
    received: str = "2026-07-02T04:00:00Z",
) -> MessageRecord:
    return MessageRecord(
        raw={"from": sender, "to": recipient, "body": body, "received": received},
        sender=sender,
        recipient=recipient,
        body=body,
        received=received,
    )
