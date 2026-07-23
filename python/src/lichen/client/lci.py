# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LCI CoAP client abstractions shared by native apps."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Mapping
from typing import Any, Protocol, Self

import cbor2

from lichen.client.model import (
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    DeliveryState,
    DeviceStatus,
    Identity,
    JsonMap,
    MessageDraft,
    MessageReceipt,
    MessageRecord,
    Neighbor,
    RadioConfig,
    RawDiagnosticResult,
    RawDiagnosticState,
    RawRxEvent,
    RawRxStatus,
    ReceiptResult,
    ReceiptStatus,
    Route,
    SendResult,
)

CBOR_CONTENT_FORMAT = 60
RAW_DIAGNOSTIC_UNSUPPORTED_CODES = frozenset({"4.04", "5.01"})


class ResourceTransport(Protocol):
    """CoAP-resource transport used by the LCI client model.

    Concrete implementations may use direct IP/UDP CoAP, or a CoAP stack
    running over a packet transport such as BLE/serial SLIP.
    """

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        """Perform one CoAP request and return a decoded response."""

    async def connect(self) -> None:
        """Open the underlying transport or establish a no-op IP session."""

    async def close(self) -> None:
        """Close the underlying transport session."""

    async def observe(self, path: str, *, method: str = "GET") -> ResourceSubscription:
        """Open an Observe subscription for a resource.

        The caller MUST use `async with (await self._transport.observe(path)) as sub:`
        (preferred, RAII) or explicitly await sub.close() exactly once. If observe()
        raises, no subscription is returned and no cleanup is required. close() is
        idempotent and safe to call from exception handlers.
        """


class ResourceSubscription(Protocol):
    """Handle for a CoAP Observe relationship.

    Caller owns lifecycle: MUST use as async context manager (preferred) or
    await close() exactly once after results() iteration completes or is
    cancelled. close() is idempotent. Implementations suppress expected errors
    during close().
    """

    def results(self) -> AsyncIterator[CoapResult]:
        """Yield initial and later notification responses."""

    async def close(self) -> None:
        """Cancel the Observe relationship and release resources."""

    async def __aenter__(self) -> Self:
        ...

    async def __aexit__(
        self, exc_type: Any | None, exc_val: Any | None, exc_tb: Any | None
    ) -> None:
        ...


class MessageSubscription:
    """Typed message updates from an inbox Observe relationship.

    Use as `async with subscription:` for automatic close().
    """

    def __init__(self, subscription: ResourceSubscription, path: str) -> None:
        self._subscription = subscription
        self._path = path

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        """Yield normalized inbox snapshots from Observe notifications."""
        return self._messages()

    async def close(self) -> None:
        """Cancel the inbox Observe relationship."""
        with contextlib.suppress(Exception):
            await self._subscription.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: Any | None, exc_val: Any | None, exc_tb: Any | None
    ) -> None:
        with contextlib.suppress(Exception):
            await self.close()

    async def _messages(self) -> AsyncIterator[list[MessageRecord]]:
        async for result in self._subscription.results():
            if not result.is_success:
                raise LciClientError(
                    f"GET {self._path} observe failed with {result.code}",
                    method="GET",
                    path=self._path,
                    code=result.code,
                    payload=result.payload,
                )
            yield _normalize_inbox_payload(result.payload, self._path)


class RawRxSubscription:
    """Typed raw RX diagnostic Observe notifications.

    Use as `async with subscription:` for automatic close().
    """

    def __init__(self, subscription: ResourceSubscription, path: str) -> None:
        self._subscription = subscription
        self._path = path

    def events(self) -> AsyncIterator[RawRxEvent]:
        """Yield normalized raw RX events and explicit unsupported/error states."""
        return self._events()

    async def close(self) -> None:
        """Cancel the raw RX Observe relationship."""
        with contextlib.suppress(Exception):
            await self._subscription.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: Any | None, exc_val: Any | None, exc_tb: Any | None
    ) -> None:
        with contextlib.suppress(Exception):
            await self.close()

    async def _events(self) -> AsyncIterator[RawRxEvent]:
        async for result in self._subscription.results():
            if not result.is_success:
                yield _raw_event_from_result(result)
                continue
            yield normalize_raw_rx_event(result.payload)


class LciClientError(RuntimeError):
    """LCI request or payload error with firmware/CoAP details preserved."""

    def __init__(
        self,
        message: str,
        *,
        method: str | None = None,
        path: str | None = None,
        code: str | None = None,
        payload: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.method = method
        self.path = path
        self.code = code
        self.payload = payload


class LciClient:
    """App-facing LCI client over discovered CoAP resources."""

    def __init__(self, transport: ResourceTransport) -> None:
        self._transport = transport

    async def connect(self) -> None:
        """Open the underlying LCI transport."""
        await self._transport.connect()

    async def disconnect(self) -> None:
        """Close the underlying LCI transport."""
        await self._transport.close()

    async def discover(self) -> Capabilities:
        """Discover advertised CoAP resources from `/.well-known/core`."""
        result = await self._request("GET", "/.well-known/core")
        body = _payload_text(result)
        return parse_link_format(body)

    async def get_status(self) -> DeviceStatus:
        """Return normalized node status from `/status`."""
        return normalize_status(await self._get_map("/status"))

    async def get_config(self) -> ConfigSnapshot:
        """Return normalized node config from `/config`."""
        return normalize_config(await self._get_map("/config"))

    async def get_radio_config(self) -> RadioConfig:
        """Return normalized radio config from `/config/radio`."""
        return normalize_radio_config(await self._get_map("/config/radio"))

    async def get_identity(self) -> Identity:
        """Return normalized identity from `/config/identity`."""
        return normalize_identity(await self._get_map("/config/identity"))

    async def identify_node(self) -> Identity:
        """Return node identity for app-facing discovery flows."""
        return await self.get_identity()

    async def set_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Update mutable node config through `PUT /config`."""
        return await self._put_map("/config", values)

    async def set_radio_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Update mutable radio config through `PUT /config/radio`."""
        return await self._put_map("/config/radio", values)

    async def list_neighbors(self) -> list[Neighbor]:
        """Return normalized neighbors from `/status/neighbors`."""
        payload = await self._get_payload("/status/neighbors")
        neighbors = payload.get("neighbors", []) if isinstance(payload, Mapping) else payload
        if not isinstance(neighbors, list):
            raise LciClientError(
                "/status/neighbors payload is not a neighbor list",
                path="/status/neighbors",
                payload=payload,
            )
        return [normalize_neighbor(item) for item in neighbors]

    async def list_routes(self) -> list[Route]:
        """Return normalized routes from `/status/routes`."""
        payload = await self._get_payload("/status/routes")
        routes = payload.get("routes", []) if isinstance(payload, Mapping) else payload
        if not isinstance(routes, list):
            raise LciClientError(
                "/status/routes payload is not a route list",
                path="/status/routes",
                payload=payload,
            )
        return [normalize_route(item) for item in routes]

    async def inbox(self, path: str = "/msg/inbox") -> list[MessageRecord]:
        """Return normalized message records from the selected inbox path."""
        return _normalize_inbox_payload(await self._get_payload(path), path)

    async def observe_inbox(self, path: str = "/msg/inbox") -> MessageSubscription:
        """Start observing an inbox resource and return typed updates."""
        return MessageSubscription(await self._transport.observe(path), path)

    async def send_message(self, draft: MessageDraft, path: str = "/msg/inbox") -> SendResult:
        """Send a message through the selected discovered messaging resource."""
        if not draft.to or not draft.body:
            return SendResult(
                state=DeliveryState.VALIDATION_ERROR,
                detail="recipient and body are required",
            )
        payload = cbor2.dumps(draft.to_payload())
        try:
            result = await self._transport.request(
                "POST",
                path,
                payload=payload,
                content_format=CBOR_CONTENT_FORMAT,
            )
        except Exception as exc:
            return SendResult(
                state=DeliveryState.TRANSPORT_ERROR,
                detail=str(exc),
            )
        if result.is_success:
            return SendResult(
                state=DeliveryState.ACCEPTED,
                coap_code=result.code,
                location_path=result.location_path,
            )
        return SendResult(
            state=DeliveryState.REJECTED,
            coap_code=result.code,
            detail=_result_detail(result),
        )

    async def send_message_receipt(
        self,
        receipt: MessageReceipt,
        path: str = "/msg/ack",
    ) -> ReceiptResult:
        """Post a delivery/read/failure receipt through `/msg/ack`."""
        if not _valid_receipt_id(receipt.message_id) or not _valid_receipt_timestamp(receipt.ts):
            return ReceiptResult(
                state=DeliveryState.VALIDATION_ERROR,
                detail="receipt id and timestamp must be unsigned integers",
            )
        if not isinstance(receipt.status, ReceiptStatus):
            return ReceiptResult(
                state=DeliveryState.VALIDATION_ERROR,
                detail="receipt status is invalid",
            )
        try:
            result = await self._transport.request(
                "POST",
                path,
                payload=cbor2.dumps(receipt.to_payload()),
                content_format=CBOR_CONTENT_FORMAT,
            )
        except Exception as exc:
            return ReceiptResult(
                state=DeliveryState.TRANSPORT_ERROR,
                detail=str(exc),
            )
        if result.is_success:
            return ReceiptResult(state=DeliveryState.ACCEPTED, coap_code=result.code)
        state = (
            DeliveryState.UNSUPPORTED
            if result.code in {"4.04", "5.01"}
            else DeliveryState.REJECTED
        )
        return ReceiptResult(
            state=state,
            coap_code=result.code,
            detail=_result_detail(result),
        )

    async def subscribe_logs(self, path: str = "/logs") -> ResourceSubscription:
        """Start observing a log stream resource when firmware exposes one."""
        return await self._transport.observe(path)

    async def get_diagnostics(self, path: str = "/diag") -> Any:
        """Fetch a diagnostics resource payload."""
        return await self._get_payload(path)

    async def get_raw_rx_status(self, path: str = "/diag/raw/rx") -> RawRxStatus:
        """Fetch optional raw RX diagnostics state without falling back to legacy APIs."""
        result = await self._raw_request("GET", path)
        if not result.is_success:
            return _raw_rx_status_from_result(result)
        return normalize_raw_rx_status(result.payload, coap_code=result.code)

    async def arm_raw_rx(
        self,
        *,
        ttl_s: int,
        include_payload: bool = False,
        enabled: bool = True,
        path: str = "/diag/raw/rx",
    ) -> RawDiagnosticResult:
        """Enable raw RX diagnostics for a finite TTL."""
        if ttl_s <= 0:
            return RawDiagnosticResult(
                state=RawDiagnosticState.ERROR,
                detail="ttl_s must be positive",
            )
        payload = {
            "enabled": enabled,
            "ttl_s": ttl_s,
            "include_payload": include_payload,
        }
        result = await self._raw_request(
            "PUT",
            path,
            payload=cbor2.dumps(payload),
            content_format=CBOR_CONTENT_FORMAT,
        )
        return _raw_command_result(result)

    async def observe_raw_rx_events(
        self,
        path: str = "/diag/raw/rx/events",
    ) -> RawRxSubscription:
        """Start observing optional raw RX diagnostic events."""
        return RawRxSubscription(await self._transport.observe(path), path)

    async def send_raw_tx(
        self,
        frame: bytes | bytearray | memoryview,
        *,
        wait: bool = True,
        path: str = "/diag/raw/tx",
    ) -> RawDiagnosticResult:
        """Transmit one raw diagnostic frame through the optional LCI resource."""
        payload = {"frame": bytes(frame), "wait": wait}
        result = await self._raw_request(
            "POST",
            path,
            payload=cbor2.dumps(payload),
            content_format=CBOR_CONTENT_FORMAT,
        )
        return _raw_command_result(result)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        result = await self._transport.request(
            method,
            path,
            payload=payload,
            content_format=content_format,
            observe=observe,
        )
        if not result.is_success:
            raise LciClientError(
                f"{method} {path} failed with {result.code}",
                method=method,
                path=path,
                code=result.code,
                payload=result.payload,
            )
        return result

    async def _raw_request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
    ) -> CoapResult:
        try:
            return await self._transport.request(
                method,
                path,
                payload=payload,
                content_format=content_format,
            )
        except Exception as exc:
            # Sentinel code="0.00" (see CoapResult.is_transport_error and model.py:65).
            # Preserves exception type (addresses lost type info).
            return CoapResult(
                code="0.00",
                payload={"error": str(exc), "type": type(exc).__name__},
            )

    async def _get_payload(self, path: str) -> Any:
        result = await self._request("GET", path)
        return result.payload

    async def _get_map(self, path: str) -> JsonMap:
        payload = await self._get_payload(path)
        if not isinstance(payload, Mapping):
            raise LciClientError(f"{path} payload is not a map", path=path, payload=payload)
        return dict(payload)

    async def _get_list(self, path: str) -> list[Any]:
        payload = await self._get_payload(path)
        if not isinstance(payload, list):
            raise LciClientError(f"{path} payload is not a list", path=path, payload=payload)
        return payload

    async def _put_map(self, path: str, values: Mapping[str, Any]) -> CoapResult:
        payload = cbor2.dumps(dict(values))
        return await self._request(
            "PUT",
            path,
            payload=payload,
            content_format=CBOR_CONTENT_FORMAT,
        )


def parse_link_format(body: str) -> Capabilities:
    """Parse a small CoRE Link Format subset into app capabilities."""
    resources: set[str] = set()
    observable: set[str] = set()
    resource_types: dict[str, tuple[str, ...]] = {}

    for entry in _split_link_entries(body):
        target, *params = [part.strip() for part in _split_link_params(entry)]
        if not target.startswith("<") or not target.endswith(">"):
            continue
        path = target[1:-1]
        resources.add(path)
        rts: list[str] = []
        for param in params:
            if param == "obs":
                observable.add(path)
            elif param.startswith("rt="):
                rts.extend(_quoted_tokens(param[3:]))
        if rts:
            resource_types[path] = tuple(rts)

    return Capabilities(
        resources=frozenset(resources),
        observable=frozenset(observable),
        resource_types=resource_types,
    )


def normalize_status(payload: Mapping[str, Any]) -> DeviceStatus:
    """Normalize a `/status` payload."""
    raw = dict(payload)
    return DeviceStatus(
        raw=raw,
        uptime_s=_int_or_none(raw.get("uptime_s", raw.get("uptime"))),
        battery_pct=_int_or_none(raw.get("battery_pct")),
        battery_mv=_int_or_none(raw.get("battery_mv")),
        mem_free_kb=_int_or_none(raw.get("mem_free_kb")),
        dodag=_map_or_none(raw.get("dodag")),
        radio=_map_or_none(raw.get("radio")),
    )


def normalize_config(payload: Mapping[str, Any]) -> ConfigSnapshot:
    """Normalize a `/config` payload."""
    raw = dict(payload)
    return ConfigSnapshot(
        raw=raw,
        name=_str_or_none(raw.get("name")),
        role=_str_or_none(raw.get("role")),
        radio_path=_str_or_none(raw.get("radio")),
        identity_path=_str_or_none(raw.get("identity")),
    )


def normalize_radio_config(payload: Mapping[str, Any]) -> RadioConfig:
    """Normalize a `/config/radio` payload."""
    raw = dict(payload)
    return RadioConfig(
        raw=raw,
        freq_mhz=_float_or_none(raw.get("freq_mhz")),
        bw_khz=_int_or_none(raw.get("bw_khz")),
        sf=_int_or_none(raw.get("sf")),
        cr=_str_or_none(raw.get("cr")),
        tx_power_dbm=_int_or_none(raw.get("tx_power_dbm")),
        sync_word=_str_or_none(raw.get("sync_word")),
    )


def normalize_identity(payload: Mapping[str, Any]) -> Identity:
    """Normalize a `/config/identity` payload."""
    raw = dict(payload)
    return Identity(
        raw=raw,
        eui64=_str_or_none(raw.get("eui64")),
        pubkey=_str_or_none(raw.get("pubkey")),
        pubkey_fingerprint=_str_or_none(raw.get("pubkey_fingerprint")),
        addrs=_map_or_none(raw.get("addrs")),
    )


def normalize_neighbor(payload: Any) -> Neighbor:
    """Normalize one neighbor row, preserving the original map."""
    raw = _require_map(payload, "neighbor")
    return Neighbor(
        raw=raw,
        addr=_str_or_none(raw.get("addr", raw.get("address"))),
        iid=_str_or_none(raw.get("iid")),
        rssi_dbm=_float_or_none(raw.get("rssi_dbm", raw.get("rssi"))),
        snr_db=_float_or_none(raw.get("snr_db", raw.get("snr"))),
        etx=_float_or_none(raw.get("etx")),
        trust=_str_or_none(raw.get("trust")),
        lqi=_int_or_none(raw.get("lqi")),
        last_seen_s=_int_or_none(raw.get("last_seen_s", raw.get("last_heard"))),
        # RF health extensions (5g8t.2, 5g8t.4)
        success_rate_pct=_float_or_none(raw.get("success_rate_pct", raw.get("success_rate"))),
        duty_observed_pct=_float_or_none(
            raw.get("duty_observed_pct", raw.get("duty_pct", raw.get("observed_duty")))
        ),
        is_cheater=_bool_or_none(raw.get("is_cheater", raw.get("cheater"))),
        rx_count=_int_or_none(raw.get("rx_count")),
        tx_count=_int_or_none(raw.get("tx_count")),
    )


def normalize_route(payload: Any) -> Route:
    """Normalize one route row, preserving the original map."""
    raw = _require_map(payload, "route")
    return Route(
        raw=raw,
        prefix=_str_or_none(raw.get("prefix", raw.get("destination", raw.get("dest")))),
        via=_str_or_none(raw.get("via", raw.get("next_hop"))),
        metric=_int_or_none(raw.get("metric", raw.get("hops"))),
        lifetime_s=_int_or_none(raw.get("lifetime_s", raw.get("expires"))),
        flags=_int_or_none(raw.get("flags")),
    )


def normalize_message(payload: Any) -> MessageRecord:
    """Normalize one message row from `/msg/inbox` or legacy `/messages`."""
    raw = _require_map(payload, "message")
    return MessageRecord(
        raw=raw,
        message_id=_int_or_none(raw.get("id")),
        sender=_str_or_none(raw.get("from")),
        recipient=_str_or_none(raw.get("to")),
        body=_str_or_none(raw.get("body", raw.get("text"))),
        received=_str_or_none(raw.get("received")),
        timestamp=raw.get("ts", raw.get("t")),
    )


def normalize_raw_rx_status(payload: Any, *, coap_code: str | None = None) -> RawRxStatus:
    """Normalize a `/diag/raw/rx` status payload."""
    if not isinstance(payload, Mapping):
        return RawRxStatus(
            state=RawDiagnosticState.ERROR,
            coap_code=coap_code,
            detail="/diag/raw/rx payload is not a map",
        )
    raw = dict(payload)
    enabled = raw.get("enabled")
    return RawRxStatus(
        state=RawDiagnosticState.OK,
        raw=raw,
        enabled=enabled if isinstance(enabled, bool) else None,
        remaining_s=_int_or_none(raw.get("remaining_s")),
        max_ttl_s=_int_or_none(raw.get("max_ttl_s")),
        coap_code=coap_code,
    )


def normalize_raw_rx_event(payload: Any, *, coap_code: str | None = None) -> RawRxEvent:
    """Normalize a `/diag/raw/rx/events` notification."""
    if not isinstance(payload, Mapping):
        return RawRxEvent(
            state=RawDiagnosticState.ERROR,
            coap_code=coap_code,
            detail="/diag/raw/rx/events payload is not a map",
        )
    raw = dict(payload)
    frame = raw.get("frame")
    return RawRxEvent(
        state=RawDiagnosticState.OK,
        raw=raw,
        frame=bytes(frame) if isinstance(frame, bytes | bytearray | memoryview) else None,
        rssi_dbm=_float_or_none(raw.get("rssi_dbm", raw.get("rssi"))),
        snr_db=_float_or_none(raw.get("snr_db", raw.get("snr"))),
        freq_hz=_int_or_none(raw.get("freq_hz")),
        crc_ok=raw.get("crc_ok") if isinstance(raw.get("crc_ok"), bool) else None,
        uptime_ms=_int_or_none(raw.get("uptime_ms")),
        coap_code=coap_code,
    )


def _normalize_inbox_payload(payload: Any, path: str) -> list[MessageRecord]:
    messages = payload.get("messages", []) if isinstance(payload, Mapping) else payload
    if not isinstance(messages, list):
        raise LciClientError("message inbox payload is not a list", path=path, payload=payload)
    return [normalize_message(item) for item in messages]


def _raw_rx_status_from_result(result: CoapResult) -> RawRxStatus:
    state = (
        RawDiagnosticState.UNSUPPORTED
        if result.code in RAW_DIAGNOSTIC_UNSUPPORTED_CODES
        else RawDiagnosticState.ERROR
    )
    return RawRxStatus(
        state=state,
        raw=_map_or_empty(result.payload),
        coap_code=result.code,
        detail=_result_detail(result),
    )


def _raw_event_from_result(result: CoapResult) -> RawRxEvent:
    state = (
        RawDiagnosticState.UNSUPPORTED
        if result.code in RAW_DIAGNOSTIC_UNSUPPORTED_CODES
        else RawDiagnosticState.ERROR
    )
    return RawRxEvent(
        state=state,
        raw=_map_or_empty(result.payload),
        coap_code=result.code,
        detail=_result_detail(result),
    )


def _raw_command_result(result: CoapResult) -> RawDiagnosticResult:
    if result.is_success:
        return RawDiagnosticResult(
            state=RawDiagnosticState.OK,
            coap_code=result.code,
            payload=result.payload,
        )
    state = (
        RawDiagnosticState.UNSUPPORTED
        if result.code in RAW_DIAGNOSTIC_UNSUPPORTED_CODES
        else RawDiagnosticState.ERROR
    )
    return RawDiagnosticResult(
        state=state,
        coap_code=result.code,
        detail=_result_detail(result),
        payload=result.payload,
    )


def _payload_text(result: CoapResult) -> str:
    if isinstance(result.payload, str):
        return result.payload
    try:
        if result.raw_payload:
            return result.raw_payload.decode()
        if isinstance(result.payload, bytes):
            return result.payload.decode()
    except UnicodeDecodeError as e:
        raise LciClientError(
            f"discovery payload is not valid UTF-8: {e}",
            code=result.code,
            payload=result.payload,
        ) from e
    raise LciClientError("discovery payload is not text", code=result.code, payload=result.payload)


def _result_detail(result: CoapResult) -> str | None:
    if isinstance(result.payload, Mapping):
        detail = result.payload.get("error") or result.payload.get("detail")
        return _str_or_none(detail)
    return _str_or_none(result.payload)


def _split_link_entries(body: str) -> list[str]:
    return [entry.strip() for entry in _split_quoted(body, ",") if entry.strip()]


def _split_link_params(entry: str) -> list[str]:
    return _split_quoted(entry, ";")


def _split_quoted(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
        if char == separator and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _quoted_tokens(value: str) -> list[str]:
    stripped = value.strip()
    if stripped.startswith('"') and stripped.endswith('"'):
        stripped = stripped[1:-1]
    return [token for token in stripped.split() if token]


def _require_map(payload: Any, name: str) -> JsonMap:
    if not isinstance(payload, Mapping):
        raise LciClientError(f"{name} payload is not a map", payload=payload)
    return dict(payload)


def _map_or_none(value: Any) -> JsonMap | None:
    if isinstance(value, Mapping):
        return dict(value)
    return None


def _map_or_empty(value: Any) -> JsonMap:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _valid_receipt_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_receipt_timestamp(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    return None
