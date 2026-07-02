# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LCI CoAP client abstractions shared by native apps."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, Protocol

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
    MessageRecord,
    Neighbor,
    RadioConfig,
    Route,
    SendResult,
)

CBOR_CONTENT_FORMAT = 60


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
        """Open an Observe subscription for a resource."""


class ResourceSubscription(Protocol):
    """Handle for a CoAP Observe relationship."""

    def results(self) -> AsyncIterator[CoapResult]:
        """Yield initial and later notification responses."""

    async def close(self) -> None:
        """Cancel the Observe relationship and release resources."""


class MessageSubscription:
    """Typed message updates from an inbox Observe relationship."""

    def __init__(self, subscription: ResourceSubscription, path: str) -> None:
        self._subscription = subscription
        self._path = path

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        """Yield normalized inbox snapshots from Observe notifications."""
        return self._messages()

    async def close(self) -> None:
        """Cancel the inbox Observe relationship."""
        await self._subscription.close()

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

    async def subscribe_logs(self, path: str = "/logs") -> ResourceSubscription:
        """Start observing a log stream resource when firmware exposes one."""
        return await self._transport.observe(path)

    async def get_diagnostics(self, path: str = "/diag") -> Any:
        """Fetch a diagnostics resource payload."""
        return await self._get_payload(path)

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


def _normalize_inbox_payload(payload: Any, path: str) -> list[MessageRecord]:
    messages = payload.get("messages", []) if isinstance(payload, Mapping) else payload
    if not isinstance(messages, list):
        raise LciClientError("message inbox payload is not a list", path=path, payload=payload)
    return [normalize_message(item) for item in messages]


def _payload_text(result: CoapResult) -> str:
    if isinstance(result.payload, str):
        return result.payload
    if result.raw_payload:
        return result.raw_payload.decode()
    if isinstance(result.payload, bytes):
        return result.payload.decode()
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


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
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
