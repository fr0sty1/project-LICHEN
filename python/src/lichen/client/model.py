# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Typed app-facing LCI client models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

JsonMap = dict[str, Any]


class ConnectionPhase(StrEnum):
    """Transport and LCI session phases used by native clients."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    IPV6_READY = "ipv6_ready"
    DISCOVERING = "discovering"
    SYNCING = "syncing"
    SYNCED = "synced"
    DEGRADED = "degraded"
    ERROR = "error"


class DeliveryState(StrEnum):
    """Normalized message delivery states for UI and tests."""

    DRAFT = "draft"
    VALIDATION_ERROR = "validation_error"
    POST_PENDING = "post_pending"
    ACCEPTED = "accepted"
    OBSERVED = "observed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True)
class CoapResult:
    """A decoded CoAP response with enough detail for diagnostics."""

    code: str
    payload: Any | None = None
    location_path: tuple[str, ...] = ()
    content_format: int | None = None
    raw_payload: bytes = b""

    @property
    def is_success(self) -> bool:
        """Return true for 2.xx response codes."""
        return self.code.startswith("2.")


@dataclass(frozen=True)
class Capabilities:
    """Resources and transport capabilities discovered from the node."""

    resources: frozenset[str] = frozenset()
    observable: frozenset[str] = frozenset()
    resource_types: dict[str, tuple[str, ...]] = field(default_factory=dict)
    transport: dict[str, bool] = field(default_factory=dict)

    def has(self, path: str) -> bool:
        """Return true when *path* was advertised by resource discovery."""
        return path in self.resources

    def can_observe(self, path: str) -> bool:
        """Return true when *path* advertises CoAP Observe support."""
        return path in self.observable


@dataclass(frozen=True)
class DeviceStatus:
    """Normalized `/status` payload."""

    raw: JsonMap
    uptime_s: int | None = None
    battery_pct: int | None = None
    battery_mv: int | None = None
    mem_free_kb: int | None = None
    dodag: JsonMap | None = None
    radio: JsonMap | None = None


@dataclass(frozen=True)
class Identity:
    """Normalized `/config/identity` payload."""

    raw: JsonMap
    eui64: str | None = None
    pubkey: str | None = None
    pubkey_fingerprint: str | None = None
    addrs: JsonMap | None = None


@dataclass(frozen=True)
class RadioConfig:
    """Normalized `/config/radio` payload."""

    raw: JsonMap
    freq_mhz: float | None = None
    bw_khz: int | None = None
    sf: int | None = None
    cr: str | None = None
    tx_power_dbm: int | None = None
    sync_word: str | None = None


@dataclass(frozen=True)
class ConfigSnapshot:
    """Normalized `/config` payload."""

    raw: JsonMap
    name: str | None = None
    role: str | None = None
    radio_path: str | None = None
    identity_path: str | None = None


@dataclass(frozen=True)
class Neighbor:
    """A normalized neighbor row from `/status/neighbors`."""

    raw: JsonMap
    addr: str | None = None
    iid: str | None = None
    rssi_dbm: float | None = None
    snr_db: float | None = None
    etx: float | None = None
    trust: str | None = None
    lqi: int | None = None
    last_seen_s: int | None = None


@dataclass(frozen=True)
class Route:
    """A normalized route row from `/status/routes`."""

    raw: JsonMap
    prefix: str | None = None
    via: str | None = None
    metric: int | None = None
    lifetime_s: int | None = None
    flags: int | None = None


@dataclass(frozen=True)
class MessageDraft:
    """A message the client wants to send through the discovered LCI resource."""

    to: str
    body: str
    ack: bool = False
    priority: int | None = None
    reply_to: int | None = None
    ttl: int | None = None

    def to_payload(self) -> JsonMap:
        """Return the CBOR map payload used by the CoAP messaging resources."""
        payload: JsonMap = {"to": self.to, "body": self.body, "ack": self.ack}
        if self.priority is not None:
            payload["priority"] = self.priority
        if self.reply_to is not None:
            payload["reply_to"] = self.reply_to
        if self.ttl is not None:
            payload["ttl"] = self.ttl
        return payload


@dataclass(frozen=True)
class SendResult:
    """Normalized result of a send-message attempt."""

    state: DeliveryState
    coap_code: str | None = None
    location_path: tuple[str, ...] = ()
    detail: str | None = None


@dataclass(frozen=True)
class MessageRecord:
    """A normalized message record from an inbox resource."""

    raw: JsonMap
    message_id: int | None = None
    sender: str | None = None
    recipient: str | None = None
    body: str | None = None
    received: str | None = None
    timestamp: int | float | str | None = None
