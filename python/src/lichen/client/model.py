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


class ReceiptStatus(StrEnum):
    """Delivery receipt status values from `/msg/ack`."""

    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class RawDiagnosticState(StrEnum):
    """Optional raw diagnostic resource state."""

    OK = "ok"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass(frozen=True)
class CoapResult:
    """A decoded CoAP response with enough detail for diagnostics.

    Special sentinel code="0.00" indicates client-side transport failure
    (see is_transport_error); never returned by node.
    """

    code: str
    payload: Any | None = None
    location_path: tuple[str, ...] = ()
    content_format: int | None = None
    raw_payload: bytes = b""

    @property
    def is_success(self) -> bool:
        """Return true for 2.xx response codes."""
        return self.code.startswith("2.")

    @property
    def is_transport_error(self) -> bool:
        """True for synthetic results from _raw_request on transport exceptions."""
        return self.code == "0.00"


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
    # RF health extensions (5g8t.2, 5g8t.4)
    success_rate_pct: float | None = None
    duty_observed_pct: float | None = None
    is_cheater: bool | None = None
    rx_count: int | None = None
    tx_count: int | None = None


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
class MessageReceipt:
    """Delivery/read/failure receipt sent to `/msg/ack`."""

    message_id: int
    status: ReceiptStatus
    ts: int

    def to_payload(self) -> JsonMap:
        """Return the CBOR map payload used by `/msg/ack`."""
        return {
            "id": self.message_id,
            "status": self.status.value,
            "ts": self.ts,
        }


@dataclass(frozen=True)
class ReceiptResult:
    """Normalized result of posting a message receipt."""

    state: DeliveryState
    coap_code: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class RawRxStatus:
    """Normalized `/diag/raw/rx` state."""

    state: RawDiagnosticState
    raw: JsonMap = field(default_factory=dict)
    enabled: bool | None = None
    remaining_s: int | None = None
    max_ttl_s: int | None = None
    coap_code: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class RawRxEvent:
    """One normalized `/diag/raw/rx/events` notification."""

    state: RawDiagnosticState
    raw: JsonMap = field(default_factory=dict)
    frame: bytes | None = None
    rssi_dbm: float | None = None
    snr_db: float | None = None
    freq_hz: int | None = None
    crc_ok: bool | None = None
    uptime_ms: int | None = None
    coap_code: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class RawDiagnosticResult:
    """Result for raw diagnostic commands that do not return a typed body."""

    state: RawDiagnosticState
    coap_code: str | None = None
    detail: str | None = None
    payload: Any | None = None


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


@dataclass(frozen=True)
class TxQueueState:
    """TX queue observability state for UI display.

    Provides queue depth by priority level, total bytes queued,
    estimated drain time, and age of oldest queued packet.
    """

    depth_by_priority: dict[int, int] = field(default_factory=dict)
    total_bytes: int = 0
    estimated_drain_time_ms: int = 0
    oldest_age_ms: int = 0

    @property
    def total_depth(self) -> int:
        """Return total packets across all priority levels."""
        return sum(self.depth_by_priority.values())


@dataclass(frozen=True)
class DutyCycleState:
    """Duty cycle tracking state for UI display.

    Provides usage percentage, remaining budget, and time until
    budget begins to refill.
    """

    usage_percent: float = 0.0
    remaining_ms: int = 0
    time_until_refill_ms: int = 0
    limit_percent: float = 1.0
    window_seconds: int = 3600

    @property
    def usage_ratio(self) -> float:
        """Return usage as a ratio from 0.0 to 1.0+."""
        return self.usage_percent / 100.0

    @property
    def is_over_limit(self) -> bool:
        """Return True if duty cycle limit has been exceeded."""
        return self.usage_percent > 100.0


@dataclass(frozen=True)
class LocalRFStats:
    """Local RF health metrics for the RF tab (5g8t.4).

    Provides noise floor, channel busy percentage, and RX error counts
    tracked locally from radio observations.
    """

    noise_floor_dbm: float | None = None
    channel_busy_pct: float | None = None
    rx_crc_errors: int = 0
    rx_timeout_errors: int = 0
    rx_header_errors: int = 0
    rx_total: int = 0

    @property
    def rx_error_rate_pct(self) -> float | None:
        """Return overall RX error rate as percentage, or None if no data."""
        if self.rx_total == 0:
            return None
        total_errors = self.rx_crc_errors + self.rx_timeout_errors + self.rx_header_errors
        return (total_errors / self.rx_total) * 100.0


@dataclass(frozen=True)
class RadioState:
    """Combined radio observability state for UI display.

    Aggregates duty cycle and TX queue state for the Radio tab.
    """

    duty_cycle: DutyCycleState = field(default_factory=DutyCycleState)
    tx_queue: TxQueueState = field(default_factory=TxQueueState)
    local_rf: LocalRFStats = field(default_factory=LocalRFStats)
    error: str | None = None
    loading: bool = False
