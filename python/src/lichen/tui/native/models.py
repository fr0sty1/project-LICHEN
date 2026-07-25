# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI models, protocols, and state dataclasses."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from lichen.client import (
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    Identity,
    MessageDraft,
    MessageRecord,
    Neighbor,
    RadioConfig,
    RawDiagnosticResult,
    RawRxEvent,
    RawRxStatus,
    ResourceSubscription,
    Route,
    SendResult,
)


class MessageSubscriptionLike(Protocol):
    """Subset of a typed inbox Observe subscription used by the TUI."""

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        """Yield normalized inbox snapshots."""

    async def close(self) -> None:
        """Cancel the Observe relationship."""


class RawRxSubscriptionLike(Protocol):
    """Subset of a typed raw RX Observe subscription used by the TUI."""

    def events(self) -> AsyncIterator[RawRxEvent]:
        """Yield normalized raw RX diagnostic events."""

    async def close(self) -> None:
        """Cancel the Observe relationship."""


class MessagingClient(Protocol):
    """Subset of the shared LCI client needed by the messaging screen."""

    async def inbox(self, path: str = "/msg/inbox") -> list[MessageRecord]:
        """Return normalized inbox records."""

    async def observe_inbox(self, path: str = "/msg/inbox") -> MessageSubscriptionLike:
        """Start a normalized inbox Observe subscription."""

    async def send_message(self, draft: MessageDraft, path: str = "/msg/inbox") -> SendResult:
        """Send a normalized message draft."""

    async def discover(self) -> Capabilities:
        """Discover advertised LCI resources."""

    async def get_status(self) -> DeviceStatus:
        """Return normalized device status."""

    async def get_config(self) -> ConfigSnapshot:
        """Return normalized device config."""

    async def get_radio_config(self) -> RadioConfig:
        """Return normalized radio config."""

    async def get_identity(self) -> Identity:
        """Return normalized identity."""

    async def list_neighbors(self) -> list[Neighbor]:
        """Return normalized mesh neighbors."""

    async def list_routes(self) -> list[Route]:
        """Return normalized mesh routes."""

    async def set_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Write node config values."""

    async def set_radio_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Write radio config values."""

    async def subscribe_logs(self, path: str = "/logs") -> ResourceSubscription:
        """Subscribe to log notifications."""

    async def get_diagnostics(self, path: str = "/diag") -> Any:
        """Return raw diagnostics payload."""

    async def get_raw_rx_status(self, path: str = "/diag/raw/rx") -> RawRxStatus:
        """Return optional raw RX diagnostics state."""

    async def arm_raw_rx(
        self,
        *,
        ttl_s: int,
        include_payload: bool = False,
        enabled: bool = True,
        path: str = "/diag/raw/rx",
    ) -> RawDiagnosticResult:
        """Arm optional raw RX diagnostics for a finite TTL."""

    async def send_raw_tx(
        self,
        frame: bytes | bytearray | memoryview,
        *,
        wait: bool = True,
        path: str = "/diag/raw/tx",
    ) -> RawDiagnosticResult:
        """Transmit one optional raw diagnostic frame."""

    async def observe_raw_rx_events(
        self,
        path: str = "/diag/raw/rx/events",
    ) -> RawRxSubscriptionLike:
        """Observe optional raw RX diagnostic events."""


# Import DeviceStatus here to avoid circular import issues in the Protocol
from lichen.client import DeviceStatus  # noqa: E402


class LinkMode(StrEnum):
    """Local client transport mode labels."""

    DEMO = "DEMO"
    BLE = "BLE"
    IP = "IP"


class UiState(StrEnum):
    """Compact connection/data state labels for the shell."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    SYNCED = "SYNCED"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ShellStatus:
    """Top-bar state rendered on every native TUI screen."""

    context: str = "Dashboard"
    mode: LinkMode = LinkMode.DEMO
    state: UiState = UiState.DISCONNECTED
    device: str = "--"
    battery: str = "--"
    time: str = "none"
    unread: int = 0
    target: str = "--"


ConnectionClientFactory = Callable[[LinkMode], MessagingClient | None]


@dataclass(frozen=True)
class MessagePreview:
    """One compact chat/message list row."""

    target: str
    preview: str
    age: str = "--"
    state: str = "--"
    unread: bool = False


@dataclass(frozen=True)
class MessagingState:
    """State rendered by the Chats screen."""

    messages: tuple[MessageRecord, ...] = ()
    selected: int = 0
    unread_count: int = 0
    draft_target: str = ""
    draft_body: str = ""
    last_send: SendResult | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class DashboardState:
    """State rendered by the Dashboard screen."""

    status: DeviceStatus | None = None
    config: ConfigSnapshot | None = None
    identity: Identity | None = None
    capabilities: Capabilities | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class MeshState:
    """State rendered by the Nodes and Mesh screens."""

    neighbors: tuple[Neighbor, ...] = ()
    routes: tuple[Route, ...] = ()
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class ConfigState:
    """State rendered by the Config screen."""

    config: ConfigSnapshot | None = None
    radio: RadioConfig | None = None
    identity: Identity | None = None
    pending_path: str | None = None
    pending_field: str | None = None
    pending_value: str | int | float | None = None
    last_write: str | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class LogRow:
    """One device log row."""

    level: str
    module: str
    message: str


@dataclass(frozen=True)
class LogsState:
    """State rendered by the Logs screen."""

    rows: tuple[LogRow, ...] = ()
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class DiagnosticRow:
    """One diagnostics panel row."""

    name: str
    value: str


@dataclass(frozen=True)
class DiagnosticsState:
    """State rendered by the Diagnostics screen."""

    rows: tuple[DiagnosticRow, ...] = ()
    raw_rx_status: RawRxStatus | None = None
    raw_events: tuple[RawRxEvent, ...] = ()
    raw_available: bool | None = None
    admin_enabled: bool = False
    last_raw_action: RawDiagnosticResult | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class RadioTuiState:
    """State rendered by the Radio screen.

    Shows duty cycle usage and TX queue status for RF observability.
    """

    # Duty cycle state
    duty_cycle_usage_percent: float = 0.0
    duty_cycle_remaining_ms: int = 0
    duty_cycle_time_until_refill_ms: int = 0
    duty_cycle_limit_percent: float = 1.0

    # TX queue state
    tx_queue_depth_by_priority: tuple[tuple[int, int], ...] = ()
    tx_queue_total_bytes: int = 0
    tx_queue_drain_time_ms: int = 0
    tx_queue_oldest_age_ms: int = 0

    error: str | None = None
    loading: bool = False

    @property
    def duty_cycle_usage_ratio(self) -> float:
        """Return usage as a ratio from 0.0 to 1.0+."""
        return self.duty_cycle_usage_percent / 100.0

    @property
    def is_over_limit(self) -> bool:
        """Return True if duty cycle limit has been exceeded."""
        return self.duty_cycle_usage_percent > 100.0

    @property
    def tx_queue_total_depth(self) -> int:
        """Return total packets across all priority levels."""
        return sum(depth for _, depth in self.tx_queue_depth_by_priority)


@dataclass(frozen=True)
class RFHealthState:
    """State rendered by the RF Health screen (5g8t.6).

    Shows neighbor RF metrics (success rate, duty cycle observed, cheater flags)
    and local RF stats (noise floor, channel busy, RX errors).
    """

    # Neighbors with RF health metrics
    neighbors: tuple[Neighbor, ...] = ()

    # Local RF stats
    local_rf: LocalRFStats | None = None

    error: str | None = None
    loading: bool = False

    @property
    def cheater_count(self) -> int:
        """Return count of neighbors flagged as cheaters."""
        return sum(1 for n in self.neighbors if n.is_cheater is True)

    @property
    def has_rf_data(self) -> bool:
        """Return True if any RF health data is available."""
        return bool(self.neighbors) or self.local_rf is not None


# Import LocalRFStats here for the type hint
from lichen.client import LocalRFStats  # noqa: E402


@dataclass(frozen=True)
class ConfigRow:
    """One config editor row."""

    name: str
    value: str
    status: str = "read-only"
