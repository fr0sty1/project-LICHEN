# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Gateway discovery protocol for multi-gateway coordination (GCP-4).

Per spec section 08-gateway-coordination.md GCP-4, gateway discovery operates
in two modes:

1. **Backbone Discovery (Primary)**: Gateways send multicast CoAP GET to
   ff02::1 for /.well-known/lichen-gw/info. Response contains gateway IID,
   capabilities, slot map, superframe time, and supported federation modes.

2. **LoRa Discovery (Fallback)**: Gateway announce frames include GATEWAY flag
   in link layer for radio-path awareness when backbone is unavailable.

CBOR Encoding:
- Uses short integer keys for constrained links
- All responses are CBOR (content-format 60)
- Gateway IID encoded as 16-byte IPv6 address bytes

SECURITY: Discovery responses reveal gateway presence and capabilities. In
open networks this is intentional. In closed networks, discovery traffic
should be OSCORE-protected per GCP-3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv6Address
from typing import Any

import cbor2


class DiscoveryError(Exception):
    """Base exception for discovery protocol errors."""


class AllocationMode(IntEnum):
    """Slot allocation mode (GCP-6.2)."""

    INTERLEAVED = 0  # Gateway N owns slots N, N+G, N+2G, ...
    CONTIGUOUS = 1  # Gateway owns sequential block of slots


class FederationMode(IntEnum):
    """Federation authentication mode (GCP-3)."""

    PSK = 0  # Pre-shared key (closed federation)
    ED25519 = 1  # Ed25519 signatures (open federation)


# CBOR map keys for gateway info (short integers for constrained links)
# Top-level keys
_KEY_IID = 1  # Gateway IPv6 address (bytes, 16)
_KEY_CAPABILITIES = 2  # Capabilities map
_KEY_SLOT_MAP = 3  # Slot allocation map
_KEY_SUPERFRAME_DURATION = 4  # Superframe duration in seconds (int)
_KEY_FEDERATION_MODES = 5  # Supported modes (array of int)
_KEY_SUPERFRAME_EPOCH = 6  # Current superframe epoch (Unix timestamp)
_KEY_TIME_SOURCE = 7  # Time source ("gps", "backbone", "local")

# Capabilities subkeys
_KEY_CAP_MAX_SLOTS = 1  # Maximum slots per superframe (int)
_KEY_CAP_GPS_SYNC = 2  # GPS time sync available (bool)
_KEY_CAP_BACKBONE_IPV6 = 3  # Backbone IPv6 connectivity (bool)
_KEY_CAP_LR_FHSS = 4  # LR-FHSS support (bool)
_KEY_CAP_CHANNELS = 5  # Number of LoRa channels (int)
_KEY_CAP_MAX_NODES = 6  # Maximum nodes supported (int)

# Slot map subkeys
_KEY_MAP_MODE = 1  # Allocation mode (AllocationMode)
_KEY_MAP_OWNED = 2  # Owned slot indices (array of int)
_KEY_MAP_GATEWAY_COUNT = 3  # Total gateways in federation (int)
_KEY_MAP_ORDINAL = 4  # This gateway's ordinal (int)
_KEY_MAP_START = 5  # Contiguous: start slot (int)
_KEY_MAP_COUNT = 6  # Contiguous: number of slots (int)

# LoRa announce frame flags (spec section 4.2)
# GATEWAY flag occupies bit 0 of the announce type field
GATEWAY_FLAG = 0x80  # High bit of type field


@dataclass(frozen=True)
class GatewayCapabilities:
    """Gateway capabilities for discovery response.

    Advertises what features this gateway supports, enabling other gateways
    to make coordination decisions (e.g., elect time master based on GPS).
    """

    max_slots: int = 60  # Slots per superframe
    gps_sync: bool = False  # GPS time sync available
    backbone_ipv6: bool = True  # Backbone connectivity
    lr_fhss: bool = False  # LR-FHSS support
    channels: int = 8  # Number of LoRa channels
    max_nodes: int = 256  # Maximum nodes supported

    def __post_init__(self) -> None:
        if not 1 <= self.max_slots <= 1000:
            raise DiscoveryError(f"max_slots out of range: {self.max_slots}")
        if not 0 <= self.channels <= 16:
            raise DiscoveryError(f"channels out of range: {self.channels}")
        if self.max_nodes < 0:
            raise DiscoveryError(f"max_nodes cannot be negative: {self.max_nodes}")

    def to_cbor_map(self) -> dict[int, Any]:
        """Encode as CBOR map with integer keys."""
        return {
            _KEY_CAP_MAX_SLOTS: self.max_slots,
            _KEY_CAP_GPS_SYNC: self.gps_sync,
            _KEY_CAP_BACKBONE_IPV6: self.backbone_ipv6,
            _KEY_CAP_LR_FHSS: self.lr_fhss,
            _KEY_CAP_CHANNELS: self.channels,
            _KEY_CAP_MAX_NODES: self.max_nodes,
        }

    @classmethod
    def from_cbor_map(cls, data: dict[int, Any]) -> GatewayCapabilities:
        """Decode from CBOR map.

        Raises:
            DiscoveryError: If required fields are missing or malformed.
        """
        try:
            return cls(
                max_slots=data.get(_KEY_CAP_MAX_SLOTS, 60),
                gps_sync=data.get(_KEY_CAP_GPS_SYNC, False),
                backbone_ipv6=data.get(_KEY_CAP_BACKBONE_IPV6, True),
                lr_fhss=data.get(_KEY_CAP_LR_FHSS, False),
                channels=data.get(_KEY_CAP_CHANNELS, 8),
                max_nodes=data.get(_KEY_CAP_MAX_NODES, 256),
            )
        except (TypeError, ValueError) as e:
            raise DiscoveryError(f"malformed capabilities: {e}") from None


@dataclass(frozen=True)
class SlotMap:
    """Slot allocation map for discovery response.

    Describes which TDMA slots this gateway owns and the overall allocation
    strategy. Used for slot conflict detection and resolution (GCP-6.3).
    """

    mode: AllocationMode = AllocationMode.INTERLEAVED
    gateway_count: int = 1  # Total gateways in federation
    ordinal: int = 0  # This gateway's ordinal (0-indexed)

    # Interleaved mode: computed owned slots
    # Contiguous mode: start slot and count
    start_slot: int | None = None  # Contiguous only
    slot_count: int | None = None  # Contiguous only

    def __post_init__(self) -> None:
        if not 0 <= self.ordinal < self.gateway_count:
            raise DiscoveryError(
                f"ordinal {self.ordinal} out of range for {self.gateway_count} gateways"
            )
        if self.gateway_count < 1:
            raise DiscoveryError(f"gateway_count must be >= 1: {self.gateway_count}")
        if self.mode == AllocationMode.CONTIGUOUS:
            if self.start_slot is None or self.slot_count is None:
                raise DiscoveryError("contiguous mode requires start_slot and slot_count")
            if self.start_slot < 0:
                raise DiscoveryError(f"start_slot cannot be negative: {self.start_slot}")
            if self.slot_count < 0:
                raise DiscoveryError(f"slot_count cannot be negative: {self.slot_count}")

    def owned_slots(self, max_slots: int = 60) -> list[int]:
        """Return list of slot indices owned by this gateway.

        Args:
            max_slots: Total slots in superframe (default 60).

        Returns:
            Sorted list of owned slot indices.
        """
        if self.mode == AllocationMode.INTERLEAVED:
            # Gateway with ordinal N owns slots N, N+G, N+2G, ...
            return list(range(self.ordinal, max_slots, self.gateway_count))
        else:
            # Contiguous block
            if self.start_slot is None or self.slot_count is None:
                return []
            return list(range(self.start_slot, self.start_slot + self.slot_count))

    def to_cbor_map(self, max_slots: int = 60) -> dict[int, Any]:
        """Encode as CBOR map with integer keys."""
        result: dict[int, Any] = {
            _KEY_MAP_MODE: int(self.mode),
            _KEY_MAP_GATEWAY_COUNT: self.gateway_count,
            _KEY_MAP_ORDINAL: self.ordinal,
            _KEY_MAP_OWNED: self.owned_slots(max_slots),
        }
        if self.mode == AllocationMode.CONTIGUOUS:
            result[_KEY_MAP_START] = self.start_slot
            result[_KEY_MAP_COUNT] = self.slot_count
        return result

    @classmethod
    def from_cbor_map(cls, data: dict[int, Any]) -> SlotMap:
        """Decode from CBOR map.

        Raises:
            DiscoveryError: If required fields are missing or malformed.
        """
        try:
            mode = AllocationMode(data.get(_KEY_MAP_MODE, 0))
            return cls(
                mode=mode,
                gateway_count=data.get(_KEY_MAP_GATEWAY_COUNT, 1),
                ordinal=data.get(_KEY_MAP_ORDINAL, 0),
                start_slot=data.get(_KEY_MAP_START),
                slot_count=data.get(_KEY_MAP_COUNT),
            )
        except (TypeError, ValueError) as e:
            raise DiscoveryError(f"malformed slot map: {e}") from None


@dataclass
class GatewayInfo:
    """Gateway info response for /.well-known/lichen-gw/info.

    This is the primary discovery response payload. Gateways multicast
    this periodically and on-change via CoAP Observe.
    """

    iid: IPv6Address  # Gateway's IPv6 address (link-local or global)
    capabilities: GatewayCapabilities = field(default_factory=GatewayCapabilities)
    slot_map: SlotMap = field(default_factory=SlotMap)
    superframe_duration_s: int = 60  # Superframe length in seconds
    federation_modes: tuple[FederationMode, ...] = (
        FederationMode.PSK,
        FederationMode.ED25519,
    )
    superframe_epoch: int | None = None  # Unix timestamp of current superframe start
    time_source: str = "local"  # "gps", "backbone", or "local"

    def __post_init__(self) -> None:
        if self.superframe_duration_s < 1:
            raise DiscoveryError(
                f"superframe_duration_s must be >= 1: {self.superframe_duration_s}"
            )
        if not self.federation_modes:
            raise DiscoveryError("at least one federation mode required")
        if self.time_source not in ("gps", "backbone", "local"):
            raise DiscoveryError(f"invalid time_source: {self.time_source}")

    def encode(self) -> bytes:
        """Encode as CBOR for transmission."""
        data: dict[int, Any] = {
            _KEY_IID: self.iid.packed,
            _KEY_CAPABILITIES: self.capabilities.to_cbor_map(),
            _KEY_SLOT_MAP: self.slot_map.to_cbor_map(self.capabilities.max_slots),
            _KEY_SUPERFRAME_DURATION: self.superframe_duration_s,
            _KEY_FEDERATION_MODES: [int(m) for m in self.federation_modes],
            _KEY_TIME_SOURCE: self.time_source,
        }
        if self.superframe_epoch is not None:
            data[_KEY_SUPERFRAME_EPOCH] = self.superframe_epoch
        return cbor2.dumps(data)

    @classmethod
    def decode(cls, payload: bytes) -> GatewayInfo:
        """Decode from CBOR payload.

        Raises:
            DiscoveryError: If payload is malformed.
        """
        try:
            data = cbor2.loads(payload)
        except (cbor2.CBORDecodeError, OverflowError):
            raise DiscoveryError("invalid CBOR") from None

        if not isinstance(data, dict):
            raise DiscoveryError("expected CBOR map")

        try:
            iid = IPv6Address(data[_KEY_IID])
        except (KeyError, ValueError):
            raise DiscoveryError("missing or invalid gateway IID") from None

        capabilities = GatewayCapabilities()
        if _KEY_CAPABILITIES in data:
            capabilities = GatewayCapabilities.from_cbor_map(data[_KEY_CAPABILITIES])

        slot_map = SlotMap()
        if _KEY_SLOT_MAP in data:
            slot_map = SlotMap.from_cbor_map(data[_KEY_SLOT_MAP])

        superframe_duration = data.get(_KEY_SUPERFRAME_DURATION, 60)
        if not isinstance(superframe_duration, int) or superframe_duration < 1:
            raise DiscoveryError("invalid superframe_duration")

        modes_raw = data.get(_KEY_FEDERATION_MODES, [0, 1])
        try:
            modes = tuple(FederationMode(m) for m in modes_raw)
        except (TypeError, ValueError):
            raise DiscoveryError("invalid federation_modes") from None

        superframe_epoch = data.get(_KEY_SUPERFRAME_EPOCH)
        if superframe_epoch is not None and not isinstance(superframe_epoch, int):
            raise DiscoveryError("superframe_epoch must be integer")

        time_source = data.get(_KEY_TIME_SOURCE, "local")
        if not isinstance(time_source, str):
            raise DiscoveryError("time_source must be string")

        return cls(
            iid=iid,
            capabilities=capabilities,
            slot_map=slot_map,
            superframe_duration_s=superframe_duration,
            federation_modes=modes,
            superframe_epoch=superframe_epoch,
            time_source=time_source,
        )


@dataclass(frozen=True)
class LoRaGatewayAnnounce:
    """LoRa-side gateway announce with GATEWAY flag (GCP-4.2 fallback).

    When backbone discovery is unavailable, gateways announce on LoRa with
    a GATEWAY flag set in the frame type byte. This enables radio-path
    awareness between gateways.

    Wire format (compact for LoRa):
        TYPE[1] + IID_SHORT[4] + EPOCH[4] + CHANNEL[1] = 10 bytes

    TYPE byte: 0x01 (announce) | 0x80 (GATEWAY flag) = 0x81
    IID_SHORT: Last 4 bytes of gateway IID (for identification)
    EPOCH: Unix timestamp of superframe start
    CHANNEL: Current channel ID (0-15)
    """

    iid_short: bytes  # 4 bytes: last 4 bytes of gateway IID
    superframe_epoch: int  # Unix timestamp
    channel_id: int  # 0-15

    def __post_init__(self) -> None:
        if len(self.iid_short) != 4:
            raise DiscoveryError(f"iid_short must be 4 bytes, got {len(self.iid_short)}")
        if not 0 <= self.channel_id <= 15:
            raise DiscoveryError(f"channel_id out of range: {self.channel_id}")
        if self.superframe_epoch < 0:
            raise DiscoveryError("superframe_epoch cannot be negative")

    @classmethod
    def from_gateway_iid(
        cls,
        iid: IPv6Address,
        superframe_epoch: int,
        channel_id: int,
    ) -> LoRaGatewayAnnounce:
        """Create from full gateway IID (extracts last 4 bytes)."""
        packed = iid.packed
        return cls(
            iid_short=packed[-4:],
            superframe_epoch=superframe_epoch,
            channel_id=channel_id,
        )

    def encode(self) -> bytes:
        """Encode for LoRa transmission.

        Returns:
            10-byte wire format with GATEWAY flag set.
        """
        # Type byte: announce (0x01) | GATEWAY flag (0x80)
        type_byte = 0x01 | GATEWAY_FLAG
        return (
            bytes([type_byte])
            + self.iid_short
            + self.superframe_epoch.to_bytes(4, "big")
            + bytes([self.channel_id])
        )

    @classmethod
    def decode(cls, payload: bytes) -> LoRaGatewayAnnounce:
        """Decode from LoRa payload.

        Raises:
            DiscoveryError: If payload is malformed or GATEWAY flag not set.
        """
        if len(payload) < 10:
            raise DiscoveryError(f"payload too short: {len(payload)} bytes, need 10")

        type_byte = payload[0]
        if not (type_byte & GATEWAY_FLAG):
            raise DiscoveryError("GATEWAY flag not set in type byte")

        # Mask out GATEWAY flag to check base type
        base_type = type_byte & ~GATEWAY_FLAG
        if base_type != 0x01:
            raise DiscoveryError(f"unexpected base type: {base_type:#04x}")

        iid_short = payload[1:5]
        superframe_epoch = int.from_bytes(payload[5:9], "big")
        channel_id = payload[9]

        return cls(
            iid_short=iid_short,
            superframe_epoch=superframe_epoch,
            channel_id=channel_id,
        )

    @staticmethod
    def is_gateway_announce(payload: bytes) -> bool:
        """Check if payload is a gateway announce (GATEWAY flag set)."""
        if len(payload) < 1:
            return False
        return bool(payload[0] & GATEWAY_FLAG)


def iid_compare(a: IPv6Address, b: IPv6Address) -> int:
    """Compare two gateway IIDs for conflict resolution.

    Per GCP-6.3, the gateway with the lower IID wins slot conflicts.
    This function returns:
        -1 if a < b (a wins)
         0 if a == b
         1 if a > b (b wins)

    The comparison is lexicographic on the 16-byte packed representation.
    """
    a_packed = a.packed
    b_packed = b.packed
    if a_packed < b_packed:
        return -1
    elif a_packed > b_packed:
        return 1
    return 0


def elect_time_master(candidates: list[tuple[IPv6Address, bool]]) -> IPv6Address | None:
    """Elect time master from candidate gateways.

    Per GCP-6.1, GPS-equipped gateways take precedence. Among gateways
    with equal GPS status, lowest IID wins.

    Args:
        candidates: List of (iid, has_gps) tuples.

    Returns:
        IID of elected time master, or None if no candidates.
    """
    if not candidates:
        return None

    # Sort by: GPS availability (True first), then IID (lowest first)
    # GPS True = 0, GPS False = 1 (so True sorts first)
    sorted_candidates = sorted(candidates, key=lambda x: (not x[1], x[0].packed))
    return sorted_candidates[0][0]
