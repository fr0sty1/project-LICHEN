# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""BLE packet transport for native LCI SLIP-over-GATT links."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Protocol, cast

from lichen.slip.codec import StreamDecoder, encode

DEFAULT_ATT_PAYLOAD = 20
LICHEN_LCI_VERSION = 1
LICHEN_LCI_CAPABILITY_SLIP_IPV6 = 1 << 0


class BleTransportError(RuntimeError):
    """BLE transport setup or I/O failure."""


@dataclass(frozen=True)
class BleLciProfile:
    """BLE service and characteristic UUIDs for an LCI packet stream."""

    service_uuid: str
    rx_uuid: str
    tx_uuid: str
    version_uuid: str | None = None
    capabilities_uuid: str | None = None


LICHEN_LCI_PROFILE = BleLciProfile(
    service_uuid="e665960c-7c84-5606-a8d3-884507d0b7a8",
    rx_uuid="5e6e304a-29af-52d9-a813-306f0f888586",
    tx_uuid="be4d4a23-876b-592b-b252-440367e18e43",
    version_uuid="9158dca0-14ea-5e1c-8580-b97e7c6381b8",
    capabilities_uuid="3d3c63f3-ce23-5451-b357-738a12c20df7",
)

NUS_LCI_PROFILE = BleLciProfile(
    service_uuid="6e400001-b5a3-f393-e0a9-e50e24dcca9e",
    rx_uuid="6e400002-b5a3-f393-e0a9-e50e24dcca9e",
    tx_uuid="6e400003-b5a3-f393-e0a9-e50e24dcca9e",
)


class BleClientLike(Protocol):
    """Subset of BleakClient used by :class:`BlePacketTransport`."""

    @property
    def mtu_size(self) -> int:
        """Return negotiated ATT MTU when the backend exposes it."""

    @property
    def services(self) -> Any:
        """Return discovered GATT services when the backend exposes them."""

    async def connect(self) -> bool | None:
        """Connect to the BLE peripheral."""

    async def disconnect(self) -> bool | None:
        """Disconnect from the BLE peripheral."""

    async def start_notify(
        self,
        char_specifier: str,
        callback: Callable[[str, bytearray], None],
    ) -> None:
        """Subscribe to GATT notifications."""

    async def stop_notify(self, char_specifier: str) -> None:
        """Unsubscribe from GATT notifications."""

    async def write_gatt_char(
        self,
        char_specifier: str,
        data: bytes,
        *,
        response: bool,
    ) -> None:
        """Write one GATT characteristic chunk."""

    async def read_gatt_char(self, char_specifier: str) -> bytes | bytearray:
        """Read one GATT characteristic value."""


class BleScannerLike(Protocol):
    """Subset of BleakScanner used by discovery helpers."""

    @staticmethod
    async def discover(*, timeout: float, return_adv: bool = False) -> Any:
        """Return BLE devices with advertisement metadata."""


# Disconnect callback signature: receives the client instance on disconnect.
BleDisconnectCallback = Callable[[Any], None]

# Client factory must accept address and disconnect callback to enable proper cleanup.
BleClientFactory = Callable[[str, BleDisconnectCallback], BleClientLike]


@dataclass(frozen=True)
class BleDeviceCandidate:
    """Discovered BLE device advertising an LCI-compatible service."""

    address: str
    name: str | None
    profile: BleLciProfile
    rssi: int | None = None


@dataclass(frozen=True)
class BleLciMetadata:
    """Client-visible metadata read from a direct native BLE LCI service."""

    protocol_version: int | None = None
    capabilities: int | None = None


class BlePacketTransport:
    """PacketTransport implementation for BLE LCI SLIP-over-GATT."""

    def __init__(
        self,
        address: str,
        *,
        profile: BleLciProfile = LICHEN_LCI_PROFILE,
        client_factory: BleClientFactory | None = None,
        write_chunk_size: int | None = None,
        timeout_s: float = 10.0,
        reconnect_attempts: int = 0,
    ) -> None:
        if reconnect_attempts < 0:
            raise ValueError("reconnect_attempts must be non-negative")
        self.address = address
        self.profile = profile
        self._client_factory = client_factory
        self._client: BleClientLike | None = None
        self._write_chunk_size = write_chunk_size
        self._timeout_s = timeout_s
        self._reconnect_attempts = reconnect_attempts
        self._rx_decoder = StreamDecoder()
        self._packets: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._connected = False
        self._notify_started = False
        self._metadata = BleLciMetadata()

    @property
    def is_connected(self) -> bool:
        """Return whether the transport believes the BLE session is open."""
        return self._connected

    @property
    def write_chunk_size(self) -> int:
        """Return current GATT write payload size."""
        if self._write_chunk_size is not None:
            return self._write_chunk_size
        if self._client is None:
            return DEFAULT_ATT_PAYLOAD
        characteristic_size = _max_write_without_response_size(self._client, self.profile.rx_uuid)
        if characteristic_size is not None:
            return characteristic_size
        mtu = getattr(self._client, "mtu_size", DEFAULT_ATT_PAYLOAD + 3)
        return max(1, int(mtu) - 3)

    @property
    def metadata(self) -> BleLciMetadata:
        """Return direct BLE LCI metadata read during connection setup."""
        return self._metadata

    async def connect(self) -> None:
        """Connect and subscribe to the TX notification characteristic."""
        last_exc: Exception | None = None
        for _ in range(self._reconnect_attempts + 1):
            try:
                await self._connect_once()
                return
            except Exception as exc:
                last_exc = exc
                await self.close()
        raise BleTransportError(f"BLE connect failed for {self.address}: {last_exc}") from last_exc

    async def close(self) -> None:
        """Stop notifications and disconnect."""
        client = self._client
        notify_started = self._notify_started
        self._connected = False
        self._notify_started = False
        if client is None:
            return
        if notify_started:
            with suppress(Exception):
                await asyncio.wait_for(
                    client.stop_notify(self.profile.tx_uuid),
                    timeout=self._timeout_s,
                )
        with suppress(Exception):
            await asyncio.wait_for(
                client.disconnect(),
                timeout=self._timeout_s,
            )
        self._client = None
        self._rx_decoder.reset()
        await self._packets.put(None)

    async def send_packet(self, packet: bytes) -> None:
        """SLIP-encode and write one IPv6 packet over the RX characteristic."""
        client = self._client
        if not self._connected or client is None:
            raise BleTransportError("BLE transport is not connected")
        frame = encode(packet)
        chunk_size = self.write_chunk_size
        try:
            for offset in range(0, len(frame), chunk_size):
                chunk = frame[offset : offset + chunk_size]
                await asyncio.wait_for(
                    client.write_gatt_char(self.profile.rx_uuid, chunk, response=False),
                    timeout=self._timeout_s,
                )
        except Exception as exc:
            raise BleTransportError(f"BLE write failed for {self.address}: {exc}") from exc

    async def packets(self) -> AsyncIterator[bytes]:
        """Yield decoded IPv6 packets received from TX notifications.

        The iterator survives reconnection. If a sentinel None is received
        from a queue no longer current (replaced by connect()), switch to
        the new queue rather than stopping.
        """
        while True:
            queue = self._packets
            packet = await queue.get()
            if packet is None:
                if queue is not self._packets:
                    continue  # reconnection: switch to new queue
                return
            yield packet

    async def _connect_once(self) -> None:
        client = self._build_client()
        self._client = client
        self._packets = asyncio.Queue()
        self._rx_decoder.reset()
        result = await asyncio.wait_for(client.connect(), timeout=self._timeout_s)
        if result is False:
            raise BleTransportError("BLE client returned unsuccessful connect")
        self._metadata = await read_lci_metadata(
            client,
            self.profile,
            timeout_s=self._timeout_s,
        )
        await asyncio.wait_for(
            client.start_notify(self.profile.tx_uuid, self._on_notify),
            timeout=self._timeout_s,
        )
        self._notify_started = True
        self._connected = True

    def _build_client(self) -> BleClientLike:
        if self._client_factory is not None:
            return self._client_factory(self.address, self._on_disconnect)
        try:
            bleak = import_module("bleak")
        except ImportError as exc:
            raise BleTransportError(
                "Bleak is required for BLE transport; install lichen[ble] or pass a client_factory"
            ) from exc
        client_cls = bleak.BleakClient
        return cast(
            BleClientLike,
            client_cls(self.address, disconnected_callback=self._on_disconnect),
        )

    def _on_notify(self, _sender: str, data: bytearray) -> None:
        for packet in self._rx_decoder.feed(bytes(data)):
            self._packets.put_nowait(packet)

    def _on_disconnect(self, _client: Any) -> None:
        self._connected = False
        self._notify_started = False
        self._packets.put_nowait(None)


async def discover_lci_devices(
    *,
    scanner: BleScannerLike | None = None,
    timeout_s: float = 5.0,
    profiles: Iterable[BleLciProfile] = (LICHEN_LCI_PROFILE,),
) -> list[BleDeviceCandidate]:
    """Discover BLE devices advertising LCI-compatible services.

    Profile order is authoritative. Keep the LICHEN-specific native LCI
    profile before legacy NUS when allowing both, and skip NUS when a device
    advertises MeshCore compatibility because MeshCore owns NUS semantics.
    """
    scanner_obj = scanner
    if scanner_obj is None:
        try:
            bleak = import_module("bleak")
        except ImportError as exc:
            raise BleTransportError(
                "Bleak is required for BLE discovery; install lichen[ble] or pass a scanner"
            ) from exc
        scanner_obj = cast(BleScannerLike, bleak.BleakScanner)

    profile_list = tuple(profiles)
    try:
        discovered = await asyncio.wait_for(
            _discover_with_advertisements(scanner_obj, timeout_s),
            timeout=timeout_s + 1.0,
        )
    except Exception as exc:
        raise BleTransportError(f"BLE discovery failed: {exc}") from exc
    candidates: list[BleDeviceCandidate] = []
    for device, advertisement in _iter_discovered(discovered):
        service_uuids = _advertised_service_uuids(device, advertisement)
        matched = next(
            (
                profile
                for profile in profile_list
                if profile.service_uuid.lower() in service_uuids
                and not (
                    profile == NUS_LCI_PROFILE
                    and _advertises_meshcore_compat(device, advertisement)
                )
            ),
            None,
        )
        if matched is None:
            continue
        candidates.append(
            BleDeviceCandidate(
                address=str(getattr(device, "address", "")),
                name=getattr(device, "name", None),
                profile=matched,
                rssi=_discovered_rssi(device, advertisement),
            )
        )
    return candidates


async def read_lci_metadata(
    client: BleClientLike,
    profile: BleLciProfile = LICHEN_LCI_PROFILE,
    *,
    timeout_s: float = 10.0,
) -> BleLciMetadata:
    """Read direct native BLE LCI version/capabilities when advertised."""
    if profile.version_uuid is None and profile.capabilities_uuid is None:
        return BleLciMetadata()

    protocol_version: int | None = None
    capabilities: int | None = None
    try:
        if profile.version_uuid is not None:
            version_raw = bytes(
                await asyncio.wait_for(
                    client.read_gatt_char(profile.version_uuid),
                    timeout=timeout_s,
                )
            )
            if len(version_raw) != 2:
                raise BleTransportError("BLE LCI protocol version must be two octets")
            protocol_version = int.from_bytes(version_raw, "little")

        if profile.capabilities_uuid is not None:
            capabilities_raw = bytes(
                await asyncio.wait_for(
                    client.read_gatt_char(profile.capabilities_uuid),
                    timeout=timeout_s,
                )
            )
            if len(capabilities_raw) != 4:
                raise BleTransportError("BLE LCI capabilities must be four octets")
            capabilities = int.from_bytes(capabilities_raw, "little")
    except BleTransportError:
        raise
    except Exception as exc:
        raise BleTransportError(f"BLE LCI metadata read failed: {exc}") from exc

    return BleLciMetadata(
        protocol_version=protocol_version,
        capabilities=capabilities,
    )


async def _discover_with_advertisements(scanner: BleScannerLike, timeout_s: float) -> Any:
    try:
        return await scanner.discover(timeout=timeout_s, return_adv=True)
    except TypeError:
        return await scanner.discover(timeout=timeout_s)


def _iter_discovered(discovered: Any) -> Iterable[tuple[Any, Any | None]]:
    if isinstance(discovered, dict):
        for item in discovered.values():
            if isinstance(item, tuple) and len(item) == 2:
                yield item
            else:
                yield item, None
        return
    for device in discovered:
        yield device, None


def _advertised_service_uuids(device: Any, advertisement: Any | None = None) -> set[str]:
    if advertisement is not None:
        raw_adv = getattr(advertisement, "service_uuids", ())
        if raw_adv:
            return {str(uuid).lower() for uuid in raw_adv}
    metadata = getattr(device, "metadata", {}) or {}
    raw = metadata.get("uuids", ())
    return {str(uuid).lower() for uuid in raw}


def _discovered_rssi(device: Any, advertisement: Any | None) -> int | None:
    if advertisement is not None:
        rssi = _int_or_none(getattr(advertisement, "rssi", None))
        if rssi is not None:
            return rssi
    return _int_or_none(getattr(device, "rssi", None))


def _advertises_meshcore_compat(device: Any, advertisement: Any | None = None) -> bool:
    names = [
        getattr(device, "name", None),
        getattr(advertisement, "local_name", None) if advertisement is not None else None,
    ]
    metadata = getattr(device, "metadata", {}) or {}
    names.extend(_metadata_values(metadata.get("local_name")))
    return any(str(name).casefold().startswith("meshcore") for name in names if name)


def _metadata_values(value: Any) -> Iterable[Any]:
    if value is None or isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return value
    return (value,)


def _max_write_without_response_size(client: BleClientLike, rx_uuid: str) -> int | None:
    services = getattr(client, "services", None)
    get_characteristic = getattr(services, "get_characteristic", None)
    if get_characteristic is None:
        return None
    characteristic = get_characteristic(rx_uuid)
    size = getattr(characteristic, "max_write_without_response_size", None)
    return _int_or_none(size)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
