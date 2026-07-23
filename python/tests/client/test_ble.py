# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for BLE LCI packet transport."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from lichen.client.ble import (
    LICHEN_LCI_CAPABILITY_SLIP_IPV6,
    LICHEN_LCI_PROFILE,
    LICHEN_LCI_VERSION,
    NUS_LCI_PROFILE,
    BlePacketTransport,
    BleTransportError,
    discover_lci_devices,
    read_lci_metadata,
)
from lichen.slip.codec import encode


class FakeBleClient:
    def __init__(
        self,
        address: str,
        *,
        mtu_size: int = 23,
        max_write_size: int | None = None,
        fail_connect: bool = False,
        fail_notify: bool = False,
        fail_write: bool = False,
        reads: dict[str, bytes] | None = None,
    ) -> None:
        self.address = address
        self.mtu_size = mtu_size
        self.services = FakeServices(max_write_size)
        self.fail_connect = fail_connect
        self.fail_notify = fail_notify
        self.fail_write = fail_write
        self.connected = False
        self.notify_uuid: str | None = None
        self.notify_callback: Callable[[str, bytearray], None] | None = None
        self.writes: list[tuple[str, bytes, bool]] = []
        self.reads = reads or {
            LICHEN_LCI_PROFILE.version_uuid or "": LICHEN_LCI_VERSION.to_bytes(2, "little"),
            LICHEN_LCI_PROFILE.capabilities_uuid or "": LICHEN_LCI_CAPABILITY_SLIP_IPV6.to_bytes(
                4, "little"
            ),
        }
        self.read_calls: list[str] = []
        self.stop_notify_calls: list[str] = []

    async def connect(self) -> bool:
        if self.fail_connect:
            raise TimeoutError("scan timeout")
        self.connected = True
        return True

    async def disconnect(self) -> bool:
        self.connected = False
        return True

    async def start_notify(
        self,
        char_specifier: str,
        callback: Callable[[str, bytearray], None],
    ) -> None:
        if self.fail_notify:
            raise TimeoutError("notify timeout")
        self.notify_uuid = char_specifier
        self.notify_callback = callback

    async def stop_notify(self, char_specifier: str) -> None:
        self.stop_notify_calls.append(char_specifier)

    async def write_gatt_char(
        self,
        char_specifier: str,
        data: bytes,
        *,
        response: bool,
    ) -> None:
        if self.fail_write:
            raise TimeoutError("write timeout")
        self.writes.append((char_specifier, data, response))

    async def read_gatt_char(self, char_specifier: str) -> bytes:
        self.read_calls.append(char_specifier)
        return self.reads[char_specifier]

    def notify(self, data: bytes) -> None:
        assert self.notify_callback is not None
        self.notify_callback(self.notify_uuid or "", bytearray(data))


class FakeCharacteristic:
    def __init__(self, max_write_without_response_size: int | None) -> None:
        self.max_write_without_response_size = max_write_without_response_size


class FakeServices:
    def __init__(self, max_write_size: int | None) -> None:
        self._max_write_size = max_write_size

    def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
        return FakeCharacteristic(self._max_write_size)


@dataclass
class FakeDevice:
    address: str
    name: str
    metadata: dict[str, list[str]]
    rssi: int


@dataclass
class FakeAdvertisement:
    service_uuids: list[str]
    rssi: int
    local_name: str | None = None


class FakeScanner:
    devices: list[FakeDevice] = []
    fail_discover = False
    return_advertisements = False

    @staticmethod
    async def discover(*, timeout: float, return_adv: bool = False) -> object:
        assert timeout > 0
        if FakeScanner.fail_discover:
            raise TimeoutError("adapter unavailable")
        if return_adv and FakeScanner.return_advertisements:
            return {
                device.address: (
                    device,
                    FakeAdvertisement(
                        service_uuids=device.metadata.get("uuids", []),
                        rssi=device.rssi,
                        local_name=device.metadata.get("local_name", [device.name])[0],
                    ),
                )
                for device in FakeScanner.devices
            }
        return FakeScanner.devices


async def test_ble_transport_connects_and_subscribes_to_lci_tx() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()

    assert transport.is_connected
    assert client.connected
    assert client.notify_uuid == LICHEN_LCI_PROFILE.tx_uuid
    assert client.read_calls == [
        LICHEN_LCI_PROFILE.version_uuid,
        LICHEN_LCI_PROFILE.capabilities_uuid,
    ]
    assert transport.metadata.protocol_version == LICHEN_LCI_VERSION
    assert transport.metadata.capabilities == LICHEN_LCI_CAPABILITY_SLIP_IPV6


async def test_ble_transport_writes_slip_chunks_to_lci_rx() -> None:
    client = FakeBleClient("AA:BB", mtu_size=8, max_write_size=None)
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    await transport.send_packet(b"abcdef")

    chunks = [write[1] for write in client.writes]
    assert [write[0] for write in client.writes] == [LICHEN_LCI_PROFILE.rx_uuid] * len(chunks)
    assert all(write[2] is False for write in client.writes)
    assert b"".join(chunks) == encode(b"abcdef")
    assert all(len(chunk) <= 5 for chunk in chunks)


async def test_ble_transport_prefers_characteristic_write_size() -> None:
    client = FakeBleClient("AA:BB", mtu_size=23, max_write_size=7)
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    await transport.send_packet(b"abcdefghi")

    assert all(len(write[1]) <= 7 for write in client.writes)


async def test_ble_transport_decodes_notification_stream() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    packets = transport.packets()
    client.notify(encode(b"one")[:3])
    client.notify(encode(b"one")[3:] + encode(b"two"))

    assert await asyncio.wait_for(anext(packets), timeout=1.0) == b"one"
    assert await asyncio.wait_for(anext(packets), timeout=1.0) == b"two"


async def test_ble_transport_close_stops_notify_and_disconnects() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    await transport.close()

    assert not transport.is_connected
    assert not client.connected
    assert client.stop_notify_calls == [LICHEN_LCI_PROFILE.tx_uuid]


async def test_ble_transport_disconnect_callback_wakes_packet_iterator() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    packets = transport.packets()
    transport._on_disconnect(client)

    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(packets), timeout=1.0)
    assert not transport.is_connected


async def test_ble_transport_custom_factory_receives_disconnect_callback() -> None:
    """Verify that custom client factories receive the disconnect callback."""
    client = FakeBleClient("AA:BB")
    captured_callback: list[Callable[[object], None]] = []

    def factory(address: str, disconnect_cb: Callable[[object], None]) -> FakeBleClient:
        captured_callback.append(disconnect_cb)
        return client

    transport = BlePacketTransport("AA:BB", client_factory=factory)

    await transport.connect()
    packets = transport.packets()

    # The factory should have received the disconnect callback
    assert len(captured_callback) == 1
    assert callable(captured_callback[0])

    # Simulating external disconnect via the callback should terminate the iterator
    captured_callback[0](client)

    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(anext(packets), timeout=1.0)
    assert not transport.is_connected


async def test_ble_transport_reconnect_resets_packet_queue() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport("AA:BB", client_factory=lambda _a, _c: client)

    await transport.connect()
    await transport.close()
    await transport.connect()
    packets = transport.packets()
    client.notify(encode(b"fresh"))

    assert await asyncio.wait_for(anext(packets), timeout=1.0) == b"fresh"


def test_ble_transport_rejects_negative_reconnect_attempts() -> None:
    with pytest.raises(ValueError, match="reconnect_attempts must be non-negative"):
        BlePacketTransport("AA:BB", reconnect_attempts=-1)


async def test_ble_transport_raises_on_send_before_connect() -> None:
    transport = BlePacketTransport(
        "AA:BB", client_factory=lambda _a, _c: FakeBleClient("AA:BB")
    )

    with pytest.raises(BleTransportError, match="not connected"):
        await transport.send_packet(b"packet")


async def test_ble_transport_reports_connect_failures() -> None:
    transport = BlePacketTransport(
        "AA:BB",
        client_factory=lambda _a, _c: FakeBleClient("AA:BB", fail_connect=True),
        timeout_s=0.1,
    )

    with pytest.raises(BleTransportError, match="connect failed"):
        await transport.connect()


async def test_ble_transport_disconnects_when_notify_subscription_fails() -> None:
    client = FakeBleClient("AA:BB", fail_notify=True)
    transport = BlePacketTransport(
        "AA:BB", client_factory=lambda _a, _c: client, timeout_s=0.1
    )

    with pytest.raises(BleTransportError, match="connect failed"):
        await transport.connect()

    assert not client.connected
    assert not transport.is_connected


async def test_ble_transport_wraps_write_failures() -> None:
    client = FakeBleClient("AA:BB", fail_write=True)
    transport = BlePacketTransport(
        "AA:BB", client_factory=lambda _a, _c: client, timeout_s=0.1
    )

    await transport.connect()

    with pytest.raises(BleTransportError, match="BLE write failed"):
        await transport.send_packet(b"packet")


async def test_ble_transport_rejects_bad_lci_metadata_lengths() -> None:
    client = FakeBleClient(
        "AA:BB",
        reads={
            LICHEN_LCI_PROFILE.version_uuid or "": b"\x01",
            LICHEN_LCI_PROFILE.capabilities_uuid or "": b"\x01\x00\x00\x00",
        },
    )
    transport = BlePacketTransport(
        "AA:BB", client_factory=lambda _a, _c: client, timeout_s=0.1
    )

    with pytest.raises(BleTransportError, match="protocol version must be two octets"):
        await transport.connect()

    assert not transport.is_connected
    assert not client.connected


async def test_ble_transport_rejects_bad_lci_capabilities_length() -> None:
    client = FakeBleClient(
        "AA:BB",
        reads={
            LICHEN_LCI_PROFILE.version_uuid or "": b"\x01\x00",
            LICHEN_LCI_PROFILE.capabilities_uuid or "": b"\x01\x00\x00",
        },
    )
    transport = BlePacketTransport(
        "AA:BB", client_factory=lambda _a, _c: client, timeout_s=0.1
    )

    with pytest.raises(BleTransportError, match="capabilities must be four octets"):
        await transport.connect()

    assert not transport.is_connected
    assert not client.connected


async def test_read_lci_metadata_returns_empty_for_legacy_nus() -> None:
    client = FakeBleClient("AA:BB")

    metadata = await read_lci_metadata(client, NUS_LCI_PROFILE, timeout_s=0.1)

    assert metadata.protocol_version is None
    assert metadata.capabilities is None
    assert client.read_calls == []


async def test_ble_transport_skips_lci_metadata_reads_for_legacy_nus() -> None:
    client = FakeBleClient("AA:BB")
    transport = BlePacketTransport(
        "AA:BB",
        profile=NUS_LCI_PROFILE,
        client_factory=lambda _a, _c: client,
    )

    await transport.connect()

    assert client.notify_uuid == NUS_LCI_PROFILE.tx_uuid
    assert client.read_calls == []
    assert transport.metadata.protocol_version is None
    assert transport.metadata.capabilities is None


async def test_discover_lci_devices_defaults_to_native_lci_profile() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = False
    FakeScanner.devices = [
        FakeDevice(
            address="AA:01",
            name="LICHEN",
            metadata={"uuids": [LICHEN_LCI_PROFILE.service_uuid.upper()]},
            rssi=-45,
        ),
        FakeDevice(
            address="AA:02",
            name="legacy",
            metadata={"uuids": [NUS_LCI_PROFILE.service_uuid]},
            rssi=-60,
        ),
        FakeDevice(address="AA:03", name="other", metadata={"uuids": []}, rssi=-70),
    ]

    candidates = await discover_lci_devices(scanner=FakeScanner, timeout_s=0.1)

    rows = [(item.address, item.name, item.profile.service_uuid, item.rssi) for item in candidates]
    assert rows == [("AA:01", "LICHEN", LICHEN_LCI_PROFILE.service_uuid, -45)]


async def test_discover_lci_devices_prefers_native_lci_before_legacy_nus() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = False
    FakeScanner.devices = [
        FakeDevice(
            address="AA:01",
            name="dual-mode",
            metadata={"uuids": [NUS_LCI_PROFILE.service_uuid, LICHEN_LCI_PROFILE.service_uuid]},
            rssi=-40,
        )
    ]

    candidates = await discover_lci_devices(
        scanner=FakeScanner,
        timeout_s=0.1,
        profiles=(LICHEN_LCI_PROFILE, NUS_LCI_PROFILE),
    )

    assert [(item.address, item.profile) for item in candidates] == [("AA:01", LICHEN_LCI_PROFILE)]


async def test_discover_lci_devices_uses_bleak_advertisement_data() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = True
    FakeScanner.devices = [
        FakeDevice(
            address="AA:01",
            name="LICHEN",
            metadata={"uuids": [LICHEN_LCI_PROFILE.service_uuid]},
            rssi=-42,
        )
    ]

    candidates = await discover_lci_devices(scanner=FakeScanner, timeout_s=0.1)

    assert [(item.address, item.rssi) for item in candidates] == [("AA:01", -42)]
    FakeScanner.return_advertisements = False


async def test_discover_lci_devices_supports_explicit_legacy_nus_profile() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = False
    FakeScanner.devices = [
        FakeDevice(
            address="AA:02",
            name="legacy",
            metadata={"uuids": [NUS_LCI_PROFILE.service_uuid]},
            rssi=-60,
        ),
    ]

    candidates = await discover_lci_devices(
        scanner=FakeScanner,
        timeout_s=0.1,
        profiles=(NUS_LCI_PROFILE,),
    )

    rows = [(item.address, item.name, item.profile.service_uuid, item.rssi) for item in candidates]
    assert rows == [
        ("AA:02", "legacy", NUS_LCI_PROFILE.service_uuid, -60),
    ]


async def test_discover_lci_devices_skips_nus_when_meshcore_is_advertised() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = False
    FakeScanner.devices = [
        FakeDevice(
            address="AA:02",
            name="MeshCore-LICHEN",
            metadata={"uuids": [NUS_LCI_PROFILE.service_uuid]},
            rssi=-60,
        ),
    ]

    candidates = await discover_lci_devices(
        scanner=FakeScanner,
        timeout_s=0.1,
        profiles=(NUS_LCI_PROFILE,),
    )

    assert candidates == []


async def test_discover_lci_devices_skips_nus_when_meshcore_local_name_is_advertised() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = True
    FakeScanner.devices = [
        FakeDevice(
            address="AA:02",
            name="legacy",
            metadata={
                "uuids": [NUS_LCI_PROFILE.service_uuid],
                "local_name": ["MeshCore-LICHEN"],
            },
            rssi=-60,
        ),
    ]

    candidates = await discover_lci_devices(
        scanner=FakeScanner,
        timeout_s=0.1,
        profiles=(NUS_LCI_PROFILE,),
    )

    assert candidates == []
    FakeScanner.return_advertisements = False


async def test_discover_lci_devices_skips_nus_when_meshcore_metadata_name_is_list() -> None:
    FakeScanner.fail_discover = False
    FakeScanner.return_advertisements = False
    FakeScanner.devices = [
        FakeDevice(
            address="AA:02",
            name="legacy",
            metadata={
                "uuids": [NUS_LCI_PROFILE.service_uuid],
                "local_name": ["MeshCore-LICHEN"],
            },
            rssi=-60,
        ),
    ]

    candidates = await discover_lci_devices(
        scanner=FakeScanner,
        timeout_s=0.1,
        profiles=(NUS_LCI_PROFILE,),
    )

    assert candidates == []


async def test_discover_lci_devices_wraps_scanner_failures() -> None:
    FakeScanner.fail_discover = True

    with pytest.raises(BleTransportError, match="BLE discovery failed"):
        await discover_lci_devices(scanner=FakeScanner, timeout_s=0.1)

    FakeScanner.fail_discover = False
