# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Deterministic tests for the bless native-LCI peripheral binding."""

from __future__ import annotations

from enum import Flag
from types import SimpleNamespace
from typing import Any

import pytest

from lichen.client.ble import (
    LICHEN_LCI_CAPABILITY_SLIP_IPV6,
    LICHEN_LCI_PROFILE,
    LICHEN_LCI_VERSION,
)
from lichen.gateway import ble_lci
from lichen.gateway.ble_lci import (
    MAX_IPV6_PACKET_SIZE,
    BleGattServerError,
    BlessLciGattServer,
)
from lichen.slip.codec import encode


class Properties(Flag):
    read = 0x02
    write_without_response = 0x04
    write = 0x08
    notify = 0x10


class Permissions(Flag):
    readable = 0x01
    writeable = 0x02


class FakeCharacteristic:
    def __init__(self, uuid: str, value: bytearray | None) -> None:
        self.uuid = uuid
        self.value = bytearray() if value is None else value


class FakeServer:
    instances: list[FakeServer] = []
    start_result = True
    stop_result = True
    fail_add_at: int | None = None

    def __init__(self, *, name: str) -> None:
        self.name = name
        self.services: list[str] = []
        self.characteristics: dict[str, FakeCharacteristic] = {}
        self.characteristic_specs: dict[str, tuple[Properties, Permissions]] = {}
        self.read_request_func: Any = None
        self.write_request_func: Any = None
        self.started = False
        self.stopped = False
        self.update_calls: list[tuple[str, str, bytes]] = []
        self.update_result = True
        self.mtu: int | None = None
        type(self).instances.append(self)

    async def add_new_service(self, uuid: str) -> None:
        self.services.append(uuid)

    async def add_new_characteristic(
        self,
        _service_uuid: str,
        char_uuid: str,
        properties: Properties,
        value: bytearray | None,
        permissions: Permissions,
    ) -> None:
        if self.fail_add_at == len(self.characteristics):
            raise RuntimeError("add failed")
        self.characteristics[char_uuid] = FakeCharacteristic(char_uuid, value)
        self.characteristic_specs[char_uuid] = (properties, permissions)

    async def start(self) -> bool:
        self.started = True
        return self.start_result

    async def stop(self) -> bool:
        self.stopped = True
        return self.stop_result

    def get_characteristic(self, uuid: str) -> FakeCharacteristic | None:
        return self.characteristics.get(uuid)

    def update_value(self, service_uuid: str, char_uuid: str) -> bool:
        characteristic = self.characteristics[char_uuid]
        self.update_calls.append((service_uuid, char_uuid, bytes(characteristic.value)))
        return self.update_result


@pytest.fixture(autouse=True)
def reset_fake_server() -> None:
    FakeServer.instances.clear()
    FakeServer.start_result = True
    FakeServer.stop_result = True
    FakeServer.fail_add_at = None


@pytest.fixture
def backend() -> SimpleNamespace:
    return SimpleNamespace(
        BlessServer=FakeServer,
        GATTCharacteristicProperties=Properties,
        GATTAttributePermissions=Permissions,
    )


@pytest.mark.asyncio
async def test_start_registers_native_profile_and_read_values(backend: SimpleNamespace) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)

    await service.start()
    server = FakeServer.instances[-1]

    assert service.is_running
    assert server.services == [LICHEN_LCI_PROFILE.service_uuid]
    assert set(server.characteristics) == {
        LICHEN_LCI_PROFILE.rx_uuid,
        LICHEN_LCI_PROFILE.tx_uuid,
        LICHEN_LCI_PROFILE.version_uuid,
        LICHEN_LCI_PROFILE.capabilities_uuid,
    }
    assert LICHEN_LCI_PROFILE.version_uuid is not None
    assert LICHEN_LCI_PROFILE.capabilities_uuid is not None
    version = server.characteristics[LICHEN_LCI_PROFILE.version_uuid]
    capabilities = server.characteristics[LICHEN_LCI_PROFILE.capabilities_uuid]
    assert server.read_request_func(version) == bytearray(LICHEN_LCI_VERSION.to_bytes(2, "little"))
    assert server.read_request_func(capabilities) == bytearray(
        LICHEN_LCI_CAPABILITY_SLIP_IPV6.to_bytes(4, "little")
    )


@pytest.mark.asyncio
async def test_write_reassembles_packets_and_resets_oversize_input(
    backend: SimpleNamespace,
) -> None:
    received: list[bytes] = []
    service = BlessLciGattServer(received.append, backend=backend)
    await service.start()
    server = FakeServer.instances[-1]
    rx = server.characteristics[LICHEN_LCI_PROFILE.rx_uuid]

    packet = bytes(range(256)) * 5
    assert len(packet) == MAX_IPV6_PACKET_SIZE
    frame = encode(packet)
    for offset in range(0, len(frame), 17):
        server.write_request_func(rx, frame[offset : offset + 17])
    assert received == [packet]

    oversize = encode(b"x" * (MAX_IPV6_PACKET_SIZE + 1))
    for offset in range(0, len(oversize), 19):
        server.write_request_func(rx, oversize[offset : offset + 19])
    valid = encode(b"next")
    server.write_request_func(rx, valid)
    assert received == [packet, b"next"]


@pytest.mark.asyncio
async def test_notify_slip_frames_and_chunks_at_negotiated_mtu(
    backend: SimpleNamespace,
) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)
    await service.start()
    server = FakeServer.instances[-1]
    server.mtu = 9

    packet = b"a\xc0b\xdbc"
    await service.send_packet(packet)

    assert service.notification_payload_size == 6
    assert b"".join(call[2] for call in server.update_calls) == encode(packet)
    assert all(len(call[2]) <= 6 for call in server.update_calls)


@pytest.mark.asyncio
async def test_write_captures_request_mtu(backend: SimpleNamespace) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)
    await service.start()
    server = FakeServer.instances[-1]
    rx = server.characteristics[LICHEN_LCI_PROFILE.rx_uuid]

    server.write_request_func(rx, b"\xc0", SimpleNamespace(mtu=64))

    assert service.notification_payload_size == 61


@pytest.mark.asyncio
async def test_start_failure_stops_partial_backend_and_clears_state(
    backend: SimpleNamespace,
) -> None:
    FakeServer.fail_add_at = 1
    service = BlessLciGattServer(lambda _packet: None, backend=backend)

    with pytest.raises(BleGattServerError, match="start failed"):
        await service.start()

    server = FakeServer.instances[-1]
    assert server.stopped
    assert not service.is_running
    with pytest.raises(BleGattServerError, match="not running"):
        await service.send_packet(b"x")


@pytest.mark.asyncio
async def test_stop_failure_still_clears_state(backend: SimpleNamespace) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)
    await service.start()
    FakeServer.stop_result = False

    with pytest.raises(BleGattServerError, match="unsuccessful server stop"):
        await service.stop()

    assert not service.is_running
    await service.stop()


@pytest.mark.asyncio
async def test_callback_failure_is_contained_and_next_frame_works(
    backend: SimpleNamespace,
) -> None:
    calls = 0

    def on_packet(_packet: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("consumer failed")

    service = BlessLciGattServer(on_packet, backend=backend)
    await service.start()
    server = FakeServer.instances[-1]
    rx = server.characteristics[LICHEN_LCI_PROFILE.rx_uuid]

    server.write_request_func(rx, encode(b"first"))
    assert isinstance(service.last_error, BleGattServerError)
    server.write_request_func(rx, encode(b"second"))
    assert calls == 2


@pytest.mark.asyncio
async def test_optional_dependency_error_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> Any:
        raise ImportError("not installed")

    monkeypatch.setattr(ble_lci, "_import_module", missing)
    service = BlessLciGattServer(lambda _packet: None)

    with pytest.raises(BleGattServerError, match=r"install lichen\[ble\]"):
        await service.start()


@pytest.mark.asyncio
async def test_start_stop_are_idempotent(backend: SimpleNamespace) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)

    await service.start()
    await service.start()
    assert len(FakeServer.instances) == 1
    await service.stop()
    await service.stop()


@pytest.mark.asyncio
async def test_notification_failure_is_reported(backend: SimpleNamespace) -> None:
    service = BlessLciGattServer(lambda _packet: None, backend=backend)
    await service.start()
    FakeServer.instances[-1].update_result = False

    with pytest.raises(BleGattServerError, match="unsuccessful BLE notification"):
        await service.send_packet(b"packet")
