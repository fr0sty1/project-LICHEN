"""Tests for KISS BLE GATT service."""

import pytest

from lichen.interface.kiss import (
    KissCommand,
    KissHandler,
    kiss_encode,
)
from lichen.interface.kiss.gatt import (
    DEFAULT_MTU,
    MAX_MTU,
    RX_CHAR_UUID,
    SERVICE_UUID,
    TX_CHAR_UUID,
    KissGattService,
)


@pytest.fixture
def handler():
    return KissHandler()


@pytest.fixture
def service(handler):
    return KissGattService(handler=handler)


class TestGattServiceConstants:
    def test_service_uuid_format(self):
        # Should be valid UUID format
        parts = SERVICE_UUID.split("-")
        assert len(parts) == 5

    def test_characteristic_uuids(self):
        assert TX_CHAR_UUID != RX_CHAR_UUID
        assert TX_CHAR_UUID.startswith("00000002")
        assert RX_CHAR_UUID.startswith("00000003")

    def test_mtu_values(self):
        assert DEFAULT_MTU == 20
        assert MAX_MTU == 512


class TestGattServiceInit:
    def test_creates_with_handler(self, service, handler):
        assert service.handler is handler

    def test_default_mtu(self, service):
        assert service.mtu == DEFAULT_MTU

    def test_starts_not_running(self, service):
        assert not service.is_running

    def test_starts_not_connected(self, service):
        assert not service.is_connected


class TestGattServiceLifecycle:
    @pytest.mark.asyncio
    async def test_start_sets_running(self, service):
        await service.start()
        assert service.is_running
        await service.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running(self, service):
        await service.start()
        await service.stop()
        assert not service.is_running

    @pytest.mark.asyncio
    async def test_start_twice_no_error(self, service):
        await service.start()
        await service.start()  # No-op
        assert service.is_running
        await service.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start_no_error(self, service):
        await service.stop()  # No-op


class TestGattServiceConnect:
    def test_on_connect_sets_connected(self, service):
        service.on_connect()
        assert service.is_connected

    def test_on_connect_sets_mtu(self, service):
        service.on_connect(mtu=256)
        assert service.mtu == 256

    def test_on_disconnect_clears_connected(self, service):
        service.on_connect()
        service.on_disconnect()
        assert not service.is_connected

    def test_connect_clears_reader(self, service):
        # Feed partial data
        service._reader.feed(b"\xC0\x00partial")
        service.on_connect()
        # Reader should be cleared
        assert len(list(service._reader)) == 0


class TestGattServiceTxWrite:
    def test_tx_write_dispatches_to_handler(self, service, handler):
        received = []
        handler.on_tx_frame = lambda port, data: received.append((port, data))

        service.on_connect()
        frame = kiss_encode(0, KissCommand.DATA, b"hello")
        service.on_tx_write(frame)

        assert received == [(0, b"hello")]

    def test_tx_write_reassembles_split_frames(self, service, handler):
        received = []
        handler.on_tx_frame = lambda port, data: received.append((port, data))

        service.on_connect()
        frame = kiss_encode(0, KissCommand.DATA, b"split across packets")

        # Split frame into small chunks
        mid = len(frame) // 2
        service.on_tx_write(frame[:mid])
        assert received == []  # Not complete yet

        service.on_tx_write(frame[mid:])
        assert received == [(0, b"split across packets")]

    def test_tx_write_handles_multiple_frames(self, service, handler):
        received = []
        handler.on_tx_frame = lambda port, data: received.append((port, data))

        service.on_connect()
        data = kiss_encode(0, KissCommand.DATA, b"one")
        data += kiss_encode(0, KissCommand.DATA, b"two")
        service.on_tx_write(data)

        assert received == [(0, b"one"), (0, b"two")]

    def test_tx_write_while_disconnected_ignored(self, service, handler):
        received = []
        handler.on_tx_frame = lambda port, data: received.append((port, data))

        # Don't connect
        frame = kiss_encode(0, KissCommand.DATA, b"ignored")
        service.on_tx_write(frame)

        assert received == []

    def test_tx_write_return_command(self, service, handler):
        service.on_connect()
        frame = kiss_encode(0, KissCommand.RETURN, b"")
        service.on_tx_write(frame)

        assert handler.exited


class TestGattServiceRxNotify:
    @pytest.mark.asyncio
    async def test_send_frame_calls_notify(self, service):
        chunks = []
        service.on_notify = lambda data: chunks.append(data)

        service.on_connect()
        await service.send_frame(b"test")

        assert chunks == [b"test"]

    @pytest.mark.asyncio
    async def test_send_frame_splits_large_data(self, service):
        chunks = []
        service.on_notify = lambda data: chunks.append(data)

        service.on_connect(mtu=10)  # Small MTU
        data = b"x" * 25  # Larger than MTU
        await service.send_frame(data)

        assert len(chunks) == 3
        assert b"".join(chunks) == data

    @pytest.mark.asyncio
    async def test_send_frame_while_disconnected_ignored(self, service):
        chunks = []
        service.on_notify = lambda data: chunks.append(data)

        # Don't connect
        await service.send_frame(b"ignored")

        assert chunks == []

    def test_send_frame_sync_returns_chunks(self, service):
        service.on_connect(mtu=10)
        data = b"y" * 35

        chunks = service.send_frame_sync(data)

        assert len(chunks) == 4
        assert b"".join(chunks) == data

    def test_send_frame_sync_empty(self, service):
        service.on_connect(mtu=10)
        chunks = service.send_frame_sync(b"")

        assert chunks == [b""]
        assert b"".join(chunks) == b""


class TestGattServiceConfig:
    def test_config_commands_work(self, service, handler):
        service.on_connect()

        # Send config command
        frame = kiss_encode(0, KissCommand.TXDELAY, bytes([100]))
        service.on_tx_write(frame)

        assert handler.config.txdelay_ms == 100


class TestGattServiceIntegration:
    @pytest.mark.asyncio
    async def test_bidirectional_flow(self, service, handler):
        tx_received = []
        rx_sent = []

        handler.on_tx_frame = lambda port, data: tx_received.append((port, data))
        service.on_notify = lambda data: rx_sent.append(data)

        service.on_connect(mtu=100)

        # App -> Device (TX write)
        service.on_tx_write(kiss_encode(0, KissCommand.DATA, b"from app"))
        assert tx_received == [(0, b"from app")]

        # Device -> App (RX notify)
        await service.send_frame(kiss_encode(0, KissCommand.DATA, b"from device"))
        assert len(rx_sent) == 1
        assert b"from device" in rx_sent[0]

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, service, handler):
        tx_received = []
        handler.on_tx_frame = lambda port, data: tx_received.append((port, data))

        # Start service
        await service.start()
        assert service.is_running

        # Client connects
        service.on_connect(mtu=64)
        assert service.is_connected

        # Exchange frames
        service.on_tx_write(kiss_encode(0, KissCommand.DATA, b"msg1"))
        assert tx_received == [(0, b"msg1")]

        # Client disconnects
        service.on_disconnect()
        assert not service.is_connected

        # Stop service
        await service.stop()
        assert not service.is_running
