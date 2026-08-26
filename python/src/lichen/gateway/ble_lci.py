# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LCI SLIP-over-GATT peripheral binding using ``bless``.

The protocol-facing client implementation lives in :mod:`lichen.client.ble`.
This module provides the matching desktop gateway/peripheral surface while
keeping ``bless`` optional and injectable for deterministic, hardware-free
tests.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from contextlib import suppress
from importlib import import_module as _import_module
from types import ModuleType
from typing import Any

from lichen.client.ble import (
    DEFAULT_ATT_PAYLOAD,
    LICHEN_LCI_CAPABILITY_SLIP_IPV6,
    LICHEN_LCI_PROFILE,
    LICHEN_LCI_VERSION,
)
from lichen.slip.codec import StreamDecoder, encode

MAX_IPV6_PACKET_SIZE = 1280
MAX_ATT_PAYLOAD = 509

log = logging.getLogger(__name__)


class BleGattServerError(RuntimeError):
    """Native BLE LCI server setup or I/O failure."""


class BlessLciGattServer:
    """Expose the native LICHEN LCI GATT profile through ``bless``.

    Args:
        on_packet: Synchronous callback for each decoded IPv6 packet.
        name: Advertised peripheral name.
        backend: Optional bless-compatible module, primarily for tests.
        att_payload_size: Fixed notification payload limit. When omitted, a
            negotiated MTU exposed by bless is used, then the 20-byte default.
    """

    def __init__(
        self,
        on_packet: Callable[[bytes], None],
        *,
        name: str = "LICHEN Gateway",
        backend: ModuleType | Any | None = None,
        att_payload_size: int | None = None,
    ) -> None:
        if att_payload_size is not None and not 1 <= att_payload_size <= MAX_ATT_PAYLOAD:
            raise ValueError(f"att_payload_size must be in 1..{MAX_ATT_PAYLOAD}")
        self.on_packet = on_packet
        self.name = name
        self._backend = backend
        self._configured_att_payload = att_payload_size
        self._observed_att_payload: int | None = None
        # max_size is the rejection threshold in StreamDecoder, so 1281
        # accepts exactly the mandatory 1280-octet IPv6 packet size.
        self._decoder = StreamDecoder(max_size=MAX_IPV6_PACKET_SIZE + 1)
        self._server: Any | None = None
        self._running = False
        self._last_error: BleGattServerError | None = None

    @property
    def is_running(self) -> bool:
        """Return whether advertising was started successfully."""
        return self._running

    @property
    def last_error(self) -> BleGattServerError | None:
        """Return the last asynchronous callback error, if any."""
        return self._last_error

    @property
    def notification_payload_size(self) -> int:
        """Return the current maximum ATT notification value size."""
        if self._configured_att_payload is not None:
            return self._configured_att_payload
        if self._observed_att_payload is not None:
            return self._observed_att_payload
        mtu = getattr(self._server, "mtu", None)
        if isinstance(mtu, int) and not isinstance(mtu, bool) and mtu >= 4:
            return min(mtu - 3, MAX_ATT_PAYLOAD)
        return DEFAULT_ATT_PAYLOAD

    async def start(self) -> None:
        """Register the native LCI service and begin advertising."""
        if self._running:
            return
        backend = self._backend if self._backend is not None else _load_bless()
        server: Any | None = None
        try:
            server = backend.BlessServer(name=self.name)
            server.read_request_func = self._read_request
            server.write_request_func = self._write_request
            await server.add_new_service(LICHEN_LCI_PROFILE.service_uuid)

            properties = backend.GATTCharacteristicProperties
            permissions = backend.GATTAttributePermissions
            writable = getattr(permissions, "writeable", None)
            if writable is None:
                writable = permissions.writable

            await server.add_new_characteristic(
                LICHEN_LCI_PROFILE.service_uuid,
                LICHEN_LCI_PROFILE.rx_uuid,
                properties.write_without_response | properties.write,
                bytearray(),
                writable,
            )
            await server.add_new_characteristic(
                LICHEN_LCI_PROFILE.service_uuid,
                LICHEN_LCI_PROFILE.tx_uuid,
                properties.notify,
                bytearray(),
                permissions.readable,
            )
            await server.add_new_characteristic(
                LICHEN_LCI_PROFILE.service_uuid,
                _required_uuid(LICHEN_LCI_PROFILE.version_uuid, "version"),
                properties.read,
                bytearray(LICHEN_LCI_VERSION.to_bytes(2, "little")),
                permissions.readable,
            )
            await server.add_new_characteristic(
                LICHEN_LCI_PROFILE.service_uuid,
                _required_uuid(LICHEN_LCI_PROFILE.capabilities_uuid, "capabilities"),
                properties.read,
                bytearray(LICHEN_LCI_CAPABILITY_SLIP_IPV6.to_bytes(4, "little")),
                permissions.readable,
            )
            started = await server.start()
            if started is False:
                raise BleGattServerError("bless reported unsuccessful server start")
        except BaseException as exc:
            if server is not None:
                with suppress(Exception, asyncio.CancelledError):
                    await server.stop()
            self._clear_session()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, BleGattServerError):
                raise
            raise BleGattServerError(f"BLE GATT server start failed: {exc}") from exc

        self._server = server
        self._running = True
        self._last_error = None
        self.reset_session()

    async def stop(self) -> None:
        """Stop advertising and discard all connection-scoped state."""
        server = self._server
        self._clear_session()
        if server is None:
            return
        try:
            stopped = await server.stop()
            if stopped is False:
                raise BleGattServerError("bless reported unsuccessful server stop")
        except asyncio.CancelledError:
            raise
        except BleGattServerError:
            raise
        except Exception as exc:
            raise BleGattServerError(f"BLE GATT server stop failed: {exc}") from exc

    def reset_session(self) -> None:
        """Reset reassembly and negotiated-MTU state at a session boundary."""
        self._decoder.reset()
        self._observed_att_payload = None
        self._last_error = None

    async def send_packet(self, packet: bytes) -> None:
        """SLIP-frame an IPv6 packet and notify it in ATT-sized chunks."""
        if not self._running or self._server is None:
            raise BleGattServerError("BLE GATT server is not running")
        if not packet or len(packet) > MAX_IPV6_PACKET_SIZE:
            raise BleGattServerError(
                f"IPv6 packet size must be in 1..{MAX_IPV6_PACKET_SIZE} octets"
            )
        characteristic = self._server.get_characteristic(LICHEN_LCI_PROFILE.tx_uuid)
        if characteristic is None:
            raise BleGattServerError("BLE TX characteristic is unavailable")

        frame = encode(packet)
        chunk_size = self.notification_payload_size
        for offset in range(0, len(frame), chunk_size):
            characteristic.value = bytearray(frame[offset : offset + chunk_size])
            try:
                updated = self._server.update_value(
                    LICHEN_LCI_PROFILE.service_uuid,
                    LICHEN_LCI_PROFILE.tx_uuid,
                )
            except Exception as exc:
                raise BleGattServerError(f"BLE notification failed: {exc}") from exc
            if updated is False:
                raise BleGattServerError("bless reported unsuccessful BLE notification")
            await asyncio.sleep(0)

    def _read_request(self, characteristic: Any, *_args: Any, **_kwargs: Any) -> bytearray:
        uuid = str(getattr(characteristic, "uuid", "")).lower()
        readable = {
            _required_uuid(LICHEN_LCI_PROFILE.version_uuid, "version"),
            _required_uuid(LICHEN_LCI_PROFILE.capabilities_uuid, "capabilities"),
        }
        if uuid not in readable:
            raise BleGattServerError(f"characteristic {uuid or '<unknown>'} is not readable")
        return bytearray(characteristic.value)

    def _write_request(
        self,
        characteristic: Any,
        value: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        uuid = str(getattr(characteristic, "uuid", "")).lower()
        if uuid != LICHEN_LCI_PROFILE.rx_uuid:
            raise BleGattServerError(f"characteristic {uuid or '<unknown>'} is not writable")
        data = bytes(value)
        characteristic.value = bytearray(data)
        self._capture_mtu(args, kwargs)
        try:
            for packet in self._decoder.feed(data):
                self.on_packet(packet)
        except Exception as exc:
            self._decoder.reset()
            self._last_error = BleGattServerError(f"BLE receive callback failed: {exc}")
            log.exception("BLE receive callback failed")

    def _capture_mtu(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        request = kwargs.get("request")
        if request is None and args:
            request = args[-1]
        mtu = getattr(request, "mtu", None)
        if isinstance(mtu, int) and not isinstance(mtu, bool) and mtu >= 4:
            self._observed_att_payload = min(mtu - 3, MAX_ATT_PAYLOAD)

    def _clear_session(self) -> None:
        self._running = False
        self._server = None
        self.reset_session()


def _load_bless() -> ModuleType:
    try:
        return _import_module("bless")
    except ImportError as exc:
        raise BleGattServerError(
            "bless is required for BLE peripheral mode; install lichen[ble] "
            "or inject a bless-compatible backend"
        ) from exc


def _required_uuid(value: str | None, name: str) -> str:
    if value is None:  # Defensive: the native profile always defines both.
        raise BleGattServerError(f"native LCI profile is missing the {name} UUID")
    return value
