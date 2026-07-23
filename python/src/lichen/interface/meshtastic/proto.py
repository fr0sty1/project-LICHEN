# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Manual protobuf encoding/decoding for Meshtastic messages.

This module provides hand-rolled protobuf codec for the subset of Meshtastic
messages needed by the LICHEN bridge, avoiding the betterproto dependency.
Wire format follows proto3 specification.

Supported messages:
- ToRadio: want_config_id, packet, heartbeat
- FromRadio: my_info, metadata, config_complete_id, packet, queueStatus
- MeshPacket: from, to, channel, decoded/encrypted, id, etc.
- Data: portnum, payload, want_response, dest, source, request_id, etc.
- Routing: error_reason (for ACK/NAK generation)
- MyNodeInfo: my_node_num, reboot_count, min_app_version
- QueueStatus: res, free, maxlen, mesh_packet_id
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum


class ProtoError(Exception):
    """Raised when protobuf encoding/decoding fails."""


# Wire types
WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN_DELIM = 2
WIRE_FIXED32 = 5


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    if value < 0:
        # Protobuf int32/int64: sign-extend to 64 bits, encode as 10-byte varint
        value = value & 0xFFFFFFFFFFFFFFFF
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value)
    return bytes(parts) if parts else b"\x00"


def _decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a protobuf varint, return (value, new_offset)."""
    value = 0
    shift = 0
    i = offset
    while i < len(data):
        byte = data[i]
        value |= (byte & 0x7F) << shift
        i += 1
        if not (byte & 0x80):
            return value, i
        shift += 7
        if shift > 63:
            raise ProtoError("varint too long")
    raise ProtoError("truncated varint")


def _varint_to_int32(value: int) -> int:
    """Convert protobuf varint-decoded value to signed int32.

    Protobuf encodes int32 negative values as sign-extended varints
    (often 10 bytes). _decode_varint yields a large positive int; we
    reinterpret the low 32 bits as two's complement signed.

    The cf7526a change (`value & 0x80000000` vs `value > 0x7FFFFFFF`
    after the mask) was a no-op as noted in kimi-review; both are
    equivalent for values in [0, 2**32). This implementation is correct
    for rx_rssi and QueueStatus.res as verified by tests.
    """
    value = value & 0xFFFFFFFF
    if value > 0x7FFFFFFF:
        value -= 0x100000000
    return value


def _encode_tag(field_num: int, wire_type: int) -> bytes:
    """Encode a protobuf field tag."""
    return _encode_varint((field_num << 3) | wire_type)


def _decode_tag(data: bytes, offset: int) -> tuple[int, int, int]:
    """Decode a protobuf field tag, return (field_num, wire_type, new_offset)."""
    tag, new_offset = _decode_varint(data, offset)
    return tag >> 3, tag & 0x07, new_offset


def _skip_field(data: bytes, offset: int, wire_type: int) -> int:
    """Skip a field of given wire type, return new offset."""
    if wire_type == WIRE_VARINT:
        _, new_offset = _decode_varint(data, offset)
        return new_offset
    elif wire_type == WIRE_FIXED64:
        if offset + 8 > len(data):
            raise ProtoError("truncated fixed64")
        return offset + 8
    elif wire_type == WIRE_LEN_DELIM:
        length, new_offset = _decode_varint(data, offset)
        if new_offset + length > len(data):
            raise ProtoError("truncated length-delimited")
        return new_offset + length
    elif wire_type == WIRE_FIXED32:
        if offset + 4 > len(data):
            raise ProtoError("truncated fixed32")
        return offset + 4
    else:
        raise ProtoError(f"unknown wire type {wire_type}")


# =============================================================================
# Routing / ACK/NAK
# =============================================================================


class RoutingError(IntEnum):
    """Routing error codes (meshtastic.Routing.Error)."""

    NONE = 0
    NO_ROUTE = 1
    GOT_NAK = 2
    TIMEOUT = 3
    NO_INTERFACE = 4
    MAX_RETRANSMIT = 5
    NO_CHANNEL = 6
    TOO_LARGE = 7
    NO_RESPONSE = 8
    DUTY_CYCLE_LIMIT = 9
    BAD_REQUEST = 32
    NOT_AUTHORIZED = 33


@dataclass
class Routing:
    """Routing message for ACK/NAK responses."""

    error_reason: RoutingError = RoutingError.NONE
    route_request: bytes = b""
    route_reply: bytes = b""

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.error_reason != RoutingError.NONE:
            parts.append(_encode_tag(2, WIRE_VARINT))
            parts.append(_encode_varint(self.error_reason))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> Routing:
        """Decode from protobuf."""
        routing = cls()
        offset = 0
        while offset < len(data):
            field_num, wire_type, offset = _decode_tag(data, offset)
            if field_num == 2 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                try:
                    routing.error_reason = RoutingError(val)
                except ValueError:
                    # Unknown routing error code from newer Meshtastic version
                    routing.error_reason = RoutingError.NONE
            else:
                offset = _skip_field(data, offset, wire_type)
        return routing


# =============================================================================
# Data payload
# =============================================================================


@dataclass
class Data:
    """Data payload within a MeshPacket (meshtastic.Data)."""

    portnum: int = 0  # PortNum enum value
    payload: bytes = b""
    want_response: bool = False
    dest: int = 0  # fixed32
    source: int = 0  # fixed32
    request_id: int = 0  # fixed32
    reply_id: int = 0  # fixed32
    emoji: int = 0  # fixed32
    bitfield: int | None = None

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.portnum != 0:
            parts.append(_encode_tag(1, WIRE_VARINT))
            parts.append(_encode_varint(self.portnum))
        if self.payload:
            parts.append(_encode_tag(2, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.payload)))
            parts.append(self.payload)
        if self.want_response:
            parts.append(_encode_tag(3, WIRE_VARINT))
            parts.append(b"\x01")
        if self.dest != 0:
            parts.append(_encode_tag(4, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.dest))
        if self.source != 0:
            parts.append(_encode_tag(5, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.source))
        if self.request_id != 0:
            parts.append(_encode_tag(6, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.request_id))
        if self.reply_id != 0:
            parts.append(_encode_tag(7, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.reply_id))
        if self.emoji != 0:
            parts.append(_encode_tag(8, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.emoji))
        if self.bitfield is not None:
            parts.append(_encode_tag(9, WIRE_VARINT))
            parts.append(_encode_varint(self.bitfield))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> Data:
        """Decode from protobuf."""
        result = cls()
        offset = 0
        while offset < len(data):
            field_num, wire_type, offset = _decode_tag(data, offset)
            if field_num == 1 and wire_type == WIRE_VARINT:
                result.portnum, offset = _decode_varint(data, offset)
            elif field_num == 2 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                result.payload = data[offset : offset + length]
                offset += length
            elif field_num == 3 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                result.want_response = val != 0
            elif field_num == 4 and wire_type == WIRE_FIXED32:
                result.dest = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 5 and wire_type == WIRE_FIXED32:
                result.source = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 6 and wire_type == WIRE_FIXED32:
                result.request_id = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 7 and wire_type == WIRE_FIXED32:
                result.reply_id = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 8 and wire_type == WIRE_FIXED32:
                result.emoji = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 9 and wire_type == WIRE_VARINT:
                result.bitfield, offset = _decode_varint(data, offset)
            else:
                offset = _skip_field(data, offset, wire_type)
        return result


# =============================================================================
# MeshPacket
# =============================================================================


class PacketPriority(IntEnum):
    """MeshPacket priority levels."""

    UNSET = 0
    MIN = 1
    BACKGROUND = 10
    DEFAULT = 64
    RELIABLE = 70
    RESPONSE = 80
    HIGH = 100
    ALERT = 110
    ACK = 120
    MAX = 127


@dataclass
class MeshPacket:
    """Over-the-mesh packet envelope (meshtastic.MeshPacket)."""

    from_: int = 0  # fixed32 ('from' is reserved)
    to: int = 0  # fixed32
    channel: int = 0  # uint32
    # oneof payload_variant
    decoded: Data | None = None  # field 4
    encrypted: bytes | None = None  # field 5
    # Metadata
    id: int = 0  # fixed32, field 6
    rx_time: int = 0  # fixed32, field 7
    rx_snr: float = 0.0  # float, field 8
    hop_limit: int = 0  # uint32, field 9
    want_ack: bool = False  # bool, field 10
    priority: PacketPriority = PacketPriority.DEFAULT  # enum, field 11
    rx_rssi: int = 0  # int32, field 12
    via_mqtt: bool = False  # bool, field 14
    hop_start: int = 0  # uint32, field 15
    public_key: bytes = b""  # bytes, field 16
    pki_encrypted: bool = False  # bool, field 17

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.from_ != 0:
            parts.append(_encode_tag(1, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.from_))
        if self.to != 0:
            parts.append(_encode_tag(2, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.to))
        if self.channel != 0:
            parts.append(_encode_tag(3, WIRE_VARINT))
            parts.append(_encode_varint(self.channel))
        if self.decoded is not None:
            decoded_bytes = self.decoded.to_bytes()
            parts.append(_encode_tag(4, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(decoded_bytes)))
            parts.append(decoded_bytes)
        if self.encrypted is not None:
            parts.append(_encode_tag(5, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.encrypted)))
            parts.append(self.encrypted)
        if self.id != 0:
            parts.append(_encode_tag(6, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.id))
        if self.rx_time != 0:
            parts.append(_encode_tag(7, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.rx_time))
        if self.rx_snr != 0.0:
            parts.append(_encode_tag(8, WIRE_FIXED32))
            parts.append(struct.pack("<f", self.rx_snr))
        if self.hop_limit != 0:
            parts.append(_encode_tag(9, WIRE_VARINT))
            parts.append(_encode_varint(self.hop_limit))
        if self.want_ack:
            parts.append(_encode_tag(10, WIRE_VARINT))
            parts.append(b"\x01")
        if self.priority != PacketPriority.DEFAULT:
            parts.append(_encode_tag(11, WIRE_VARINT))
            parts.append(_encode_varint(self.priority))
        if self.rx_rssi != 0:
            parts.append(_encode_tag(12, WIRE_VARINT))
            parts.append(_encode_varint(self.rx_rssi))
        if self.via_mqtt:
            parts.append(_encode_tag(14, WIRE_VARINT))
            parts.append(b"\x01")
        if self.hop_start != 0:
            parts.append(_encode_tag(15, WIRE_VARINT))
            parts.append(_encode_varint(self.hop_start))
        if self.public_key:
            parts.append(_encode_tag(16, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.public_key)))
            parts.append(self.public_key)
        if self.pki_encrypted:
            parts.append(_encode_tag(17, WIRE_VARINT))
            parts.append(b"\x01")
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> MeshPacket:
        """Decode from protobuf."""
        pkt = cls()
        offset = 0
        while offset < len(data):
            field_num, wire_type, offset = _decode_tag(data, offset)
            if field_num == 1 and wire_type == WIRE_FIXED32:
                pkt.from_ = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 2 and wire_type == WIRE_FIXED32:
                pkt.to = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 3 and wire_type == WIRE_VARINT:
                pkt.channel, offset = _decode_varint(data, offset)
            elif field_num == 4 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                pkt.decoded = Data.from_bytes(data[offset : offset + length])
                offset += length
            elif field_num == 5 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                pkt.encrypted = data[offset : offset + length]
                offset += length
            elif field_num == 6 and wire_type == WIRE_FIXED32:
                pkt.id = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 7 and wire_type == WIRE_FIXED32:
                pkt.rx_time = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 8 and wire_type == WIRE_FIXED32:
                pkt.rx_snr = struct.unpack("<f", data[offset : offset + 4])[0]
                offset += 4
            elif field_num == 9 and wire_type == WIRE_VARINT:
                pkt.hop_limit, offset = _decode_varint(data, offset)
            elif field_num == 10 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                pkt.want_ack = val != 0
            elif field_num == 11 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                try:
                    pkt.priority = PacketPriority(val)
                except ValueError:
                    # Unknown priority from newer Meshtastic version
                    pkt.priority = PacketPriority.DEFAULT
            elif field_num == 12 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                pkt.rx_rssi = _varint_to_int32(val)
            elif field_num == 14 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                pkt.via_mqtt = val != 0
            elif field_num == 15 and wire_type == WIRE_VARINT:
                pkt.hop_start, offset = _decode_varint(data, offset)
            elif field_num == 16 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                pkt.public_key = data[offset : offset + length]
                offset += length
            elif field_num == 17 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                pkt.pki_encrypted = val != 0
            else:
                offset = _skip_field(data, offset, wire_type)
        return pkt


# =============================================================================
# MyNodeInfo (FromRadio.my_info)
# =============================================================================


@dataclass
class MyNodeInfo:
    """Node identity info sent during config sync (meshtastic.MyNodeInfo)."""

    my_node_num: int = 0  # uint32
    reboot_count: int = 0  # uint32
    min_app_version: int = 0  # uint32

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.my_node_num != 0:
            parts.append(_encode_tag(1, WIRE_VARINT))
            parts.append(_encode_varint(self.my_node_num))
        if self.reboot_count != 0:
            parts.append(_encode_tag(8, WIRE_VARINT))
            parts.append(_encode_varint(self.reboot_count))
        if self.min_app_version != 0:
            parts.append(_encode_tag(11, WIRE_VARINT))
            parts.append(_encode_varint(self.min_app_version))
        return b"".join(parts)


# =============================================================================
# DeviceMetadata (FromRadio.metadata)
# =============================================================================


@dataclass
class DeviceMetadata:
    """Device metadata sent during config sync (meshtastic.DeviceMetadata)."""

    firmware_version: str = ""  # string, field 1
    device_state_version: int = 0  # uint32, field 2
    can_shutdown: bool = False  # bool, field 3
    has_wifi: bool = False  # bool, field 4
    has_bluetooth: bool = False  # bool, field 5
    has_ethernet: bool = False  # bool, field 6
    role: int = 0  # enum DeviceConfig.Role, field 7
    position_flags: int = 0  # uint32, field 8
    hw_model: int = 0  # enum HardwareModel, field 9
    has_remote_hardware: bool = False  # bool, field 10
    excluded_modules: list[int] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.firmware_version:
            fw_bytes = self.firmware_version.encode("utf-8")
            parts.append(_encode_tag(1, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(fw_bytes)))
            parts.append(fw_bytes)
        if self.device_state_version != 0:
            parts.append(_encode_tag(2, WIRE_VARINT))
            parts.append(_encode_varint(self.device_state_version))
        if self.can_shutdown:
            parts.append(_encode_tag(3, WIRE_VARINT))
            parts.append(b"\x01")
        if self.has_wifi:
            parts.append(_encode_tag(4, WIRE_VARINT))
            parts.append(b"\x01")
        if self.has_bluetooth:
            parts.append(_encode_tag(5, WIRE_VARINT))
            parts.append(b"\x01")
        if self.has_ethernet:
            parts.append(_encode_tag(6, WIRE_VARINT))
            parts.append(b"\x01")
        if self.role != 0:
            parts.append(_encode_tag(7, WIRE_VARINT))
            parts.append(_encode_varint(self.role))
        if self.position_flags != 0:
            parts.append(_encode_tag(8, WIRE_VARINT))
            parts.append(_encode_varint(self.position_flags))
        if self.hw_model != 0:
            parts.append(_encode_tag(9, WIRE_VARINT))
            parts.append(_encode_varint(self.hw_model))
        if self.has_remote_hardware:
            parts.append(_encode_tag(10, WIRE_VARINT))
            parts.append(b"\x01")
        return b"".join(parts)


# =============================================================================
# QueueStatus (FromRadio.queueStatus)
# =============================================================================


@dataclass
class QueueStatus:
    """TX queue status for flow control (meshtastic.QueueStatus).

    Supports both encoding and decoding; uses _varint_to_int32 for
    the signed int32 `res` field.
    """

    res: int = 0  # int32, result of last send
    free: int = 0  # uint32, free slots
    maxlen: int = 0  # uint32, max queue length
    mesh_packet_id: int = 0  # uint32, ID of packet this status refers to

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.res != 0:
            parts.append(_encode_tag(1, WIRE_VARINT))
            parts.append(_encode_varint(self.res))
        if self.free != 0:
            parts.append(_encode_tag(2, WIRE_VARINT))
            parts.append(_encode_varint(self.free))
        if self.maxlen != 0:
            parts.append(_encode_tag(3, WIRE_VARINT))
            parts.append(_encode_varint(self.maxlen))
        if self.mesh_packet_id != 0:
            parts.append(_encode_tag(4, WIRE_VARINT))
            parts.append(_encode_varint(self.mesh_packet_id))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> QueueStatus:
        """Decode from protobuf."""
        qs = cls()
        offset = 0
        while offset < len(data):
            field_num, wire_type, offset = _decode_tag(data, offset)
            if field_num == 1 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                qs.res = _varint_to_int32(val)
            elif field_num == 2 and wire_type == WIRE_VARINT:
                qs.free, offset = _decode_varint(data, offset)
            elif field_num == 3 and wire_type == WIRE_VARINT:
                qs.maxlen, offset = _decode_varint(data, offset)
            elif field_num == 4 and wire_type == WIRE_VARINT:
                qs.mesh_packet_id, offset = _decode_varint(data, offset)
            else:
                offset = _skip_field(data, offset, wire_type)
        return qs


# =============================================================================
# ToRadio (incoming from app)
# =============================================================================


@dataclass
class ToRadio:
    """Message from app to device (meshtastic.ToRadio).

    Only one of the fields should be set (oneof payload_variant).
    """

    # oneof payload_variant
    packet: MeshPacket | None = None  # field 1
    want_config_id: int | None = None  # field 3, config request nonce
    disconnect: bool = False  # field 4
    heartbeat: bytes | None = None  # field 5, Heartbeat message
    xmodem_packet: bytes | None = None  # field 6

    @classmethod
    def from_bytes(cls, data: bytes) -> ToRadio:
        """Decode from protobuf."""
        msg = cls()
        offset = 0
        while offset < len(data):
            field_num, wire_type, offset = _decode_tag(data, offset)
            if field_num == 1 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                msg.packet = MeshPacket.from_bytes(data[offset : offset + length])
                offset += length
            elif field_num == 3 and wire_type == WIRE_VARINT:
                msg.want_config_id, offset = _decode_varint(data, offset)
            elif field_num == 4 and wire_type == WIRE_VARINT:
                val, offset = _decode_varint(data, offset)
                msg.disconnect = val != 0
            elif field_num == 5 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                msg.heartbeat = data[offset : offset + length]
                offset += length
            elif field_num == 6 and wire_type == WIRE_LEN_DELIM:
                length, offset = _decode_varint(data, offset)
                msg.xmodem_packet = data[offset : offset + length]
                offset += length
            else:
                offset = _skip_field(data, offset, wire_type)
        return msg


# =============================================================================
# FromRadio (outgoing to app)
# =============================================================================


@dataclass
class FromRadio:
    """Message from device to app (meshtastic.FromRadio).

    Only one of the fields should be set (oneof payload_variant).
    """

    id: int = 0  # uint32, message sequence number
    # oneof payload_variant
    packet: MeshPacket | None = None  # field 2
    my_info: MyNodeInfo | None = None  # field 3
    node_info: bytes | None = None  # field 4, NodeInfo (raw)
    config: bytes | None = None  # field 5, Config section (raw)
    log_record: bytes | None = None  # field 6, LogRecord (raw)
    config_complete_id: int | None = None  # field 7, echoes want_config_id
    rebooted: bool = False  # field 8
    module_config: bytes | None = None  # field 9, ModuleConfig (raw)
    channel: bytes | None = None  # field 10, Channel (raw)
    queue_status: QueueStatus | None = None  # field 11
    xmodem_packet: bytes | None = None  # field 12
    metadata: DeviceMetadata | None = None  # field 13
    mqtt_client_proxy_message: bytes | None = None  # field 14
    file_info: bytes | None = None  # field 15
    client_notification: bytes | None = None  # field 16
    device_ui_config: bytes | None = None  # field 17

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.id != 0:
            parts.append(_encode_tag(1, WIRE_VARINT))
            parts.append(_encode_varint(self.id))
        if self.packet is not None:
            pkt_bytes = self.packet.to_bytes()
            parts.append(_encode_tag(2, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(pkt_bytes)))
            parts.append(pkt_bytes)
        if self.my_info is not None:
            info_bytes = self.my_info.to_bytes()
            parts.append(_encode_tag(3, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(info_bytes)))
            parts.append(info_bytes)
        if self.node_info is not None:
            parts.append(_encode_tag(4, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.node_info)))
            parts.append(self.node_info)
        if self.config is not None:
            parts.append(_encode_tag(5, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.config)))
            parts.append(self.config)
        if self.log_record is not None:
            parts.append(_encode_tag(6, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.log_record)))
            parts.append(self.log_record)
        if self.config_complete_id is not None:
            parts.append(_encode_tag(7, WIRE_VARINT))
            parts.append(_encode_varint(self.config_complete_id))
        if self.rebooted:
            parts.append(_encode_tag(8, WIRE_VARINT))
            parts.append(b"\x01")
        if self.module_config is not None:
            parts.append(_encode_tag(9, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.module_config)))
            parts.append(self.module_config)
        if self.channel is not None:
            parts.append(_encode_tag(10, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.channel)))
            parts.append(self.channel)
        if self.queue_status is not None:
            qs_bytes = self.queue_status.to_bytes()
            parts.append(_encode_tag(11, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(qs_bytes)))
            parts.append(qs_bytes)
        if self.xmodem_packet is not None:
            parts.append(_encode_tag(12, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.xmodem_packet)))
            parts.append(self.xmodem_packet)
        if self.metadata is not None:
            meta_bytes = self.metadata.to_bytes()
            parts.append(_encode_tag(13, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(meta_bytes)))
            parts.append(meta_bytes)
        if self.mqtt_client_proxy_message is not None:
            parts.append(_encode_tag(14, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.mqtt_client_proxy_message)))
            parts.append(self.mqtt_client_proxy_message)
        if self.file_info is not None:
            parts.append(_encode_tag(15, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.file_info)))
            parts.append(self.file_info)
        if self.client_notification is not None:
            parts.append(_encode_tag(16, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.client_notification)))
            parts.append(self.client_notification)
        if self.device_ui_config is not None:
            parts.append(_encode_tag(17, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.device_ui_config)))
            parts.append(self.device_ui_config)
        return b"".join(parts)


# =============================================================================
# NodeInfo (for synthesizing peer info)
# =============================================================================


@dataclass
class NodeInfo:
    """Full node information (meshtastic.NodeInfo)."""

    num: int = 0  # uint32, field 1
    user: bytes | None = None  # User message (raw), field 2
    position: bytes | None = None  # Position message (raw), field 3
    snr: float = 0.0  # float, field 4
    last_heard: int = 0  # fixed32, field 5
    device_metrics: bytes | None = None  # DeviceMetrics (raw), field 6
    channel: int = 0  # uint32, field 7
    via_mqtt: bool = False  # bool, field 8
    hops_away: int | None = None  # optional uint32, field 9
    is_favorite: bool = False  # bool, field 10

    def to_bytes(self) -> bytes:
        """Encode as protobuf."""
        parts = []
        if self.num != 0:
            parts.append(_encode_tag(1, WIRE_VARINT))
            parts.append(_encode_varint(self.num))
        if self.user is not None:
            parts.append(_encode_tag(2, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.user)))
            parts.append(self.user)
        if self.position is not None:
            parts.append(_encode_tag(3, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.position)))
            parts.append(self.position)
        if self.snr != 0.0:
            parts.append(_encode_tag(4, WIRE_FIXED32))
            parts.append(struct.pack("<f", self.snr))
        if self.last_heard != 0:
            parts.append(_encode_tag(5, WIRE_FIXED32))
            parts.append(struct.pack("<I", self.last_heard))
        if self.device_metrics is not None:
            parts.append(_encode_tag(6, WIRE_LEN_DELIM))
            parts.append(_encode_varint(len(self.device_metrics)))
            parts.append(self.device_metrics)
        if self.channel != 0:
            parts.append(_encode_tag(7, WIRE_VARINT))
            parts.append(_encode_varint(self.channel))
        if self.via_mqtt:
            parts.append(_encode_tag(8, WIRE_VARINT))
            parts.append(b"\x01")
        if self.hops_away is not None:
            parts.append(_encode_tag(9, WIRE_VARINT))
            parts.append(_encode_varint(self.hops_away))
        if self.is_favorite:
            parts.append(_encode_tag(10, WIRE_VARINT))
            parts.append(b"\x01")
        return b"".join(parts)
