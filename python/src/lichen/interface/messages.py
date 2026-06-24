"""
LICHEN Native protocol CBOR messages.

All messages are CBOR maps with integer keys.
Key 0 is always the message type.

See spec/lichen-native/02-common.md through 10-raw-frame.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import cbor2


class MessageType(IntEnum):
    """Message type codes."""

    HELLO = 0x01
    CONFIG_GET = 0x10
    CONFIG_SET = 0x11
    CONFIG_RESULT = 0x12
    SEND_MESSAGE = 0x20
    MESSAGE_RECEIVED = 0x21
    MESH_STATE = 0x30
    NODE_INFO = 0x31
    LOG_ENTRY = 0x40
    LOG_SUBSCRIBE = 0x41
    OTA_BEGIN = 0x50
    OTA_CHUNK = 0x51
    OTA_FINISH = 0x52
    OTA_STATUS = 0x53
    RAW_TX = 0x60
    RAW_RX = 0x61


class ResultCode(IntEnum):
    """Result codes for responses."""

    OK = 0
    ERROR = 1
    INVALID_PARAM = 2
    NOT_FOUND = 3
    BUSY = 4
    NOT_SUPPORTED = 5


class LogLevel(IntEnum):
    """Log severity levels."""

    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


class ConfigKey(IntEnum):
    """Configuration keys."""

    TX_POWER = 1
    FREQUENCY = 2
    SPREADING_FACTOR = 3
    BANDWIDTH = 4
    CODING_RATE = 5
    SYNC_WORD = 6
    ANNOUNCE_INTERVAL = 16
    RECEIVE_TIMEOUT = 17
    TX_JITTER_MAX = 18
    DEVICE_NAME = 32
    NETWORK_KEY = 48
    RAW_RX_ENABLE = 64


# --- Base class ---


@dataclass
class Message:
    """Base class for all messages."""

    def to_cbor(self) -> bytes:
        """Encode to CBOR bytes."""
        return cbor2.dumps(self.to_dict())

    def to_dict(self) -> dict[int, Any]:
        """Convert to CBOR-ready dict with integer keys."""
        raise NotImplementedError

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> Message:
        """Create from decoded CBOR dict."""
        raise NotImplementedError


# --- Hello ---


@dataclass
class Hello(Message):
    """Connection handshake message."""

    version: int = 1
    supported: list[int] = field(default_factory=list)
    firmware: str = ""
    iid: bytes | None = None
    name: str | None = None
    max_size: int | None = None
    features: dict[int, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {
            0: MessageType.HELLO,
            1: self.version,
            2: self.supported,
            3: self.firmware,
        }
        if self.iid is not None:
            d[4] = self.iid
        if self.name is not None:
            d[5] = self.name
        if self.max_size is not None:
            d[6] = self.max_size
        if self.features:
            d[7] = self.features
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> Hello:
        return cls(
            version=d.get(1, 1),
            supported=d.get(2, []),
            firmware=d.get(3, ""),
            iid=d.get(4),
            name=d.get(5),
            max_size=d.get(6),
            features=d.get(7, {}),
        )


# --- Config ---


@dataclass
class ConfigGet(Message):
    """Request configuration values."""

    keys: list[int] | None = None  # None = get all

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.CONFIG_GET}
        if self.keys is not None:
            d[1] = self.keys
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> ConfigGet:
        return cls(keys=d.get(1))


@dataclass
class ConfigSet(Message):
    """Set configuration values."""

    values: dict[int, Any]
    persist: bool = True

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.CONFIG_SET, 1: self.values}
        if not self.persist:
            d[2] = False
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> ConfigSet:
        return cls(values=d.get(1, {}), persist=d.get(2, True))


@dataclass
class ConfigResult(Message):
    """Configuration response."""

    result: ResultCode
    values: dict[int, Any] | None = None
    error: str | None = None
    failed_keys: list[int] | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.CONFIG_RESULT, 1: self.result}
        if self.values is not None:
            d[2] = self.values
        if self.error is not None:
            d[3] = self.error
        if self.failed_keys is not None:
            d[4] = self.failed_keys
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> ConfigResult:
        return cls(
            result=ResultCode(d.get(1, 0)),
            values=d.get(2),
            error=d.get(3),
            failed_keys=d.get(4),
        )


# --- Messaging ---


@dataclass
class SendMessage(Message):
    """Send application message."""

    dest: bytes  # IID (8 bytes) or IPv6 (16 bytes)
    payload: bytes
    dest_port: int = 5683
    src_port: int | None = None
    ack: bool = False
    msg_id: int | None = None
    ttl: int = 64

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {
            0: MessageType.SEND_MESSAGE,
            1: self.dest,
            2: self.payload,
        }
        if self.dest_port != 5683:
            d[3] = self.dest_port
        if self.src_port is not None:
            d[4] = self.src_port
        if self.ack:
            d[5] = True
        if self.msg_id is not None:
            d[6] = self.msg_id
        if self.ttl != 64:
            d[7] = self.ttl
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> SendMessage:
        return cls(
            dest=d[1],
            payload=d[2],
            dest_port=d.get(3, 5683),
            src_port=d.get(4),
            ack=d.get(5, False),
            msg_id=d.get(6),
            ttl=d.get(7, 64),
        )


@dataclass
class MessageReceived(Message):
    """Received application message."""

    src: bytes
    payload: bytes
    src_port: int | None = None
    dest_port: int | None = None
    rssi: int | None = None
    snr: int | None = None
    hops: int | None = None
    msg_id: int | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {
            0: MessageType.MESSAGE_RECEIVED,
            1: self.src,
            2: self.payload,
        }
        if self.src_port is not None:
            d[3] = self.src_port
        if self.dest_port is not None:
            d[4] = self.dest_port
        if self.rssi is not None:
            d[5] = self.rssi
        if self.snr is not None:
            d[6] = self.snr
        if self.hops is not None:
            d[7] = self.hops
        if self.msg_id is not None:
            d[8] = self.msg_id
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> MessageReceived:
        return cls(
            src=d[1],
            payload=d[2],
            src_port=d.get(3),
            dest_port=d.get(4),
            rssi=d.get(5),
            snr=d.get(6),
            hops=d.get(7),
            msg_id=d.get(8),
        )


# --- Mesh State ---


@dataclass
class GradientEntry:
    """Routing table entry."""

    dest: bytes  # IID
    next_hop: bytes  # IID
    hops: int
    seq: int
    expires_ms: int
    rssi: int | None = None
    flags: int | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {
            1: self.dest,
            2: self.next_hop,
            3: self.hops,
            4: self.seq,
            5: self.expires_ms,
        }
        if self.rssi is not None:
            d[6] = self.rssi
        if self.flags is not None:
            d[7] = self.flags
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> GradientEntry:
        return cls(
            dest=d[1],
            next_hop=d[2],
            hops=d[3],
            seq=d[4],
            expires_ms=d[5],
            rssi=d.get(6),
            flags=d.get(7),
        )


@dataclass
class NeighborEntry:
    """Direct neighbor entry."""

    iid: bytes
    rssi: int
    snr: int | None = None
    last_heard_ms: int | None = None
    rx_count: int | None = None
    tx_count: int | None = None
    lqi: int | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {1: self.iid, 2: self.rssi}
        if self.snr is not None:
            d[3] = self.snr
        if self.last_heard_ms is not None:
            d[4] = self.last_heard_ms
        if self.rx_count is not None:
            d[5] = self.rx_count
        if self.tx_count is not None:
            d[6] = self.tx_count
        if self.lqi is not None:
            d[7] = self.lqi
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> NeighborEntry:
        return cls(
            iid=d[1],
            rssi=d[2],
            snr=d.get(3),
            last_heard_ms=d.get(4),
            rx_count=d.get(5),
            tx_count=d.get(6),
            lqi=d.get(7),
        )


@dataclass
class MeshState(Message):
    """Mesh topology state."""

    gradients: list[GradientEntry] = field(default_factory=list)
    neighbors: list[NeighborEntry] = field(default_factory=list)
    seq: int | None = None
    is_delta: bool = False
    uptime_ms: int | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {
            0: MessageType.MESH_STATE,
            1: [g.to_dict() for g in self.gradients],
            2: [n.to_dict() for n in self.neighbors],
        }
        if self.seq is not None:
            d[3] = self.seq
        if self.is_delta:
            d[4] = True
        if self.uptime_ms is not None:
            d[5] = self.uptime_ms
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> MeshState:
        return cls(
            gradients=[GradientEntry.from_dict(g) for g in d.get(1, [])],
            neighbors=[NeighborEntry.from_dict(n) for n in d.get(2, [])],
            seq=d.get(3),
            is_delta=d.get(4, False),
            uptime_ms=d.get(5),
        )


# --- Node Info ---


@dataclass
class NodeInfo(Message):
    """Device status and telemetry."""

    iid: bytes
    name: str | None = None
    firmware: str | None = None
    hardware: str | None = None
    uptime_ms: int | None = None
    battery: dict[int, Any] | None = None
    gps: dict[int, Any] | None = None
    radio: dict[int, Any] | None = None
    memory: dict[int, Any] | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.NODE_INFO, 1: self.iid}
        if self.name is not None:
            d[2] = self.name
        if self.firmware is not None:
            d[3] = self.firmware
        if self.hardware is not None:
            d[4] = self.hardware
        if self.uptime_ms is not None:
            d[5] = self.uptime_ms
        if self.battery is not None:
            d[6] = self.battery
        if self.gps is not None:
            d[7] = self.gps
        if self.radio is not None:
            d[8] = self.radio
        if self.memory is not None:
            d[9] = self.memory
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> NodeInfo:
        return cls(
            iid=d[1],
            name=d.get(2),
            firmware=d.get(3),
            hardware=d.get(4),
            uptime_ms=d.get(5),
            battery=d.get(6),
            gps=d.get(7),
            radio=d.get(8),
            memory=d.get(9),
        )


# --- Logging ---


@dataclass
class LogEntry(Message):
    """Debug log entry."""

    level: LogLevel
    msg: str
    module: str | None = None
    time_ms: int | None = None
    location: str | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.LOG_ENTRY, 1: self.level, 2: self.msg}
        if self.module is not None:
            d[3] = self.module
        if self.time_ms is not None:
            d[4] = self.time_ms
        if self.location is not None:
            d[5] = self.location
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> LogEntry:
        return cls(
            level=LogLevel(d[1]),
            msg=d[2],
            module=d.get(3),
            time_ms=d.get(4),
            location=d.get(5),
        )


@dataclass
class LogSubscribe(Message):
    """Enable/disable log streaming."""

    enable: bool
    level: LogLevel | None = None
    modules: list[str] | None = None

    def to_dict(self) -> dict[int, Any]:
        d: dict[int, Any] = {0: MessageType.LOG_SUBSCRIBE, 1: self.enable}
        if self.level is not None:
            d[2] = self.level
        if self.modules is not None:
            d[3] = self.modules
        return d

    @classmethod
    def from_dict(cls, d: dict[int, Any]) -> LogSubscribe:
        level = d.get(2)
        return cls(
            enable=d[1],
            level=LogLevel(level) if level is not None else None,
            modules=d.get(3),
        )


# --- Codec ---

_MESSAGE_CLASSES: dict[int, type[Message]] = {
    MessageType.HELLO: Hello,
    MessageType.CONFIG_GET: ConfigGet,
    MessageType.CONFIG_SET: ConfigSet,
    MessageType.CONFIG_RESULT: ConfigResult,
    MessageType.SEND_MESSAGE: SendMessage,
    MessageType.MESSAGE_RECEIVED: MessageReceived,
    MessageType.MESH_STATE: MeshState,
    MessageType.NODE_INFO: NodeInfo,
    MessageType.LOG_ENTRY: LogEntry,
    MessageType.LOG_SUBSCRIBE: LogSubscribe,
}


def encode_message(msg: Message) -> bytes:
    """Encode message to CBOR bytes."""
    return msg.to_cbor()


def decode_message(data: bytes) -> Message:
    """Decode CBOR bytes to message."""
    d = cbor2.loads(data)
    if not isinstance(d, dict) or 0 not in d:
        raise ValueError("invalid message: missing type field")

    msg_type = d[0]
    cls = _MESSAGE_CLASSES.get(msg_type)
    if cls is None:
        raise ValueError(f"unknown message type: 0x{msg_type:02x}")

    return cls.from_dict(d)
