# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field

ANNOUNCE_TYPE = 0x01
SIGNATURE_LENGTH = 48
MAX_ANNOUNCE_HOPS = 15
ANNOUNCE_SIGNATURE_DOMAIN = b"LICHEN-ANNOUNCE-v1\x00"
_FIXED_LENGTH = 1 + 1 + 2 + 8 + 32 + 48 + 1
# A signed broadcast link frame has a 254-byte body containing the 4-byte
# link header, 8-byte signer identity, 48-byte link signature, and payload.
# The authenticated payload also contains the one-byte routing dispatch before
# the announce bytes.
MAX_ANNOUNCE_WIRE_LENGTH = 254 - 4 - 8 - 48 - 1
MAX_ANNOUNCE_APP_DATA = MAX_ANNOUNCE_WIRE_LENGTH - _FIXED_LENGTH


class AnnounceError(Exception):
    pass


@dataclass(frozen=True)
class AnnounceMessage:
    """LICHEN announce message.

    Broadcast periodically by every node to advertise presence,
    routing information, and capabilities.

    Attributes:
        originator_iid: 8-byte interface identifier derived from
            SHA-512(pubkey)[0:8] with the U/L bit cleared.
        pubkey: 32-byte Ed25519 public key for signature verification.
        seq_num: Monotonically increasing sequence number (0-65535).
        hop_count: Number of relays this announce has traversed (0-255).
        rx_channel: RX channel (0-7) for CCP-9 peer rendezvous coordination.
        signature: 48-byte Schnorr signature, or empty if unsigned.
        app_data: Optional application-specific payload (variable length).
    """

    originator_iid: bytes
    pubkey: bytes
    seq_num: int
    hop_count: int = 0
    rx_channel: int = 0
    signature: bytes = field(default=b"")
    app_data: bytes = field(default=b"")

    def __post_init__(self) -> None:
        for bytes_name, bytes_value in (
            ("originator_iid", self.originator_iid),
            ("pubkey", self.pubkey),
            ("signature", self.signature),
            ("app_data", self.app_data),
        ):
            if type(bytes_value) is not bytes:
                raise AnnounceError(f"{bytes_name} must be immutable bytes")
        for integer_name, integer_value in (
            ("seq_num", self.seq_num),
            ("hop_count", self.hop_count),
            ("rx_channel", self.rx_channel),
        ):
            if type(integer_value) is not int:
                raise AnnounceError(f"{integer_name} must be an integer")
        if len(self.originator_iid) != 8:
            raise AnnounceError(f"originator_iid must be 8 bytes, got {len(self.originator_iid)}")
        if len(self.pubkey) != 32:
            raise AnnounceError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if not 0 <= self.seq_num <= 0xFFFF:
            raise AnnounceError(f"seq_num out of range: {self.seq_num}")
        if not 0 <= self.hop_count <= 0xFF:
            raise AnnounceError(f"hop_count out of range: {self.hop_count}")
        if not 0 <= self.rx_channel < 8:
            raise AnnounceError(f"invalid rx_channel: {self.rx_channel} (must be 0-7)")
        if self.signature and len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"signature must be 0 or {SIGNATURE_LENGTH} bytes, got {len(self.signature)}"
            )
        if len(self.app_data) > MAX_ANNOUNCE_APP_DATA:
            raise AnnounceError(
                f"app_data exceeds link profile limit: {len(self.app_data)} > "
                f"{MAX_ANNOUNCE_APP_DATA}"
            )

    def signed_data(self) -> bytes:
        """Data covered by signature.

        The fixed domain/version and explicit app-data length prevent
        cross-protocol signature reuse and ambiguous future extensions.
        """
        return (
            ANNOUNCE_SIGNATURE_DOMAIN
            + self.originator_iid
            + self.pubkey
            + self.seq_num.to_bytes(2, "big")
            + self.rx_channel.to_bytes(1, "big")
            + len(self.app_data).to_bytes(2, "big")
            + self.app_data
        )

    def to_bytes(self) -> bytes:
        if len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"cannot serialize unsigned announce (signature len "
                f"{len(self.signature)}, expected {SIGNATURE_LENGTH})"
            )
        return (
            bytes([ANNOUNCE_TYPE, self.rx_channel, self.hop_count])
            + self.seq_num.to_bytes(2, "big")
            + self.originator_iid
            + self.pubkey
            + self.signature
            + self.app_data
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> AnnounceMessage:
        if type(data) is not bytes:
            raise AnnounceError("announce wire value must be immutable bytes")
        if len(data) > MAX_ANNOUNCE_WIRE_LENGTH:
            raise AnnounceError(
                f"announce message too long: {len(data)} > {MAX_ANNOUNCE_WIRE_LENGTH}"
            )
        if len(data) < _FIXED_LENGTH:
            raise AnnounceError(
                f"announce message too short: {len(data)} bytes, need at least {_FIXED_LENGTH}"
            )
        if data[0] != ANNOUNCE_TYPE:
            raise AnnounceError(f"wrong message type: expected {ANNOUNCE_TYPE}, got {data[0]}")
        rx_channel = data[1]
        if rx_channel >= 8:
            raise AnnounceError(f"invalid rx_channel: {rx_channel} (must be 0-7)")
        return cls(
            originator_iid=data[5:13],
            pubkey=data[13:45],
            seq_num=int.from_bytes(data[3:5], "big"),
            hop_count=data[2],
            rx_channel=rx_channel,
            signature=data[45:93],
            app_data=data[93:],
        )

    def with_incremented_hop_count(self) -> AnnounceMessage:
        new_hop_count = self.hop_count + 1
        if new_hop_count > MAX_ANNOUNCE_HOPS:
            raise AnnounceError(
                f"hop_count would exceed MAX_ANNOUNCE_HOPS: {new_hop_count} > {MAX_ANNOUNCE_HOPS}"
            )
        return AnnounceMessage(
            originator_iid=self.originator_iid,
            pubkey=self.pubkey,
            seq_num=self.seq_num,
            hop_count=new_hop_count,
            rx_channel=self.rx_channel,
            signature=self.signature,
            app_data=self.app_data,
        )

    def should_relay(self) -> bool:
        return self.hop_count < MAX_ANNOUNCE_HOPS
