# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field

ANNOUNCE_TYPE = 0x01
SIGNATURE_LENGTH = 48
MAX_ANNOUNCE_HOPS = 15
_FIXED_LENGTH = 93


class AnnounceError(Exception):
    pass


@dataclass
class AnnounceMessage:
    originator_iid: bytes
    pubkey: bytes
    seq_num: int
    hop_count: int = 0
    flags: int = 0
    rx_channel: int = 0
    signature: bytes = field(default=b"")
    app_data: bytes = field(default=b"")

    def __post_init__(self) -> None:
        if len(self.originator_iid) != 8:
            raise AnnounceError("originator_iid must be 8 bytes")
        if len(self.pubkey) != 32:
            raise AnnounceError("pubkey must be 32 bytes")
        if not 0 <= self.seq_num <= 0xFFFF:
            raise AnnounceError("seq_num out of range")
        if not 0 <= self.hop_count <= 0xFF:
            raise AnnounceError("hop_count out of range")
        if not 0 <= self.flags <= 0xFF:
            raise AnnounceError("flags out of range")
        if not 0 <= self.rx_channel <= 7:
            raise AnnounceError("invalid rx_channel")
        if self.signature and len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError("signature must be 0 or 48 bytes")

    def signed_data(self) -> bytes:
        return (
            self.originator_iid
            + self.pubkey
            + self.seq_num.to_bytes(2, "big")
            + self.rx_channel.to_bytes(1, "big")
            + self.app_data
        )

    def to_bytes(self) -> bytes:
        if len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError("cannot serialize unsigned")
        return (
            bytes([ANNOUNCE_TYPE, self.flags, self.hop_count])
            + self.seq_num.to_bytes(2, "big")
            + self.originator_iid
            + self.pubkey
            + self.signature
            + self.app_data
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> AnnounceMessage:
        if len(data) < _FIXED_LENGTH:
            raise AnnounceError("too short")
        if data[0] != ANNOUNCE_TYPE:
            raise AnnounceError("wrong message type")
        flags = data[1]
        rx_channel = flags
        if rx_channel >= 8:
            raise AnnounceError("invalid channel")
        return cls(
            originator_iid=data[5:13],
            pubkey=data[13:45],
            seq_num=int.from_bytes(data[3:5], "big"),
            hop_count=data[2],
            flags=flags,
            rx_channel=rx_channel,
            signature=data[45:93],
            app_data=data[93:],
        )

    def with_incremented_hop_count(self) -> AnnounceMessage:
        new_hop_count = self.hop_count + 1
        if new_hop_count > MAX_ANNOUNCE_HOPS:
            raise AnnounceError("hop_count would exceed MAX_ANNOUNCE_HOPS")
        return AnnounceMessage(
            originator_iid=self.originator_iid,
            pubkey=self.pubkey,
            seq_num=self.seq_num,
            hop_count=new_hop_count,
            flags=self.flags,
            rx_channel=self.rx_channel,
            signature=self.signature,
            app_data=self.app_data,
        )

    def should_relay(self) -> bool:
        return self.hop_count < MAX_ANNOUNCE_HOPS
