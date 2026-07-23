# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field

"""Announce message codec (spec section 9.2 + CCP-9).

Wire format:
    0: Type = 0x01
    1: rx_channel (0-7) / Flags
    2: Hop Cnt
  3-4: Seq Num (BE)
  5-12: Originator IID (8B)
13-44: Public Key (32B)
45-92: Signature (48B Schnorr)
 93+: Optional App Data

Total fixed: 93 bytes. rx_channel signed to prevent relay tampering (CCP-9).
Signature covers signed_data() excluding hop_count.
"""

ANNOUNCE_TYPE = 0x01
SIGNATURE_LENGTH = 48
MAX_ANNOUNCE_HOPS = 15
# Calculated from wire format for maintainability (matches test vectors)
_FIXED_LENGTH = 1 + 1 + 1 + 2 + 8 + 32 + 48


class AnnounceError(Exception):
    """Raised when an announce message is malformed."""



@dataclass
class AnnounceMessage:
    """An announce message advertising presence in the mesh (spec 9.2 + CCP-9).

    Security model: Schnorr48 signature over signed_data() (originator_iid +
    pubkey + seq_num + rx_channel + app_data) provides authenticity and binds
    the key to the IID. TOFU or DANE for key pinning. Hop count is NOT signed
    (relays increment it).
    """

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
            raise AnnounceError(
                f"originator_iid must be 8 bytes, got {len(self.originator_iid)}"
            )
        if len(self.pubkey) != 32:
            raise AnnounceError(
                f"pubkey must be 32 bytes, got {len(self.pubkey)}"
            )
        if not 0 <= self.seq_num <= 0xFFFF:
            raise AnnounceError(f"seq_num out of range: {self.seq_num}")
        if not 0 <= self.hop_count <= 0xFF:
            raise AnnounceError(f"hop_count out of range: {self.hop_count}")
        if not 0 <= self.flags <= 0xFF:
            raise AnnounceError(f"flags out of range: {self.flags}")
        if not 0 <= self.rx_channel <= 7:
            raise AnnounceError(
                f"invalid rx_channel: {self.rx_channel} (must be 0-7)"
            )
        if self.signature and len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"signature must be 0 or {SIGNATURE_LENGTH} bytes, "
                f"got {len(self.signature)}"
            )

    def signed_data(self) -> bytes:
        return (
            self.originator_iid
            + self.pubkey
            + self.seq_num.to_bytes(2, "big")
            + self.rx_channel.to_bytes(1, "big")
            + self.app_data
        )

    def to_bytes(self) -> bytes:
        """Serialize to wire format per spec 9.2/CCP-9 (type, rx_channel/flags, hop, seq, iid, pubkey, sig, app_data)."""
        if len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"cannot serialize unsigned announce (signature len "
                f"{len(self.signature)}, expected {SIGNATURE_LENGTH})"
            )
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
            raise AnnounceError(
                f"announce message too short: {len(data)} bytes, "
                f"need at least {_FIXED_LENGTH}"
            )
        if data[0] != ANNOUNCE_TYPE:
            raise AnnounceError(
                f"wrong message type: expected {ANNOUNCE_TYPE}, got {data[0]}"
            )
        flags = data[1]
        rx_channel = flags
        if rx_channel >= 8:
            raise AnnounceError(f"invalid rx_channel: {rx_channel} (must be 0-7)")
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
            raise AnnounceError(
                f"hop_count would exceed MAX_ANNOUNCE_HOPS: "
                f"{new_hop_count} > {MAX_ANNOUNCE_HOPS}"
            )
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
