# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Announce message codec (spec section 9.2 + CCP-9).

Wire format (CCP-9):
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Type=0x01 | rx_ch/Flags | Hop Cnt | Seq Num (2B) |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Originator IID (8 bytes)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Public Key (32 bytes)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Signature (48 bytes)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Optional: App Data (variable)              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total: 93 bytes minimum. rx_channel in flags byte, signed per CCP-9.
"""


from __future__ import annotations

from dataclasses import dataclass, field

ANNOUNCE_TYPE = 0x01
SIGNATURE_LENGTH = 48
MAX_ANNOUNCE_HOPS = 15

_FIXED_LENGTH = 1 + 1 + 1 + 2 + 8 + 32 + 48


class AnnounceError(Exception):
    """Raised when an announce message is malformed."""


@dataclass
class AnnounceMessage:
    """An announce message advertising presence in the mesh (spec 9.2).

    Security model (spec 9.6):
    - Signature proves sender holds private key for pubkey
    - TOFU binding associates pubkey with IID
    - Cannot forge announce for another node's address

    Attributes:
        originator_iid: 8-byte Interface Identifier of the announcer.
        pubkey: 32-byte Ed25519 public key of the announcer.
        seq_num: 16-bit monotonic sequence number.
        hop_count: How many hops this announce has traveled.
        rx_channel: Preferred RX channel for rendezvous (0-7 per CCP-9).
            Used for rendezvous per CCP-9; signed in signed_data() to prevent tampering.
            Flags byte holds this value.
        signature: 48-byte Schnorr signature over signed_data().
        app_data: Optional application data (node name, capabilities).
        flags: rx_channel value.
    """

    originator_iid: bytes
    pubkey: bytes
    seq_num: int
    hop_count: int = 0
    rx_channel: int = 0
    signature: bytes = field(default=b"")
    app_data: bytes = field(default=b"")
    flags: int = 0

    def __post_init__(self) -> None:
        if len(self.originator_iid) != 8:
            raise AnnounceError(
                f"originator_iid must be 8 bytes, got {len(self.originator_iid)}"
            )
        if len(self.pubkey) != 32:
            raise AnnounceError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if not 0 <= self.seq_num <= 0xFFFF:
            raise AnnounceError(f"seq_num out of range: {self.seq_num}")
        if not 0 <= self.hop_count <= 0xFF:
            raise AnnounceError(f"hop_count out of range: {self.hop_count}")
        if not 0 <= self.rx_channel <= 7:
            raise AnnounceError(
                f"rx_channel must be 0-7 for CCP-9, got {self.rx_channel}"
            )
        if not 0 <= self.flags <= 0xFF:
            raise AnnounceError(f"flags out of range: {self.flags}")
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
        """Serialize to wire format (CCP-9).

        Raises:
            AnnounceError: If signature is missing (unsigned message).
        """
        if len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError("cannot serialize unsigned announce message")

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
        """Parse from wire format (CCP-9 rx_channel in flags byte at offset 1).

        Args:
            data: Raw bytes from the network.

        Returns:
            Parsed AnnounceMessage.

        Raises:
            AnnounceError: If the data is truncated or has wrong type.
        """
        if len(data) < _FIXED_LENGTH:
            raise AnnounceError(
                f"announce message too short: {len(data)} bytes, need {_FIXED_LENGTH}"
            )

        msg_type = data[0]
        if msg_type != ANNOUNCE_TYPE:
            raise AnnounceError(f"wrong message type: expected {ANNOUNCE_TYPE}, got {msg_type}")

        rx_channel = data[1]
        hop_count = data[2]
        seq_num = int.from_bytes(data[3:5], "big")
        originator_iid = data[5:13]
        pubkey = data[13:45]
        signature = data[45:93]
        app_data = data[93:]

        return cls(
            originator_iid=originator_iid,
            pubkey=pubkey,
            seq_num=seq_num,
            hop_count=hop_count,
            rx_channel=rx_channel,
            signature=signature,
            app_data=app_data,
            flags=rx_channel,
        )

    def with_incremented_hop_count(self) -> AnnounceMessage:
        new_hop_count = self.hop_count + 1
        if new_hop_count > MAX_ANNOUNCE_HOPS:
            raise AnnounceError(
                f"hop_count would exceed MAX_ANNOUNCE_HOPS: {new_hop_count}"
            )
        return AnnounceMessage(
            originator_iid=self.originator_iid,
            pubkey=self.pubkey,
            seq_num=self.seq_num,
            hop_count=new_hop_count,
            rx_channel=self.rx_channel,
            signature=self.signature,
            app_data=self.app_data,
            flags=self.flags,
        )

    def should_relay(self) -> bool:
        """Whether this announce should be relayed (spec 9.3).

        Returns:
            True if hop_count < MAX_ANNOUNCE_HOPS, meaning more hops allowed.
        """
        return self.hop_count < MAX_ANNOUNCE_HOPS
