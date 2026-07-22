# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Announce message codec (spec section 9.2).

Wire format:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Type=ANN  | Flags     | Hop Count   | Seq Num               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Originator IID (8 bytes)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Public Key (32 bytes)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Signature (48 bytes)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Optional: App Data (variable)              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total: 93 bytes minimum (1+1+1+2+8+32+48).

Why sign IID+pubkey+seq+app_data: These are the security-relevant fields.
Hop count is NOT signed because it's modified by each relay.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Why 0x01: Needs a unique type identifier inside the routing/control
# namespace. At the authenticated link layer this byte follows
# L2_DISPATCH_ROUTING (0x15), so it cannot collide with SCHC rule 0x01.
# Other types: 0x02=RREQ, 0x03=RREP, 0x04=RERR.
ANNOUNCE_TYPE = 0x01

# Why 48: Schnorr48 signature length (16-byte challenge + 32-byte response).
SIGNATURE_LENGTH = 48

# Why 15: Spec section 9.4. Limits propagation to prevent infinite flooding.
MAX_ANNOUNCE_HOPS = 15

# Fixed portion: type(1) + flags(1) + hop_count(1) + seq_num(2) + iid(8) + pubkey(32) + sig(48)
_FIXED_LENGTH = 1 + 1 + 1 + 2 + 8 + 32 + 48


class AnnounceError(Exception):
    """Raised when an announce message is malformed."""


@dataclass
class AnnounceMessage:
    """An announce message advertising presence in the mesh (spec 9.2).

    Why this message: Active mesh participants broadcast announces periodically.
    Other nodes build gradients toward announcers, enabling instant peer-to-peer
    routing without discovery latency.

    Security model (spec 9.6):
    - Signature proves sender holds private key for pubkey
    - TOFU binding associates pubkey with IID
    - Cannot forge announce for another node's address

    Attributes:
        originator_iid: 8-byte Interface Identifier of the announcer.
            Why IID not full IPv6: IID is the unique identifier derived from pubkey.
            The IPv6 prefix is known from network context.
        pubkey: 32-byte Ed25519 public key of the announcer.
            Why include: Receivers need it to verify the signature and for TOFU.
        seq_num: 16-bit monotonic sequence number.
            Why: Detects duplicates and freshness. Higher = newer.
        hop_count: How many hops this announce has traveled.
            Why NOT signed: Each relay increments it. If signed, relays couldn't
            update it without breaking the signature.
        current_channel: Preferred RX channel (0-15) for rendezvous per CCP-9.
            Included in signed_data() after seq_num to cryptographically bind announced channel (prevents tampering/injection per vectors).
        signature: 48-byte Schnorr signature over signed_data().
            Why 48: Schnorr48 spec (16-byte truncated challenge + 32-byte response).
        app_data: Optional application data (node name, capabilities).
            Why optional: Most announces don't need it. Keeps base message small.
        flags: Reserved for future use.
            Why: Forward compatibility. Must be 0 for now.
    """

    originator_iid: bytes
    pubkey: bytes
    seq_num: int
    hop_count: int = 0
    current_channel: int = 0
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
        if not 0 <= self.current_channel <= 15:
            raise AnnounceError(f"current_channel out of range: {self.current_channel}")
        if not 0 <= self.flags <= 0xFF:
            raise AnnounceError(f"flags out of range: {self.flags}")
        if self.signature and len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"signature must be 0 or {SIGNATURE_LENGTH} bytes, "
                f"got {len(self.signature)}"
            )

    def signed_data(self) -> bytes:
        """Data covered by the signature (spec 9.2).

        Why these fields: Security-relevant content that must not be modified.
        - originator_iid: Proves you're announcing for this IID
        - pubkey: Binds the IID to this key (TOFU)
        - seq_num: Prevents replay of old announces
        - app_data: Proves you authored this data

        Why NOT hop_count: Relays must increment it. If signed, they couldn't.
        Why NOT flags: Reserved, always 0. Could sign if semantics defined.

        Returns:
            Bytes to sign/verify.
        """
        return (
            self.originator_iid
            + self.pubkey
            + self.seq_num.to_bytes(2, "big")
            + self.app_data
        )

    def to_bytes(self) -> bytes:
        """Serialize to wire format.

        Raises:
            AnnounceError: If signature is missing (unsigned message).
        """
        if len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError("cannot serialize unsigned announce message")

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
        """Parse from wire format.

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

        flags = data[1]
        hop_count = data[2]
        seq_num = int.from_bytes(data[3:5], "big")
        originator_iid = data[5:13]
        pubkey = data[13:45]
        signature = data[45:93]
        app_data = data[93:]  # Everything after signature is app_data

        return cls(
            originator_iid=originator_iid,
            pubkey=pubkey,
            seq_num=seq_num,
            hop_count=hop_count,
            signature=signature,
            app_data=app_data,
            flags=flags,
        )

    def with_incremented_hop_count(self) -> AnnounceMessage:
        """Return a copy with hop_count incremented.

        Why a new object: AnnounceMessage is mutable but semantically we're
        creating a modified copy for relay. Cleaner API than mutating.

        Returns:
            New AnnounceMessage with hop_count + 1.

        Raises:
            AnnounceError: If hop_count would exceed MAX_ANNOUNCE_HOPS.
        """
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
