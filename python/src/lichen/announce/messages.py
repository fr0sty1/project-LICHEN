# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field

"""Announce message codec (spec section 9.2 + CCP-9).

Wire format (final per spec/05-routing.md, CCP-9 rendezvous, and test vectors):
    0: Type = 0x01
    1: current_channel (0-7 packed in flags per CCP-9) / Flags
    2: Hop Cnt
  3-4: Seq Num (BE)
  5-12: Originator IID (8B)
13-44: Public Key (32B)
45-92: Signature (48B Schnorr)
 93+: Optional App Data

Total fixed: 93 bytes. current_channel (rx_channel) packed at byte 1 (flags byte) and
included in signed_data() to prevent relay tampering per CCP-9. Matches Rust/C/Zephyr,
ccp9*.json vectors, and _l2_announce_with_channel oracle in generate.py.

Why 0x01: unique identifier in routing/control namespace (follows L2_DISPATCH_ROUTING=0x15
at link layer). Other types: 0x02=RREQ, 0x03=RREP, 0x04=RERR.
"""

ANNOUNCE_TYPE = 0x01
SIGNATURE_LENGTH = 48
MAX_ANNOUNCE_HOPS = 15
# Fixed portion per wire format (type+flags+hop+seq+iid+pubkey+sig = 93 bytes).
# Matches test vectors exactly; rx_channel packed into byte 1 (CCP-9).
_FIXED_LENGTH = 1 + 1 + 1 + 2 + 8 + 32 + 48


class AnnounceError(Exception):
    """Raised when an announce message is malformed."""


@dataclass(frozen=True)
class AnnounceMessage:
    """An announce message advertising presence in the mesh (spec 9.2 + CCP-9).

    Security model (spec 9.6, draft-lichen-schnorr-00):
    - Schnorr48 signature proves sender holds private key for the pubkey.
    - TOFU (or DANE/PKIX) binds pubkey to originator_iid.
    - Cannot forge announce for another node's address.
    - Hop count is NOT signed (relays MUST increment it without breaking sig).
    - rx_channel is signed (CCP-9) to prevent tampering with rendezvous info.

    Attributes:
        originator_iid: 8-byte IID of announcer.
        pubkey: 32-byte public key (Ed25519).
        seq_num: 16-bit monotonic sequence (anti-replay).
        hop_count: hops traveled (0-15).
        flags: reserved for future use (currently rx_channel value).
        rx_channel: preferred RX channel 0-7 for rendezvous (CCP-9).
        signature: 48-byte Schnorr48 sig over signed_data().
        app_data: optional authenticated payload.
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
            raise AnnounceError(f"originator_iid must be 8 bytes, got {len(self.originator_iid)}")
        if len(self.pubkey) != 32:
            raise AnnounceError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if not 0 <= self.seq_num <= 0xFFFF:
            raise AnnounceError(f"seq_num out of range: {self.seq_num}")
        if not 0 <= self.hop_count <= 0xFF:
            raise AnnounceError(f"hop_count out of range: {self.hop_count}")
        if not 0 <= self.flags <= 0xFF:
            raise AnnounceError(f"flags out of range: {self.flags}")
        if not 0 <= self.rx_channel <= 7:
            raise AnnounceError(f"invalid rx_channel: {self.rx_channel} (must be 0-7)")
        if self.signature and len(self.signature) != SIGNATURE_LENGTH:
            raise AnnounceError(
                f"signature must be 0 or {SIGNATURE_LENGTH} bytes, got {len(self.signature)}"
            )

    def signed_data(self) -> bytes:
        """Data covered by the Schnorr48 signature (exact for interop).

        Concatenation order (bit-exact with Rust lichen-core, C/Zephyr, test vectors):
            originator_iid (8B) + pubkey (32B) + seq_num (u16 BE, 2B) +
            rx_channel (u8, 1B per CCP-9) + app_data (variable)

        rx_channel is signed to bind the announced rendezvous channel.
        Value 0 = CH0 (control/fallback).

        Why these fields only:
        - originator_iid, pubkey: identity/TOFU binding.
        - seq_num: anti-replay protection.
        - rx_channel: prevents tampering with rendezvous info (CCP-9).
        - app_data: authenticated application payload.

        Why NOT included:
        - hop_count: incremented by every relay.
        - flags/signature: not security-relevant for transcript.

        See draft-lichen-schnorr-00.md Appendix A for test vectors.
        Must match python/src/lichen/crypto/schnorr48.py and Rust equivalent.
        """
        return (
            self.originator_iid
            + self.pubkey
            + self.seq_num.to_bytes(2, "big")
            + self.rx_channel.to_bytes(1, "big")
            + self.app_data
        )

    def to_bytes(self) -> bytes:
        """Serialize to wire format per spec 9.2 + CCP-9.

        Layout: [type, rx_channel/flags, hop, seq_BE, iid, pubkey, sig, app_data...].
        rx_channel placed in byte 1 (as per final spec and vectors). Raises if
        no signature (all announces on wire MUST be signed).
        """
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
        """Parse wire format per spec (CCP-9 layout with rx_channel in byte 1).

        Validates type, minimum length, rx_channel range. Offsets:
        - byte 0: type
        - byte 1: flags/rx_channel
        - byte 2: hop
        - 3:5 seq, 5:13 iid, 13:45 pubkey, 45:93 sig, 93+: app_data
        """
        if len(data) < _FIXED_LENGTH:
            raise AnnounceError(
                f"announce message too short: {len(data)} bytes, need at least {_FIXED_LENGTH}"
            )
        if data[0] != ANNOUNCE_TYPE:
            raise AnnounceError(f"wrong message type: expected {ANNOUNCE_TYPE}, got {data[0]}")
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
                f"hop_count would exceed MAX_ANNOUNCE_HOPS: {new_hop_count} > {MAX_ANNOUNCE_HOPS}"
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
