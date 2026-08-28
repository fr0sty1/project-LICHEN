# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Frame data classes for LICHEN link layer reception.

This module contains the data classes used for received frame metadata and
verification receipts. These are extracted from link_layer.py to reduce
module size and improve organization.

Classes:
    RxFrame: A received and validated frame with metadata (sender, RSSI, SNR).
    ReceiveError: Enumeration of receive-time frame rejection reasons.
    _VerifiedReceipt: Internal receipt binding a facade to its snapshot.
    _AuthenticatedPeerSchcIssuance: Internal SCHC context issuance record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

from ..crypto.identity import PeerIdentity
from .frame import AddrMode, LichenFrame, MicLength

if TYPE_CHECKING:
    from ..schc.context import AuthenticatedPeerSchcContext


@dataclass(frozen=True, init=False)
class RxFrame:
    """A received and validated frame with metadata.

    Why a separate class: Callers need both the frame content and reception
    metadata (RSSI, SNR) for link quality estimation and routing decisions.

    Attributes:
        frame: The parsed and validated LichenFrame.
        sender: The sender's identity (verified by signature).
        rssi_dbm: Received signal strength in dBm.
        snr_db: Signal-to-noise ratio in dB.
    """

    sender: PeerIdentity
    rssi_dbm: int
    snr_db: int
    _authenticated_payload: bytes = field(repr=False)
    _authenticated_sender_pubkey: bytes = field(repr=False)
    _authenticated_local_pubkey: bytes = field(repr=False)
    _authenticated_epoch: int = field(repr=False)
    _authenticated_seqnum: int = field(repr=False)
    _authenticated_dst_addr: bytes = field(repr=False)
    _authenticated_signer_eui64: bytes = field(repr=False)
    _authenticated_mic: bytes = field(repr=False)
    _authenticated_addr_mode: AddrMode = field(repr=False)
    _authenticated_mic_length: MicLength = field(repr=False)
    _authenticated_signature_present: bool = field(repr=False)
    _authenticated_encrypted: bool = field(repr=False)
    _authenticated_received_monotonic: float = field(repr=False)
    _authenticated_clock_domain: object = field(repr=False)
    _authenticated_key_generation: object = field(repr=False)
    _authenticated_receiving_link_identity: object = field(repr=False)

    def __new__(cls) -> RxFrame:
        raise TypeError("RxFrame values are issued only by LinkLayer.receive")

    @property
    def frame(self) -> LichenFrame:
        """Return a detached copy of the fully authenticated frame snapshot."""
        return LichenFrame(
            epoch=self._authenticated_epoch,
            seqnum=self._authenticated_seqnum,
            dst_addr=self._authenticated_dst_addr,
            signer_eui64=self._authenticated_signer_eui64,
            payload=self._authenticated_payload,
            mic=self._authenticated_mic,
            addr_mode=self._authenticated_addr_mode,
            mic_length=self._authenticated_mic_length,
            signature_present=self._authenticated_signature_present,
            encrypted=self._authenticated_encrypted,
        )

    @property
    def payload(self) -> bytes:
        """Authenticated frame payload."""
        return self._authenticated_payload

    @property
    def sender_iid(self) -> bytes:
        """Authenticated sender IID."""
        return self.sender.iid

    @property
    def sender_pubkey(self) -> bytes:
        """Authenticated sender public key."""
        return self._authenticated_sender_pubkey

    @property
    def local_pubkey(self) -> bytes:
        """Canonical local signer identity of the receiving link layer."""
        return self._authenticated_local_pubkey

    @property
    def epoch(self) -> int:
        """Authenticated and replay-accepted link epoch."""
        return self._authenticated_epoch

    @property
    def seqnum(self) -> int:
        """Authenticated and replay-accepted link sequence number."""
        return self._authenticated_seqnum

    @property
    def received_monotonic(self) -> float:
        """Link-stamped monotonic reception time in seconds."""
        return self._authenticated_received_monotonic

    @property
    def clock_domain(self) -> object:
        """Opaque identity for the receiving link's monotonic clock domain."""
        return self._authenticated_clock_domain

    @property
    def key_generation(self) -> object:
        """Opaque identity for the authenticated peer-key generation."""
        return self._authenticated_key_generation

    @property
    def receiving_link_identity(self) -> object:
        """Opaque identity for the exact LinkLayer that accepted this frame."""
        return self._authenticated_receiving_link_identity


class ReceiveError(IntEnum):
    MALFORMED = 1
    UNSIGNED = 2
    ENCRYPTED = 3
    BAD_SIGNATURE = 4
    KEY_CHANGE = 5
    MIC_FAILED = 6
    REPLAY = 7
    NOT_FOR_US = 8
    CAPACITY_EXHAUSTED = 9


@dataclass(frozen=True)
class _VerifiedReceipt:
    facade: RxFrame
    snapshot: RxFrame
    expires_at: float
    sender_was_pinned: bool


@dataclass(frozen=True)
class _AuthenticatedPeerSchcIssuance:
    facade: AuthenticatedPeerSchcContext
    remote_version: int
    signer_identity: bytes
    key_generation: object
    admitted_counter: int = -1
