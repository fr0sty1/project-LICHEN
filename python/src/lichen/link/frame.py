# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link-layer frame format (spec section 4).

Wire layout (spec 4.1)::

    +--------+--------+-------+--------+----------+---------+--------+
    | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload | MIC    |
    +--------+--------+-------+--------+----------+---------+--------+
       1B       1B       1B      2B       0/2/8B    var      0/48B

``Length`` is the total frame length excluding the Length field itself.
Multi-byte integer fields are big-endian.

The LLSec byte (spec 4.2) packs, from the least-significant bit::

    bits 0-1 : Addr Mode  (0=none/broadcast, 1=16-bit, 2=64-bit, 3=elided)
    bits 2-4 : MIC selector (0 or 1; ignored for wire MIC length)
    bit  5   : Signature present (Schnorr-48, 48 bytes)
    bit  6   : Encrypted (unsupported)
    bit  7   : Reserved (must be 0)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class AddrMode(IntEnum):
    """Destination addressing mode (LLSec bits 0-1, spec 4.3)."""

    NONE = 0  # broadcast, 0 address bytes
    SHORT = 1  # 16-bit short address, 2 bytes
    EXTENDED = 2  # EUI-64, 8 bytes
    ELIDED = 3  # derived from IPv6 destination, 0 address bytes

    @property
    def addr_len(self) -> int:
        """Number of destination-address bytes for this mode."""
        return _ADDR_LEN_TABLE[self]


# Lookup table for AddrMode.addr_len (avoids dict creation on each access).
_ADDR_LEN_TABLE: tuple[int, ...] = (0, 2, 8, 0)  # indexed by AddrMode value


class MicLength(IntEnum):
    """MIC length / compatibility selector (LLSec bits 2-4, spec 4.2).

    Only 0 and 1 are valid (both mean no MIC on unsigned frames);
    values 2-7 are reserved. The enum is the source of truth for
    valid values (see from_bytes()).
    """

    BITS32 = 0  # compatibility selector; unsigned frames have no MIC
    BITS64 = 1  # compatibility selector; unsigned frames have no MIC

    @property
    def mic_len(self) -> int:
        """Number of MIC bytes for this setting."""
        return 4 if self == MicLength.BITS32 else 8


# LLSec bit fields.
_ADDR_MODE_MASK = 0b0000_0011
_MIC_LEN_SHIFT = 2
_MIC_LEN_MASK = 0b0000_0111
_SIGNATURE_BIT = 1 << 5
_ENCRYPTED_BIT = 1 << 6
_RESERVED_BIT = 1 << 7

_MAX_FRAME_BODY = 255  # the Length field is a single byte
MAX_FRAME_BODY = _MAX_FRAME_BODY
_SIGNATURE_LENGTH = 48  # Schnorr-48 signature


class FrameError(Exception):
    """Raised when a link-layer frame is malformed."""


@dataclass
class LichenFrame:
    """A parsed LICHEN link-layer frame.

    Attributes:
        epoch: 8-bit epoch counter (spec 4.4).
        seqnum: 16-bit sequence number (replay protection).
        dst_addr: Destination address bytes; length must match ``addr_mode``.
        payload: Frame payload (SCHC-compressed packet or app data).
        mic: MIC or Schnorr-48 signature (48 bytes if signature_present=True,
            else per mic_length; current profile uses signature in MIC field).
        addr_mode: Destination addressing mode.
        mic_length: MIC length selector (ignored for length when signed).
        signature_present: Whether Schnorr-48 signature is present in MIC field
            (LLSec bit 5; see draft-lichen-schnorr-00). Design note: signature
            reuses mic field for wire compatibility; link_layer.receive strips
            it from payload visible to upper layers.
        encrypted: Whether the unsupported encrypted-frame flag is set.
    """

    epoch: int
    seqnum: int
    dst_addr: bytes
    payload: bytes
    mic: bytes
    addr_mode: AddrMode = AddrMode.NONE
    mic_length: MicLength = MicLength.BITS32
    signature_present: bool = False
    encrypted: bool = False

    def _validate(self) -> None:
        if self.signature_present and self.encrypted:
            raise FrameError("signed and encrypted frames are unsupported")
        if not 0 <= self.epoch <= 0xFF:
            raise FrameError(f"epoch out of range: {self.epoch}")
        if not 0 <= self.seqnum <= 0xFFFF:
            raise FrameError(f"seqnum out of range: {self.seqnum}")
        if len(self.dst_addr) != self.addr_mode.addr_len:
            raise FrameError(
                f"dst_addr is {len(self.dst_addr)} bytes but {self.addr_mode.name} "
                f"requires {self.addr_mode.addr_len}"
            )
        expected_mic_len = _SIGNATURE_LENGTH if self.signature_present else 0
        if len(self.mic) != expected_mic_len:
            raise FrameError(
                f"mic is {len(self.mic)} bytes but {expected_mic_len} are required"
            )

    def llsec_byte(self) -> int:
        """Compute the LLSec flags byte."""
        value = int(self.addr_mode) & _ADDR_MODE_MASK
        value |= (int(self.mic_length) & _MIC_LEN_MASK) << _MIC_LEN_SHIFT
        if self.signature_present:
            value |= _SIGNATURE_BIT
        if self.encrypted:
            value |= _ENCRYPTED_BIT
        return value

    def to_bytes(self) -> bytes:
        """Serialize the frame to its on-air byte representation.

        Raises:
            FrameError: If a field is out of range, lengths are inconsistent
                with the LLSec modes, or the frame exceeds 254 body bytes.
        """
        self._validate()
        body_len = 4 + len(self.dst_addr) + len(self.payload) + len(self.mic)
        if body_len > MAX_FRAME_BODY:
            raise FrameError(
                f"frame body is {body_len} bytes, exceeds {MAX_FRAME_BODY}"
            )
        body = (
            bytes([self.llsec_byte(), self.epoch])
            + self.seqnum.to_bytes(2, "big")
            + self.dst_addr
            + self.payload
            + self.mic
        )
        return bytes([len(body)]) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> LichenFrame:
        """Parse a frame from its on-air byte representation.

        Raises:
            FrameError: If the data is truncated, the length field is wrong, the
                reserved bit is set, or the MIC-length field is reserved.
        """
        if len(data) < 1:
            raise FrameError("frame is empty")
        if len(data) > MAX_FRAME_BODY + 1:
            raise FrameError(
                f"frame is {len(data)} bytes, exceeds {MAX_FRAME_BODY + 1}"
            )
        length = data[0]
        if length > MAX_FRAME_BODY:
            raise FrameError(
                f"frame body is {length} bytes, exceeds {MAX_FRAME_BODY}"
            )
        received_body_len = len(data) - 1
        if received_body_len != length:
            raise FrameError(
                f"length field says {length} but {received_body_len} body bytes present"
            )
        body = data[1:]
        # Fixed fields: LLSec(1) + Epoch(1) + SeqNum(2) = 4 bytes minimum.
        if length < 4:
            raise FrameError(f"frame body too short: {length} bytes")

        llsec = body[0]
        if llsec & _RESERVED_BIT:
            raise FrameError("LLSec reserved bit (7) must be 0")
        addr_mode = AddrMode(llsec & _ADDR_MODE_MASK)
        mic_field = (llsec >> _MIC_LEN_SHIFT) & _MIC_LEN_MASK
        try:
            mic_length = MicLength(mic_field)
        except ValueError:
            raise FrameError(f"reserved MIC-length value: {mic_field}") from None

        epoch = body[1]
        seqnum = int.from_bytes(body[2:4], "big")

        offset = 4
        addr_len = addr_mode.addr_len
        signature_present = bool(llsec & _SIGNATURE_BIT)
        if signature_present and llsec & _ENCRYPTED_BIT:
            raise FrameError("signed and encrypted frames are unsupported")
        # SECURITY: Reject frames where signature_present is set but the frame
        # body is too short for the 48-byte Schnorr signature. An attacker could
        # set the signature bit without appending a signature, hoping the parser
        # reads past the buffer (over-read) or misinterprets payload bytes as MIC.
        mic_len = _SIGNATURE_LENGTH if signature_present else 0
        if length < offset + addr_len + mic_len:
            raise FrameError("frame too short for declared address/MIC sizes")

        dst_addr = body[offset : offset + addr_len]
        offset += addr_len
        payload = body[offset : len(body) - mic_len]
        mic = body[len(body) - mic_len :]

        return cls(
            epoch=epoch,
            seqnum=seqnum,
            dst_addr=dst_addr,
            payload=payload,
            mic=mic,
            addr_mode=addr_mode,
            mic_length=mic_length,
            signature_present=signature_present,
            encrypted=bool(llsec & _ENCRYPTED_BIT),
        )
