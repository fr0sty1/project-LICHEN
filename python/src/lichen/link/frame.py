# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link-layer frame format (spec section 4).

Wire layout (spec 4.1)::

    +--------+--------+-------+--------+----------+------+---------+--------+
    | Length | LLSec  | Epoch | SeqNum | Dst Addr | SIID | Payload | MIC    |
    +--------+--------+-------+--------+----------+------+---------+--------+
       1B       1B       1B      2B       0/2/8B    0/8B   var      0/48B

``Length`` is the total frame length excluding the Length field itself.
Multi-byte integer fields are big-endian.

The LLSec byte (spec 4.2) packs, from the least-significant bit::

    bits 0-1 : Addr Mode  (0=none/broadcast, 1=16-bit, 2=64-bit, 3=elided)
    bits 2-4 : MIC selector (0 or 1; ignored for wire MIC length)
    bit  5   : Signature present (Schnorr-48, 48 bytes)
    bit  6   : Encrypted (unsupported; receivers MUST reject)
    bit  7   : Signer identifier present (SI; canonical EUI-64; MUST equal S)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# Exact application-domain prefix for every link Schnorr-48 transcript.
# Changing these octets is a protocol-version change.
LINK_SIGNATURE_DOMAIN = b"LICHEN-LINK-v1\x00"


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


# Lookup table for AddrMode.addr_len (dict is robust against enum value changes).
_ADDR_LEN_TABLE: dict[AddrMode, int] = {
    AddrMode.NONE: 0,
    AddrMode.SHORT: 2,
    AddrMode.EXTENDED: 8,
    AddrMode.ELIDED: 0,
}


class MicLength(IntEnum):
    """MIC length / compatibility selector (LLSec bits 2-4, spec 4.2).

    Only 0 and 1 are valid (both mean no MIC on unsigned frames);
    values 2-7 are reserved. The enum is the source of truth for
    valid values (see from_bytes()).
    """

    BITS32 = 0  # compatibility selector; unsigned frames have no MIC
    BITS64 = 1  # compatibility selector; unsigned frames have no MIC

    def wire_mic_len(self, *, signature_present: bool) -> int:
        """Return the profile MIC width for this selector and signature state.

        The selector is retained for compatibility but does not select a wire
        width in the current profile. Unsigned frames carry no MIC, while both
        selector values carry the full Schnorr-48 value when signed.
        """
        if type(signature_present) is not bool:
            raise TypeError("signature_present must be bool")
        return _SIGNATURE_LENGTH if signature_present else 0


# LLSec bit fields.
_ADDR_MODE_MASK = 0b0000_0011
_MIC_LEN_SHIFT = 2
_MIC_LEN_MASK = 0b0000_0111
_SIGNATURE_BIT = 1 << 5
_ENCRYPTED_BIT = 1 << 6
_SI_BIT = 1 << 7

_MAX_FRAME_BODY = 254  # spec 4.1: Length field value is 4-254 bytes
MAX_FRAME_BODY = _MAX_FRAME_BODY
_SIGNATURE_LENGTH = 48  # Schnorr-48 signature


class FrameError(Exception):
    """Raised when a link-layer frame is malformed."""


class EncryptedFrameError(FrameError):
    """Raised when the unsupported encrypted-frame flag is present."""


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
            (LLSec bit 5; see draft-lichen-schnorr-00). The signature lives
            entirely in the 48-byte MIC field; the payload is delivered to
            consumers whole, with no bytes stripped for signatures.
        encrypted: Whether the unsupported encrypted-frame flag is set.
        signer_eui64: The signer's canonical EUI-64 wire value. It is modified
            into an IPv6 IID only when resolving the link address. Present
            exactly when signed.
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
    signer_eui64: bytes = b""

    def _validate(self) -> None:
        if type(self.addr_mode) is not AddrMode:
            raise FrameError("addr_mode must be an AddrMode")
        if type(self.mic_length) is not MicLength:
            raise FrameError("mic_length must be a supported MicLength selector")
        if type(self.signature_present) is not bool:
            raise FrameError("signature_present must be bool")
        if type(self.encrypted) is not bool:
            raise FrameError("encrypted must be bool")
        if type(self.epoch) is not int:
            raise FrameError("epoch must be an integer")
        if type(self.seqnum) is not int:
            raise FrameError("seqnum must be an integer")
        for name, value in (
            ("dst_addr", self.dst_addr),
            ("payload", self.payload),
            ("mic", self.mic),
            ("signer_eui64", self.signer_eui64),
        ):
            if type(value) is not bytes:
                raise FrameError(f"{name} must be bytes")
        if self.encrypted:
            raise FrameError("encrypted frames are unsupported")
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
            raise FrameError(f"mic is {len(self.mic)} bytes but {expected_mic_len} are required")
        if bool(self.signer_eui64) != self.signature_present:
            raise FrameError("signature and signer EUI-64 presence must match")
        if self.signature_present and len(self.signer_eui64) != 8:
            raise FrameError("signed frame requires an 8-byte signer EUI-64")

    def llsec_byte(self) -> int:
        """Compute the LLSec flags byte."""
        value = int(self.addr_mode) & _ADDR_MODE_MASK
        value |= (int(self.mic_length) & _MIC_LEN_MASK) << _MIC_LEN_SHIFT
        if self.signature_present:
            value |= _SIGNATURE_BIT
        if self.encrypted:
            value |= _ENCRYPTED_BIT
        if self.signer_eui64:
            value |= _SI_BIT
        return value

    def to_bytes(self) -> bytes:
        """Serialize the frame to its on-air byte representation.

        Raises:
            FrameError: If a field is out of range, lengths are inconsistent
                with the LLSec modes, or the frame exceeds 254 body bytes.
        """
        self._validate()
        body_len = (
            4 + len(self.dst_addr) + len(self.signer_eui64) + len(self.payload) + len(self.mic)
        )
        if body_len > MAX_FRAME_BODY:
            raise FrameError(f"frame body is {body_len} bytes, exceeds {MAX_FRAME_BODY}")
        body = (
            bytes([self.llsec_byte(), self.epoch])
            + self.seqnum.to_bytes(2, "big")
            + self.dst_addr
            + self.signer_eui64
            + self.payload
            + self.mic
        )
        return bytes([len(body)]) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> LichenFrame:
        """Parse a frame from its on-air byte representation.

        Raises:
            FrameError: If the data is truncated, the length field is wrong, the
                signature/SIID flags disagree, or the MIC-length field is reserved.
        """
        if type(data) is not bytes:
            raise FrameError("frame must be bytes")
        if len(data) < 1:
            raise FrameError("frame is empty")
        if len(data) > MAX_FRAME_BODY + 1:
            raise FrameError(f"frame is {len(data)} bytes, exceeds {MAX_FRAME_BODY + 1}")
        length = data[0]
        if length > MAX_FRAME_BODY:
            raise FrameError(f"frame body is {length} bytes, exceeds {MAX_FRAME_BODY}")
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
        # SECURITY: Encrypted frames are unsupported; receivers MUST reject
        # them before signature or reserved-bit processing so E=1 always
        # reports as unsupported encryption (spec 4.2).
        if llsec & _ENCRYPTED_BIT:
            raise EncryptedFrameError("encrypted frames are unsupported")
        addr_mode = AddrMode(llsec & _ADDR_MODE_MASK)
        mic_field = (llsec >> _MIC_LEN_SHIFT) & _MIC_LEN_MASK
        try:
            mic_length = MicLength(mic_field)
        except ValueError:
            # SECURITY: A malicious frame could set the signature bit (bit 5)
            # while using a reserved MIC-length value to claim no signature
            # bytes follow, causing the receiver to parse signature bytes as
            # payload.  Rejecting reserved values closes this vector.
            raise FrameError(f"reserved MIC-length value: {mic_field}") from None

        epoch = body[1]
        seqnum = int.from_bytes(body[2:4], "big")

        offset = 4
        addr_len = addr_mode.addr_len
        signature_present = bool(llsec & _SIGNATURE_BIT)
        signer_eui64_present = bool(llsec & _SI_BIT)
        if signer_eui64_present != signature_present:
            raise FrameError("signature and signer EUI-64 presence bits must match")
        # SECURITY: Reject frames where signature_present is set but the frame
        # body is too short for the 48-byte Schnorr signature. An attacker could
        # set the signature bit without appending a signature, hoping the parser
        # reads past the buffer (over-read) or misinterprets payload bytes as MIC.
        mic_len = _SIGNATURE_LENGTH if signature_present else 0
        signer_eui64_len = 8 if signer_eui64_present else 0
        if length < offset + addr_len + signer_eui64_len + mic_len:
            raise FrameError("frame too short for declared address/MIC sizes")

        dst_addr = body[offset : offset + addr_len]
        offset += addr_len
        signer_eui64 = body[offset : offset + signer_eui64_len]
        offset += signer_eui64_len
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
            signer_eui64=signer_eui64,
        )
