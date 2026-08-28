# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""pcapng packet capture writer for the LICHEN simulator.

This module provides a writer for the pcapng file format, allowing
captured packets to be written to files that can be analyzed with
Wireshark and other network analysis tools.

The format follows IETF draft-tuexen-opsawg-pcapng. Files use link type
LINKTYPE_USER0 (147 / 0x93). Each captured payload is the complete
LICHEN link-layer frame as transmitted on the wire (including the Length
byte, LLSec flags, Epoch, SeqNum, Dst Addr, SCHC payload, and MIC).

Optional RSSI, SNR, source-node, and destination-node metadata is stored as
bounded JSON in the standard EPB comment option. Standard options avoid
collisions with registered pcapng option codes and remain visible to generic
readers even when the LICHEN dissector is not installed.

The IDB explicitly declares microsecond timestamp resolution and records
the configured LoRa spreading factor, bandwidth, and coding rate in its
standard interface-description option.

A Wireshark Lua dissector that decodes these frames and options is
provided at ``tools/wireshark/lichen.lua``. Place it in your Wireshark
personal Lua directory (~/.config/wireshark/ on Linux/macOS) and
restart Wireshark.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import BinaryIO

# Block type constants
_BLOCK_TYPE_SHB = 0x0A0D0D0A  # Section Header Block
_BLOCK_TYPE_IDB = 0x00000001  # Interface Description Block
_BLOCK_TYPE_EPB = 0x00000006  # Enhanced Packet Block

# pcapng magic values
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_PCAPNG_VERSION_MAJOR = 1
_PCAPNG_VERSION_MINOR = 0

# Link type for custom protocols
_LINKTYPE_USER0 = 147

# Interface options
_OPT_ENDOFOPT = 0
_OPT_COMMENT = 1
_OPT_IF_NAME = 2
_OPT_IF_DESCRIPTION = 3
_OPT_IF_TSRESOL = 9

_SNAPLEN = 65535
_MAX_NODE_ID_LENGTH = 255
_UINT32_MAX = 0xFFFFFFFF
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF
_INT32_MIN = -0x80000000
_INT32_MAX = 0x7FFFFFFF


def _pad_to_4(length: int) -> int:
    """Calculate padding needed to align to 4-byte boundary."""
    return (4 - (length % 4)) % 4


def _encode_option(code: int, value: bytes) -> bytes:
    """Encode one pcapng option, including its zero alignment padding."""
    if not 0 <= code <= 0xFFFF:
        raise ValueError(f"pcapng option code out of range: {code}")
    if len(value) > 0xFFFF:
        raise ValueError(f"pcapng option value too long: {len(value)}")
    padded_len = len(value) + _pad_to_4(len(value))
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (padded_len - len(value))


class PcapngWriter:
    """Writer for pcapng packet capture files.

    This class creates pcapng files suitable for analysis with Wireshark
    and other network tools. It writes packets with timestamps and optional
    metadata like RSSI, SNR, and node identifiers.

    The pcapng format is specified in IETF draft-tuexen-opsawg-pcapng.

    Example:
        >>> with PcapngWriter("capture.pcapng") as writer:
        ...     writer.write_packet(timestamp_us=1000, data=b"\\x00\\x01\\x02")
    """

    def __init__(
        self,
        path: str | Path,
        *,
        spreading_factor: int = 10,
        bandwidth_hz: int = 125_000,
        coding_rate: int = 1,
    ) -> None:
        """Open a pcapng file and write the header blocks.

        Creates a new pcapng file with Section Header Block and
        Interface Description Block.

        Args:
            path: Path to the output file. Will be created or overwritten.
            spreading_factor: LoRa spreading factor, in the range 5..12.
            bandwidth_hz: LoRa bandwidth in Hz, as a positive uint32.
            coding_rate: LoRa coding-rate denominator offset (1..4 means 4/5..4/8).
        """
        if type(spreading_factor) is not int or not 5 <= spreading_factor <= 12:
            raise ValueError("spreading_factor must be an integer in [5, 12]")
        if type(bandwidth_hz) is not int or not 1 <= bandwidth_hz <= _UINT32_MAX:
            raise ValueError("bandwidth_hz must be a positive uint32")
        if type(coding_rate) is not int or not 1 <= coding_rate <= 4:
            raise ValueError("coding_rate must be an integer in [1, 4]")

        self._path = Path(path)
        self._spreading_factor = spreading_factor
        self._bandwidth_hz = bandwidth_hz
        self._coding_rate = coding_rate
        self._file: BinaryIO | None = self._path.open("wb")
        try:
            self._write_section_header_block()
            self._write_interface_description_block()
        except BaseException:
            # Don't leak the open handle if writing the header blocks fails.
            self._file.close()
            self._file = None
            raise

    def _require_file(self) -> BinaryIO:
        """Return the file handle or raise if closed.

        Returns:
            The open file handle.

        Raises:
            ValueError: If the writer has been closed.
        """
        if self._file is None:
            raise ValueError("Cannot write to closed PcapngWriter")
        return self._file

    def _write_section_header_block(self) -> None:
        """Write the Section Header Block (SHB)."""
        f = self._require_file()

        # SHB body: magic + version + section length
        body = struct.pack(
            "<IHHq",
            _BYTE_ORDER_MAGIC,
            _PCAPNG_VERSION_MAJOR,
            _PCAPNG_VERSION_MINOR,
            -1,  # Section length unknown
        )

        # Block: type + length + body + length
        block_len = 4 + 4 + len(body) + 4
        f.write(struct.pack("<II", _BLOCK_TYPE_SHB, block_len))
        f.write(body)
        f.write(struct.pack("<I", block_len))

    def _write_interface_description_block(self) -> None:
        """Write the Interface Description Block (IDB)."""
        f = self._require_file()

        # IDB fixed fields: LinkType (2) + Reserved (2) + SnapLen (4)
        fixed_fields = struct.pack(
            "<HHI",
            _LINKTYPE_USER0,  # LinkType
            0,  # Reserved
            _SNAPLEN,  # SnapLen
        )

        # Explicit timestamp resolution is 10^-6 seconds, so EPB timestamps
        # are interpreted exactly as the timestamp_us API documents.
        description = (
            f"LoRa SF={self._spreading_factor} BW={self._bandwidth_hz}Hz "
            f"CR=4/{self._coding_rate + 4}"
        ).encode("ascii")
        options = b"".join(
            (
                _encode_option(_OPT_IF_NAME, b"lichen-lora"),
                _encode_option(_OPT_IF_DESCRIPTION, description),
                _encode_option(_OPT_IF_TSRESOL, b"\x06"),
                struct.pack("<HH", _OPT_ENDOFOPT, 0),
            )
        )

        # Block: type + length + fixed + options + length
        block_len = 4 + 4 + len(fixed_fields) + len(options) + 4
        f.write(struct.pack("<II", _BLOCK_TYPE_IDB, block_len))
        f.write(fixed_fields)
        f.write(options)
        f.write(struct.pack("<I", block_len))

    def write_packet(
        self,
        timestamp_us: int,
        data: bytes,
        rssi: int | None = None,
        snr: int | None = None,
        src_node: str | None = None,
        dst_node: str | None = None,
    ) -> None:
        """Write an Enhanced Packet Block (EPB).

        Args:
            timestamp_us: Packet timestamp in microseconds since epoch.
            data: Raw packet data.
            rssi: Optional RSSI value in dBm.
            snr: Optional SNR value in dB.
            src_node: Optional source node identifier.
            dst_node: Optional destination node identifier.

        Raises:
            ValueError: If the writer is closed or a field is outside its
                pcapng encoding range.
        """
        f = self._require_file()

        if type(timestamp_us) is not int or not 0 <= timestamp_us <= _UINT64_MAX:
            raise ValueError("timestamp_us must be an unsigned 64-bit integer")
        if type(data) is not bytes:
            raise TypeError("data must be bytes")
        if len(data) > _SNAPLEN:
            raise ValueError(f"packet exceeds pcapng snap length: {len(data)} > {_SNAPLEN}")
        for name, value in (("rssi", rssi), ("snr", snr)):
            if value is not None and (
                type(value) is not int or not _INT32_MIN <= value <= _INT32_MAX
            ):
                raise ValueError(f"{name} must be a signed 32-bit integer")

        # Packet data padded to 4-byte boundary
        padded_data = data + b"\x00" * _pad_to_4(len(data))

        # Validate and encode all options before writing any part of the EPB.
        # This prevents a bad metadata value from leaving a partial block.
        metadata: dict[str, int | str] = {}
        if rssi is not None:
            metadata["rssi"] = rssi
        if snr is not None:
            metadata["snr"] = snr
        if src_node is not None:
            if type(src_node) is not str:
                raise TypeError("src_node must be str or None")
            src_node_bytes = src_node.encode("utf-8")
            if len(src_node_bytes) > _MAX_NODE_ID_LENGTH:
                raise ValueError("src_node UTF-8 encoding exceeds 255 bytes")
            metadata["src_node"] = src_node
        if dst_node is not None:
            if type(dst_node) is not str:
                raise TypeError("dst_node must be str or None")
            dst_node_bytes = dst_node.encode("utf-8")
            if len(dst_node_bytes) > _MAX_NODE_ID_LENGTH:
                raise ValueError("dst_node UTF-8 encoding exceeds 255 bytes")
            metadata["dst_node"] = dst_node
        encoded_options = b""
        if metadata:
            comment = json.dumps(
                metadata,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            encoded_options = _encode_option(_OPT_COMMENT, comment)
        encoded_options += struct.pack("<HH", _OPT_ENDOFOPT, 0)

        # Timestamp split into high/low 32-bit words
        ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
        ts_low = timestamp_us & 0xFFFFFFFF

        fixed_fields = struct.pack(
            "<IIIII",
            0,  # Interface ID
            ts_high,
            ts_low,
            len(data),  # Captured Packet Length
            len(data),  # Original Packet Length
        )
        block_len = 12 + len(fixed_fields) + len(padded_data) + len(encoded_options)
        block = (
            struct.pack("<II", _BLOCK_TYPE_EPB, block_len)
            + fixed_fields
            + padded_data
            + encoded_options
            + struct.pack("<I", block_len)
        )
        f.write(block)

    def flush(self) -> None:
        """Flush buffered capture bytes to the underlying file."""
        self._require_file().flush()

    def close(self) -> None:
        """Close the pcapng file."""
        if self._file is not None:
            f = self._file
            self._file = None
            f.close()

    def __enter__(self) -> PcapngWriter:
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager, closing the file."""
        self.close()
