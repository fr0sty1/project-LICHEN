# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""pcapng packet capture writer for the LICHEN simulator.

This module provides a writer for the pcapng file format, allowing
captured packets to be written to files that can be analyzed with
Wireshark and other network analysis tools.

The format follows IETF draft-tuexen-opsawg-pcapng. Files use link type
LINKTYPE_USER0 (147 / 0x93). Each captured payload is the raw SCHC-compressed
frame as transmitted on the wire (after SCHC compression, before link framing).

Custom EPB options (private use range 0x8000–0x8003):

    0x8000  RSSI        4-byte little-endian signed int32 in dBm
    0x8001  SNR         4-byte little-endian signed int32 in dB
    0x8002  SRC_NODE    UTF-8 string, the source node ID
    0x8003  DST_NODE    UTF-8 string, the destination node ID

A Wireshark Lua dissector for these options is provided at
``tools/wireshark/lichen.lua``. Load it via Edit → Preferences →
Protocols → DissectorTable → Lua scripts, or by placing it in your
Wireshark personal Lua directory.
"""

from __future__ import annotations

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
_OPT_IF_NAME = 2

# Custom option codes (private use range starts at 0x8000)
_OPT_CUSTOM_RSSI = 0x8000
_OPT_CUSTOM_SNR = 0x8001
_OPT_CUSTOM_SRC_NODE = 0x8002
_OPT_CUSTOM_DST_NODE = 0x8003


def _pad_to_4(length: int) -> int:
    """Calculate padding needed to align to 4-byte boundary."""
    return (4 - (length % 4)) % 4


def _write_option(
    f: BinaryIO, code: int, value: bytes
) -> None:
    """Write a pcapng option with padding."""
    padded_len = len(value) + _pad_to_4(len(value))
    f.write(struct.pack("<HH", code, len(value)))
    f.write(value)
    if padded_len > len(value):
        f.write(b"\x00" * (padded_len - len(value)))


def _write_end_of_options(f: BinaryIO) -> None:
    """Write the end-of-options marker."""
    f.write(struct.pack("<HH", _OPT_ENDOFOPT, 0))


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

    def __init__(self, path: str | Path) -> None:
        """Open a pcapng file and write the header blocks.

        Creates a new pcapng file with Section Header Block and
        Interface Description Block.

        Args:
            path: Path to the output file. Will be created or overwritten.
        """
        self._path = Path(path)
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
            65535,  # SnapLen
        )

        # Options: interface name
        if_name = b"lichen-lora"
        options_len = (
            4 + len(if_name) + _pad_to_4(len(if_name))  # if_name option
            + 4  # end of options
        )

        # Block: type + length + fixed + options + length
        block_len = 4 + 4 + len(fixed_fields) + options_len + 4
        f.write(struct.pack("<II", _BLOCK_TYPE_IDB, block_len))
        f.write(fixed_fields)
        _write_option(f, _OPT_IF_NAME, if_name)
        _write_end_of_options(f)
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
            ValueError: If the writer has been closed.
        """
        f = self._require_file()

        # Packet data padded to 4-byte boundary
        data_padded_len = len(data) + _pad_to_4(len(data))

        # Build options
        options: list[tuple[int, bytes]] = []
        if rssi is not None:
            options.append((_OPT_CUSTOM_RSSI, struct.pack("<i", rssi)))
        if snr is not None:
            options.append((_OPT_CUSTOM_SNR, struct.pack("<i", snr)))
        if src_node is not None:
            options.append((_OPT_CUSTOM_SRC_NODE, src_node.encode("utf-8")))
        if dst_node is not None:
            options.append((_OPT_CUSTOM_DST_NODE, dst_node.encode("utf-8")))

        # Calculate options length
        options_len = 0
        for _, value in options:
            options_len += 4 + len(value) + _pad_to_4(len(value))
        options_len += 4  # end of options

        # EPB fixed fields: Interface ID + Timestamp High/Low + Captured/Original Length
        # Fixed fields: 4 + 4 + 4 + 4 + 4 = 20 bytes
        fixed_fields_len = 20

        # Block: type + length + fixed + data + options + length
        block_len = 4 + 4 + fixed_fields_len + data_padded_len + options_len + 4

        # Timestamp split into high/low 32-bit words
        ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
        ts_low = timestamp_us & 0xFFFFFFFF

        # Write block header
        f.write(struct.pack("<II", _BLOCK_TYPE_EPB, block_len))

        # Write fixed fields
        f.write(
            struct.pack(
                "<IIIII",
                0,  # Interface ID
                ts_high,
                ts_low,
                len(data),  # Captured Packet Length
                len(data),  # Original Packet Length
            )
        )

        # Write packet data with padding
        f.write(data)
        if data_padded_len > len(data):
            f.write(b"\x00" * (data_padded_len - len(data)))

        # Write options
        for code, value in options:
            _write_option(f, code, value)
        _write_end_of_options(f)

        # Write block footer
        f.write(struct.pack("<I", block_len))

    def close(self) -> None:
        """Close the pcapng file."""
        if self._file is not None:
            self._file.close()
            self._file = None

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
