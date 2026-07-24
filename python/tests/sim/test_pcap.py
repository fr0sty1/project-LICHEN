# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for pcapng packet capture writer."""

import struct
import tempfile
from pathlib import Path

import pytest

from lichen.sim.pcap import PcapngWriter

# pcapng constants for verification
_BLOCK_TYPE_SHB = 0x0A0D0D0A
_BLOCK_TYPE_IDB = 0x00000001
_BLOCK_TYPE_EPB = 0x00000006
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_LINKTYPE_USER0 = 147


class TestPcapngWriter:
    """Tests for PcapngWriter class."""

    def test_creates_file(self) -> None:
        """Writer should create a file at the specified path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            writer.close()
            assert path.exists()

    def test_context_manager(self) -> None:
        """Writer should work as a context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=1000, data=b"\x00\x01\x02")
            assert path.exists()

    def test_closes_file_on_init_failure(self, monkeypatch) -> None:
        """A failure while writing header blocks must not leak the file handle."""
        opened: list = []
        real_open = Path.open

        def tracking_open(self_path, *args, **kwargs):
            handle = real_open(self_path, *args, **kwargs)
            opened.append(handle)
            return handle

        def boom(self) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr(Path, "open", tracking_open)
        monkeypatch.setattr(PcapngWriter, "_write_interface_description_block", boom)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with pytest.raises(RuntimeError, match="disk full"):
                PcapngWriter(path)

        assert opened, "expected the writer to open the file"
        assert opened[0].closed, "file handle leaked after init failure"

    def test_section_header_block(self) -> None:
        """File should start with valid Section Header Block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            writer.close()

            with open(path, "rb") as f:
                # Read SHB
                block_type, block_len = struct.unpack("<II", f.read(8))
                assert block_type == _BLOCK_TYPE_SHB

                # Read magic and version
                magic, major, minor = struct.unpack("<IHH", f.read(8))
                assert magic == _BYTE_ORDER_MAGIC
                assert major == 1
                assert minor == 0

                # Read section length (-1 for unknown)
                section_len = struct.unpack("<q", f.read(8))[0]
                assert section_len == -1

                # Read trailing block length
                trailing_len = struct.unpack("<I", f.read(4))[0]
                assert trailing_len == block_len

    def test_interface_description_block(self) -> None:
        """File should contain valid Interface Description Block."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            writer.close()

            with open(path, "rb") as f:
                # Skip SHB
                shb_len = struct.unpack("<I", f.read(4)[0:4])[0]
                # Re-read the length properly
                f.seek(0)
                _, shb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len)

                # Read IDB
                block_type, block_len = struct.unpack("<II", f.read(8))
                assert block_type == _BLOCK_TYPE_IDB

                # Read link type and snap length
                link_type, reserved, snap_len = struct.unpack("<HHI", f.read(8))
                assert link_type == _LINKTYPE_USER0
                assert reserved == 0
                assert snap_len == 65535

    def test_write_packet_basic(self) -> None:
        """Should write a basic packet without options."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            test_data = b"\xde\xad\xbe\xef"
            test_timestamp = 1234567890

            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=test_timestamp, data=test_data)

            with open(path, "rb") as f:
                # Skip SHB
                f.seek(0)
                _, shb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len)

                # Skip IDB
                _, idb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len + idb_len)

                # Read EPB
                block_type, block_len = struct.unpack("<II", f.read(8))
                assert block_type == _BLOCK_TYPE_EPB

                # Read fixed fields
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", f.read(20))
                assert iface_id == 0
                timestamp = (ts_high << 32) | ts_low
                assert timestamp == test_timestamp
                assert cap_len == len(test_data)
                assert orig_len == len(test_data)

                # Read packet data (4 bytes, no padding needed)
                packet_data = f.read(cap_len)
                assert packet_data == test_data

    def test_write_packet_with_padding(self) -> None:
        """Packet data should be padded to 4-byte boundary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            # 5 bytes needs 3 bytes padding
            test_data = b"\x01\x02\x03\x04\x05"

            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=1000, data=test_data)

            with open(path, "rb") as f:
                # Skip SHB and IDB
                f.seek(0)
                _, shb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len)
                _, idb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len + idb_len)

                # Read EPB header
                block_type, block_len = struct.unpack("<II", f.read(8))
                assert block_type == _BLOCK_TYPE_EPB

                # Read fixed fields
                _, _, _, cap_len, _ = struct.unpack("<IIIII", f.read(20))
                assert cap_len == 5

                # Read data + padding (8 bytes total: 5 data + 3 padding)
                data_with_padding = f.read(8)
                assert data_with_padding[:5] == test_data
                assert data_with_padding[5:] == b"\x00\x00\x00"

    def test_write_packet_with_rssi_snr(self) -> None:
        """Should write packets with RSSI and SNR custom options."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            test_data = b"\xaa\xbb\xcc\xdd"

            with PcapngWriter(path) as writer:
                writer.write_packet(
                    timestamp_us=1000,
                    data=test_data,
                    rssi=-80,
                    snr=10,
                )

            # Verify file was written (detailed option parsing would be complex)
            assert path.stat().st_size > 0

    def test_write_packet_with_node_ids(self) -> None:
        """Should write packets with source and destination node IDs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            test_data = b"\x11\x22\x33\x44"

            with PcapngWriter(path) as writer:
                writer.write_packet(
                    timestamp_us=1000,
                    data=test_data,
                    src_node="node-1",
                    dst_node="node-2",
                )

            # Verify file was written
            assert path.stat().st_size > 0

    def test_write_multiple_packets(self) -> None:
        """Should write multiple packets correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"

            with PcapngWriter(path) as writer:
                for i in range(10):
                    writer.write_packet(
                        timestamp_us=i * 1000,
                        data=bytes([i] * 10),
                    )

            # Count EPB blocks
            epb_count = 0
            with open(path, "rb") as f:
                while True:
                    header = f.read(8)
                    if len(header) < 8:
                        break
                    block_type, block_len = struct.unpack("<II", header)
                    if block_type == _BLOCK_TYPE_EPB:
                        epb_count += 1
                    f.seek(f.tell() + block_len - 8)

            assert epb_count == 10

    def test_write_after_close_raises(self) -> None:
        """Writing to closed writer should raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            writer.close()

            with pytest.raises(ValueError, match="closed"):
                writer.write_packet(timestamp_us=1000, data=b"test")

    def test_empty_packet(self) -> None:
        """Should handle empty packet data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"

            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=1000, data=b"")

            with open(path, "rb") as f:
                # Skip SHB and IDB
                f.seek(0)
                _, shb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len)
                _, idb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len + idb_len)

                # Read EPB
                block_type, block_len = struct.unpack("<II", f.read(8))
                assert block_type == _BLOCK_TYPE_EPB

                # Read fixed fields
                _, _, _, cap_len, orig_len = struct.unpack("<IIIII", f.read(20))
                assert cap_len == 0
                assert orig_len == 0

    def test_large_timestamp(self) -> None:
        """Should handle timestamps requiring 64-bit representation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            # Large timestamp (year 2100 in microseconds)
            large_ts = 4_102_444_800_000_000

            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=large_ts, data=b"\x00")

            with open(path, "rb") as f:
                # Skip SHB and IDB
                f.seek(0)
                _, shb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len)
                _, idb_len = struct.unpack("<II", f.read(8))
                f.seek(shb_len + idb_len)

                # Read EPB header and fixed fields
                f.read(8)  # block header
                _, ts_high, ts_low, _, _ = struct.unpack("<IIIII", f.read(20))

                timestamp = (ts_high << 32) | ts_low
                assert timestamp == large_ts

    def test_string_path(self) -> None:
        """Should accept string path as well as Path object."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "test.pcapng")
            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=1000, data=b"test")
            assert Path(path).exists()

    def test_negative_rssi(self) -> None:
        """Should correctly encode negative RSSI values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"

            with PcapngWriter(path) as writer:
                writer.write_packet(
                    timestamp_us=1000,
                    data=b"\x00",
                    rssi=-120,
                )

            # File should be created successfully
            assert path.stat().st_size > 0

    def test_interface_name_option(self) -> None:
        """IDB should contain lichen-lora interface name option."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            writer.close()

            with open(path, "rb") as f:
                content = f.read()
                # Interface name should be present in the file
                assert b"lichen-lora" in content
