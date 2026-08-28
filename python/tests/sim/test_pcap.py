# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for pcapng packet capture writer."""

import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

import pytest

from lichen.sim.pcap import PcapngWriter

# pcapng constants for verification
_BLOCK_TYPE_SHB = 0x0A0D0D0A
_BLOCK_TYPE_IDB = 0x00000001
_BLOCK_TYPE_EPB = 0x00000006
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_LINKTYPE_USER0 = 147


def _read_blocks(path: Path) -> list[tuple[int, bytes]]:
    """Parse block envelopes and assert pcapng length invariants."""
    content = path.read_bytes()
    blocks: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        assert offset + 12 <= len(content)
        block_type, block_len = struct.unpack_from("<II", content, offset)
        assert block_len >= 12
        assert block_len % 4 == 0
        block_end = offset + block_len
        assert block_end <= len(content)
        assert struct.unpack_from("<I", content, block_end - 4)[0] == block_len
        blocks.append((block_type, content[offset + 8 : block_end - 4]))
        offset = block_end
    assert offset == len(content)
    return blocks


def _parse_options(data: bytes) -> list[tuple[int, bytes]]:
    """Parse pcapng options and verify zero padding and termination."""
    options: list[tuple[int, bytes]] = []
    offset = 0
    while True:
        assert offset + 4 <= len(data)
        code, length = struct.unpack_from("<HH", data, offset)
        offset += 4
        if code == 0:
            assert length == 0
            assert offset == len(data)
            return options
        value_end = offset + length
        padded_end = value_end + ((4 - length % 4) % 4)
        assert padded_end <= len(data)
        assert data[value_end:padded_end] == b"\x00" * (padded_end - value_end)
        options.append((code, data[offset:value_end]))
        offset = padded_end


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

    def test_closes_file_on_init_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failure while writing header blocks must not leak the file handle."""
        opened: list[BinaryIO] = []
        real_open = Path.open

        def tracking_open(self_path: Path, *args: Any, **kwargs: Any) -> BinaryIO:
            handle: BinaryIO = real_open(self_path, *args, **kwargs)
            opened.append(handle)
            return handle

        def boom(self: PcapngWriter) -> None:
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

    def test_all_block_envelopes_and_interface_options(self) -> None:
        """SHB/IDB/EPB blocks are aligned and carry deterministic IDB metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(
                path,
                spreading_factor=12,
                bandwidth_hz=500_000,
                coding_rate=4,
            ) as writer:
                writer.write_packet(1, b"abc")

            blocks = _read_blocks(path)
            assert [block_type for block_type, _ in blocks] == [
                _BLOCK_TYPE_SHB,
                _BLOCK_TYPE_IDB,
                _BLOCK_TYPE_EPB,
            ]
            assert len(blocks[0][1]) == 16
            idb_fixed = struct.unpack_from("<HHI", blocks[1][1])
            assert idb_fixed == (_LINKTYPE_USER0, 0, 65535)
            options = dict(_parse_options(blocks[1][1][8:]))
            assert options[2] == b"lichen-lora"
            assert options[3] == b"LoRa SF=12 BW=500000Hz CR=4/8"
            assert options[9] == b"\x06"  # timestamps are 10^-6 seconds

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

    def test_epb_layout_and_metadata_options(self) -> None:
        """EPB timestamp, lengths, padding, and custom metadata are exact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.write_packet(
                    timestamp_us=0x0102030405060708,
                    data=b"abc",
                    rssi=-123,
                    snr=45,
                    src_node="source",
                    dst_node="dest",
                )

            _, _, (_, body) = _read_blocks(path)
            iface, ts_high, ts_low, cap_len, orig_len = struct.unpack_from("<IIIII", body)
            assert iface == 0
            assert (ts_high << 32) | ts_low == 0x0102030405060708
            assert (cap_len, orig_len) == (3, 3)
            assert body[20:24] == b"abc\x00"
            options = dict(_parse_options(body[24:]))
            assert json.loads(options[1]) == {
                "rssi": -123,
                "snr": 45,
                "src_node": "source",
                "dst_node": "dest",
            }

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

            with pytest.raises(ValueError, match="closed"):
                writer.flush()

            writer.close()  # Idempotent.

    def test_flush_makes_packet_visible_before_close(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            writer = PcapngWriter(path)
            initial_size = path.stat().st_size
            writer.write_packet(timestamp_us=1, data=b"packet")
            writer.flush()
            assert path.stat().st_size > initial_size
            writer.close()

    def test_context_manager_closes_on_body_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            retained: PcapngWriter | None = None
            with pytest.raises(RuntimeError, match="body failed"), PcapngWriter(path) as writer:
                retained = writer
                raise RuntimeError("body failed")
            assert retained is not None
            with pytest.raises(ValueError, match="closed"):
                retained.flush()

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

    def test_maximum_packet_and_oversized_rejection_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=0, data=b"x" * 65535)
                writer.flush()
                valid_size = path.stat().st_size
                with pytest.raises(ValueError, match="snap length"):
                    writer.write_packet(timestamp_us=0, data=b"x" * 65536)
                writer.flush()
                assert path.stat().st_size == valid_size
            assert _read_blocks(path)[-1][0] == _BLOCK_TYPE_EPB

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

    @pytest.mark.parametrize("timestamp", [-1, 1 << 64, True])
    def test_invalid_timestamp_rejected_without_mutation(self, timestamp: int) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.flush()
                header_size = path.stat().st_size
                with pytest.raises(ValueError, match="unsigned 64-bit"):
                    writer.write_packet(timestamp_us=timestamp, data=b"x")
                writer.flush()
                assert path.stat().st_size == header_size

    def test_uint64_max_timestamp_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.write_packet(timestamp_us=(1 << 64) - 1, data=b"")
            _, _, (_, body) = _read_blocks(path)
            assert struct.unpack_from("<II", body, 4) == (0xFFFFFFFF, 0xFFFFFFFF)

    @pytest.mark.parametrize("field", ["rssi", "snr"])
    @pytest.mark.parametrize("value", [-(1 << 31) - 1, 1 << 31, True])
    def test_invalid_signal_metadata_rejected(self, field: str, value: int) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer, pytest.raises(ValueError, match="signed 32-bit"):
                if field == "rssi":
                    writer.write_packet(0, b"x", rssi=value)
                else:
                    writer.write_packet(0, b"x", snr=value)

    def test_invalid_node_id_rejected_before_file_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.flush()
                header_size = path.stat().st_size
                with pytest.raises(ValueError, match="exceeds 255 bytes"):
                    writer.write_packet(0, b"x", src_node="n" * 256)
                writer.flush()
                assert path.stat().st_size == header_size

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"spreading_factor": 4},
            {"spreading_factor": True},
            {"bandwidth_hz": 0},
            {"bandwidth_hz": 1 << 32},
            {"coding_rate": 0},
            {"coding_rate": 5},
        ],
    )
    def test_invalid_interface_configuration_does_not_create_file(
        self, kwargs: dict[str, int]
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with pytest.raises(ValueError):
                PcapngWriter(path, **kwargs)
            assert not path.exists()

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

    def test_tshark_accepts_capture_when_available(self) -> None:
        """Use tshark as an external pcapng parser when installed."""
        tshark = shutil.which("tshark")
        if tshark is None:
            pytest.skip("tshark is not installed")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.pcapng"
            with PcapngWriter(path) as writer:
                writer.write_packet(123, b"\x01\x02\x03")
            result = subprocess.run(
                [tshark, "-r", str(path), "-c", "1"],
                check=False,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr
