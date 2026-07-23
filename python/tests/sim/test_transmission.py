# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LoRa transmission modeling."""

from uuid import UUID

import pytest

from lichen.sim.transmission import Transmission, airtime_us


class TestAirtimeUs:
    """Tests for airtime_us function."""

    def test_negative_payload_raises(self) -> None:
        """Negative payload length is invalid input and must be rejected."""
        with pytest.raises(ValueError, match="non-negative"):
            airtime_us(-1)

    def test_zero_payload(self) -> None:
        """Zero-length payload still has preamble and header overhead."""
        result = airtime_us(0)
        # n_payload = max(ceil((0 - 40 + 44) / 40) * 5, 0) = max(ceil(0.1) * 5, 0) = 5
        # Total symbols = 8 + 4.25 + 8 + 5 = 25.25
        # T_symbol = 2^10 / 125000 = 0.008192 s
        # Airtime = 0.008192 * 25.25 = 0.206848 s = 206848 us
        assert result == 206_848

    def test_small_payload(self) -> None:
        """Test with a small payload (10 bytes)."""
        result = airtime_us(10)
        # n_payload = max(ceil((80 - 40 + 44) / 40) * 5, 0) = max(ceil(2.1) * 5, 0) = 15
        # Total symbols = 8 + 4.25 + 8 + 15 = 35.25
        # Airtime = 0.008192 * 35.25 = 288767 us (floating point truncation)
        assert result == 288_767

    def test_medium_payload(self) -> None:
        """Test with a medium payload (50 bytes)."""
        result = airtime_us(50)
        # n_payload = max(ceil((400 - 40 + 44) / 40) * 5, 0) = max(ceil(10.1) * 5, 0) = 55
        # Total symbols = 8 + 4.25 + 8 + 55 = 75.25
        # Airtime = 0.008192 * 75.25 = 616448 us
        assert result == 616_448

    def test_max_lora_payload(self) -> None:
        """Test with maximum LoRa payload (255 bytes)."""
        result = airtime_us(255)
        # n_payload = max(ceil((2040 - 40 + 44) / 40) * 5, 0) = max(ceil(51.1) * 5, 0) = 260
        # Total symbols = 8 + 4.25 + 8 + 260 = 280.25
        # Airtime = 0.008192 * 280.25 = 2,295,808 us
        assert result == 2_295_808

    def test_airtime_increases_with_payload(self) -> None:
        """Larger payloads should have longer airtime."""
        small = airtime_us(10)
        medium = airtime_us(50)
        large = airtime_us(100)
        assert small < medium < large

    def test_airtime_is_positive(self) -> None:
        """Airtime should always be positive."""
        for size in [0, 1, 10, 50, 100, 255]:
            assert airtime_us(size) > 0


class TestTransmission:
    """Tests for Transmission dataclass."""

    def test_create_transmission(self) -> None:
        """Test creating a transmission with required fields."""
        tx = Transmission(
            source_node_id="node-1",
            payload=b"hello",
            tx_power_dbm=14,
            start_time_us=1000,
            end_time_us=2000,
        )
        assert tx.source_node_id == "node-1"
        assert tx.payload == b"hello"
        assert tx.tx_power_dbm == 14
        assert tx.start_time_us == 1000
        assert tx.end_time_us == 2000
        assert tx.frequency_hz == 915_000_000  # default

    def test_auto_generated_id(self) -> None:
        """Transmission ID should be auto-generated as valid UUID."""
        tx = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
        )
        # Should be a valid UUID string
        uuid = UUID(tx.id)
        assert str(uuid) == tx.id

    def test_unique_ids(self) -> None:
        """Each transmission should have a unique ID."""
        tx1 = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
        )
        tx2 = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
        )
        assert tx1.id != tx2.id

    def test_custom_frequency(self) -> None:
        """Test creating transmission with custom frequency."""
        tx = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
            frequency_hz=868_000_000,
        )
        assert tx.frequency_hz == 868_000_000

    def test_custom_id(self) -> None:
        """Test creating transmission with custom ID."""
        custom_id = "my-custom-id-123"
        tx = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
            id=custom_id,
        )
        assert tx.id == custom_id

    def test_empty_payload(self) -> None:
        """Test transmission with empty payload."""
        tx = Transmission(
            source_node_id="node-1",
            payload=b"",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
        )
        assert tx.payload == b""

    def test_negative_tx_power(self) -> None:
        """Test transmission with negative TX power (valid for some radios)."""
        tx = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=-10,
            start_time_us=0,
            end_time_us=100,
        )
        assert tx.tx_power_dbm == -10

    def test_channel_field(self) -> None:
        tx = Transmission(
            source_node_id="node-1",
            payload=b"test",
            tx_power_dbm=10,
            start_time_us=0,
            end_time_us=100,
            channel=5,
        )
        assert tx.channel == 5
