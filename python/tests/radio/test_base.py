# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the Radio protocol definition."""

from lichen.radio import Radio


class MockRadio:
    """A mock radio implementation that satisfies the Radio protocol."""

    def __init__(self) -> None:
        self.freq_hz: int = 915_000_000
        self.tx_power_dbm: int = 14
        self.last_transmitted: bytes | None = None
        self.receive_queue: list[tuple[bytes, int, int]] = []

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        """Record the payload and return success. Supports channel for multi-channel."""
        self.last_transmitted = payload
        self.last_channel = channel
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Return queued packet or None."""
        if self.receive_queue:
            return self.receive_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """Store configuration."""
        self.freq_hz = freq_hz
        self.tx_power_dbm = tx_power_dbm

    async def cad(self, timeout_ms: int) -> bool:
        """Return False (channel clear) by default."""
        return False


class IncompleteRadio:
    """A radio implementation missing required methods."""

    async def transmit(self, payload: bytes) -> bool:
        return True


class TestRadioProtocol:
    """Tests verifying the Radio protocol behavior."""

    def test_mock_radio_satisfies_protocol(self) -> None:
        """MockRadio should be recognized as implementing Radio protocol."""
        radio = MockRadio()
        assert isinstance(radio, Radio)

    def test_incomplete_radio_does_not_satisfy_protocol(self) -> None:
        """IncompleteRadio should NOT be recognized as implementing Radio."""
        radio = IncompleteRadio()
        assert not isinstance(radio, Radio)

    async def test_transmit_returns_bool(self) -> None:
        """transmit() should return a boolean indicating success."""
        radio = MockRadio()
        result = await radio.transmit(b"hello")
        assert result is True
        assert radio.last_transmitted == b"hello"

    async def test_receive_returns_packet_tuple(self) -> None:
        """receive() should return (payload, rssi, snr) tuple."""
        radio = MockRadio()
        radio.receive_queue.append((b"data", -80, 10))

        result = await radio.receive(timeout_ms=1000)

        assert result is not None
        payload, rssi, snr = result
        assert payload == b"data"
        assert rssi == -80
        assert snr == 10

    async def test_receive_returns_none_on_timeout(self) -> None:
        """receive() should return None when no packet available."""
        radio = MockRadio()
        result = await radio.receive(timeout_ms=100)
        assert result is None

    def test_configure_sets_parameters(self) -> None:
        """configure() should update radio parameters."""
        radio = MockRadio()
        radio.configure(freq_hz=868_000_000, tx_power_dbm=20)
        assert radio.freq_hz == 868_000_000
        assert radio.tx_power_dbm == 20

    async def test_cad_returns_bool(self) -> None:
        """cad() should return a boolean indicating channel activity."""
        radio = MockRadio()
        result = await radio.cad(timeout_ms=35)
        assert result is False  # MockRadio returns False (channel clear)
