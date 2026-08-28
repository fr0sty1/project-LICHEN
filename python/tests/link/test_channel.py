# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for channel selection functions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.channel import (
    GNSS_EPOCH_BASE_US,
    SUPERFRAME_DURATION_US,
    GnssHopConfig,
    hash_32,
    select_channel,
    sfn_from_unix_time,
    synchronized_hop_channel,
)
from lichen.sim.tdma import synchronized_hop_channel as tdma_synchronized_hop_channel
from lichen.time_provider import SimulatedTimeProvider

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _fnv1a32(data: bytes) -> int:
    """Published FNV-1a 32-bit (offset 0x811c9dc5, prime 0x01000193).

    Independent of lichen.link.channel.hash_32 so wrap tests have an
    oracle that is not the function under test.
    """
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _u32le(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little")


class TestSfnFromUnixTime:
    """Tests for sfn_from_unix_time function."""

    def test_before_epoch_returns_zero(self) -> None:
        """Time before epoch should return SFN 0."""
        assert sfn_from_unix_time(0) == 0
        assert sfn_from_unix_time(GNSS_EPOCH_BASE_US - 1) == 0

    def test_at_epoch_returns_zero(self) -> None:
        """Time exactly at epoch should return SFN 0."""
        assert sfn_from_unix_time(GNSS_EPOCH_BASE_US) == 0

    def test_one_superframe_after_epoch(self) -> None:
        """One superframe duration after epoch should return SFN 1."""
        assert sfn_from_unix_time(GNSS_EPOCH_BASE_US + SUPERFRAME_DURATION_US) == 1

    def test_multiple_superframes(self) -> None:
        """Multiple superframes should return correct SFN."""
        for n in [2, 10, 100, 1000]:
            time_us = GNSS_EPOCH_BASE_US + n * SUPERFRAME_DURATION_US
            assert sfn_from_unix_time(time_us) == n

    def test_partial_superframe_truncates(self) -> None:
        """Partial superframe should truncate to lower SFN."""
        # 1.5 superframes after epoch should still be SFN 1
        time_us = GNSS_EPOCH_BASE_US + int(1.5 * SUPERFRAME_DURATION_US)
        assert sfn_from_unix_time(time_us) == 1

    def test_custom_superframe_duration(self) -> None:
        """Custom superframe duration should be respected."""
        custom_duration = 1_000_000  # 1 second
        time_us = GNSS_EPOCH_BASE_US + 5 * custom_duration
        assert sfn_from_unix_time(time_us, superframe_duration_us=custom_duration) == 5

    def test_custom_epoch_base(self) -> None:
        """Custom epoch base should be respected."""
        custom_epoch = 1_000_000_000_000_000  # Some arbitrary epoch
        time_us = custom_epoch + 3 * SUPERFRAME_DURATION_US
        assert sfn_from_unix_time(time_us, epoch_base_us=custom_epoch) == 3

    def test_zero_superframe_duration_returns_zero(self) -> None:
        """Duration 0 must not divide; SFN is defined as 0 (Rust/C contract)."""
        after_epoch = GNSS_EPOCH_BASE_US + 1_000_000
        assert sfn_from_unix_time(after_epoch, superframe_duration_us=0) == 0
        assert sfn_from_unix_time(after_epoch, superframe_duration_us=-1) == 0


class TestSynchronizedHopChannel:
    """Tests for synchronized_hop_channel function."""

    def test_channel_in_valid_range(self) -> None:
        """Channel should be in the configured data range [1, n_channels)."""
        for sfn in range(100):
            ch = synchronized_hop_channel(sfn, seed=0, n_channels=64)
            assert 1 <= ch < 64

    def test_avoids_control_channel(self) -> None:
        """Channel 0 (control) should never be returned."""
        for sfn in range(1000):
            for seed in [0, 1, 0x12345678]:
                ch = synchronized_hop_channel(sfn, seed=seed, n_channels=64)
                assert ch != 0

    def test_deterministic(self) -> None:
        """Same inputs should always produce same channel."""
        for _ in range(10):
            ch1 = synchronized_hop_channel(42, seed=123, n_channels=64)
            ch2 = synchronized_hop_channel(42, seed=123, n_channels=64)
            assert ch1 == ch2

    def test_different_sfn_different_channel(self) -> None:
        """Different SFN should usually produce different channels."""
        channels = [synchronized_hop_channel(sfn, seed=0, n_channels=64) for sfn in range(100)]
        # With 64 channels, we expect good distribution
        unique_channels = set(channels)
        assert len(unique_channels) > 20  # At least 20 unique channels in 100 SFNs

    def test_different_seed_different_channel(self) -> None:
        """Different seeds should produce different channel sequences."""
        seq1 = [synchronized_hop_channel(sfn, seed=0, n_channels=64) for sfn in range(10)]
        seq2 = [synchronized_hop_channel(sfn, seed=1, n_channels=64) for sfn in range(10)]
        # Sequences should differ
        assert seq1 != seq2

    def test_sfn_wrapping(self) -> None:
        """SFN values near 32-bit boundary should work correctly."""
        ch1 = synchronized_hop_channel(0xFFFFFFFF, seed=0, n_channels=64)
        ch2 = synchronized_hop_channel(0x100000000, seed=0, n_channels=64)  # Wraps to 0
        assert 1 <= ch1 < 64
        assert 1 <= ch2 < 64

    def test_small_channel_count(self) -> None:
        """A three-entry plan selects one of its two data channels."""
        ch = synchronized_hop_channel(42, seed=0, n_channels=3)
        assert 1 <= ch < 3

    def test_minimum_channel_count(self) -> None:
        """Empty/control-only plans fail closed; a sole data channel is CH1."""
        assert synchronized_hop_channel(42, seed=0, n_channels=0) == 0
        assert synchronized_hop_channel(42, seed=0, n_channels=1) == 0
        assert synchronized_hop_channel(42, seed=0, n_channels=2) == 1

    def test_all_counts_and_hash_boundary_stay_in_plan(self) -> None:
        """Zero, one, u8-max, and the historic hash boundary are bounded."""
        for n_channels in (0, 1, 2, 3, 64, 255):
            for sfn in (0, 1, 26, 0x7FFFFFFF, 0xFFFFFFFF):
                ch = synchronized_hop_channel(sfn, seed=0, n_channels=n_channels)
                if n_channels <= 1:
                    assert ch == 0
                else:
                    assert 1 <= ch < n_channels
        assert _fnv1a32(_u32le(0) + _u32le(26)) % 64 == 63
        assert synchronized_hop_channel(26, seed=0, n_channels=64) == 15

    def test_seed_wraps_as_u32(self) -> None:
        """Negative or oversized seed is little-endian u32, matching SFN masking."""
        sfn = 42
        n_channels = 64
        n = n_channels - 1

        data_neg = _u32le(-1) + _u32le(sfn)
        expected_neg = 1 + (_fnv1a32(data_neg) % n)
        assert synchronized_hop_channel(sfn, seed=-1, n_channels=n_channels) == expected_neg

        data_over = _u32le(0x1_0000_0005) + _u32le(sfn)
        expected_over = 1 + (_fnv1a32(data_over) % n)
        assert (
            synchronized_hop_channel(sfn, seed=0x1_0000_0005, n_channels=n_channels)
            == expected_over
        )
        assert expected_over == 1 + (_fnv1a32(_u32le(5) + _u32le(sfn)) % n)


class TestSynchronizedHopChannelCompatibility:
    """Cross-validation tests with tdma.py implementation."""

    def test_compatible_with_tdma_implementation(self) -> None:
        """Verify channel.py produces compatible results with tdma.py.

        Note: The implementations have different default n_channels (64 vs 8)
        and slightly different edge case handling. We test with matching params.
        """
        # Test with matching parameters
        for sfn in range(50):
            for seed in [0, 1, 0xDEADBEEF]:
                # Use n_channels=8 to match tdma.py default behavior
                ch_channel = synchronized_hop_channel(sfn, seed=seed, n_channels=8)
                ch_tdma = tdma_synchronized_hop_channel(sfn, seed=seed, num_channels=8)

                # Both should avoid channel 0
                assert ch_channel >= 1
                assert ch_tdma >= 1

                # Implementations must produce identical results
                assert ch_channel == ch_tdma, f"sfn={sfn}, seed={seed}: {ch_channel} != {ch_tdma}"

    def test_hash_function_identical(self) -> None:
        """Verify hash_32 produces identical results."""
        from lichen.sim.tdma import hash_32 as tdma_hash_32

        test_data = [
            b"",
            b"\x00",
            b"\xff" * 8,
            b"test data",
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        ]
        for data in test_data:
            assert hash_32(data) == tdma_hash_32(data)


class TestSelectChannel:
    """Tests for select_channel function."""

    def test_announce_driven_priority(self) -> None:
        """Announce-driven selection should take priority."""
        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            announce_rx_channel=5,
            sfn=42,
        )
        assert ch == 5

    def test_hash_based_for_known_peer(self) -> None:
        """Hash-based selection for known peers without announce."""
        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
        )
        assert 1 <= ch <= 7

    def test_fallback_to_ch0(self) -> None:
        """Unknown peers should fallback to CH0."""
        ch = select_channel(peer_known=False)
        assert ch == 0

    def test_unknown_peer_ignores_announce(self) -> None:
        """Unknown peer should ignore announce_rx_channel."""
        ch = select_channel(
            peer_known=False,
            announce_rx_channel=5,
        )
        assert ch == 0

    def test_gnss_synced_priority(self) -> None:
        """GNSS-synced selection should take priority over hash-based."""
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 5 * SUPERFRAME_DURATION_US,
            has_gnss=True,
        )
        gnss_config = GnssHopConfig(enabled=True, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        # Should use synchronized_hop_channel with computed SFN=5
        expected_ch = synchronized_hop_channel(5, seed=0, n_channels=8)
        assert ch == expected_ch

    def test_announce_beats_gnss_synced(self) -> None:
        """Announce-driven should take priority over GNSS-synced."""
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 5 * SUPERFRAME_DURATION_US,
            has_gnss=True,
        )
        gnss_config = GnssHopConfig(enabled=True, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            announce_rx_channel=3,
            sfn=42,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        assert ch == 3

    def test_gnss_disabled_falls_through(self) -> None:
        """When GNSS config disabled, should fall through to hash-based."""
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 5 * SUPERFRAME_DURATION_US,
            has_gnss=True,
        )
        gnss_config = GnssHopConfig(enabled=False, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        # Should use hash-based since GNSS is disabled
        assert 1 <= ch <= 7

    def test_gnss_no_time_falls_through(self) -> None:
        """When time provider returns None, should fall through to hash-based."""
        time_provider = SimulatedTimeProvider(unix_time_us=None, has_gnss=False)
        gnss_config = GnssHopConfig(enabled=True, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        # Should use hash-based since no time available
        assert 1 <= ch <= 7

    def test_unestablished_wall_clock_falls_through(self) -> None:
        """A retained but invalid timestamp must not drive synchronized hopping."""
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 5 * SUPERFRAME_DURATION_US,
            has_gnss=True,
            wall_clock_valid=False,
        )
        gnss_config = GnssHopConfig(enabled=True, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )

        expected = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
        )
        assert ch == expected

    def test_gnss_synced_uses_config_params(self) -> None:
        """GNSS-synced should use config's seed and timing params."""
        custom_duration = 1_000_000  # 1 second
        custom_seed = 0xDEADBEEF
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 10 * custom_duration,
            has_gnss=True,
        )
        gnss_config = GnssHopConfig(
            enabled=True,
            seed=custom_seed,
            superframe_duration_us=custom_duration,
        )

        ch = select_channel(
            peer_known=False,  # Unknown peer, but GNSS should still work
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        # Should use synchronized_hop_channel with computed SFN=10 and custom seed
        expected_ch = synchronized_hop_channel(10, seed=custom_seed, n_channels=8)
        assert ch == expected_ch

    def test_gnss_without_time_provider_falls_through(self) -> None:
        """When time_provider is None, should fall through to hash-based."""
        gnss_config = GnssHopConfig(enabled=True, seed=0)

        ch = select_channel(
            peer_eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            peer_known=True,
            sfn=42,
            n_channels=8,
            time_provider=None,
            gnss_config=gnss_config,
        )
        # Should use hash-based since no time provider
        assert 1 <= ch <= 7

    def test_epoch_wraps_as_u32(self) -> None:
        """Negative or oversized epoch is little-endian u32, matching SFN masking."""
        eui = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        sfn = 42
        n_channels = 8
        n = max(n_channels - 1, 1)

        expected = 1 + (_fnv1a32(eui + _u32le(-1) + _u32le(sfn)) % n)
        assert (
            select_channel(
                peer_eui64=eui,
                peer_known=True,
                sfn=sfn,
                epoch=-1,
                n_channels=n_channels,
            )
            == expected
        )

        expected_over = 1 + (_fnv1a32(eui + _u32le(0x1_0000_0007) + _u32le(sfn)) % n)
        assert (
            select_channel(
                peer_eui64=eui,
                peer_known=True,
                sfn=sfn,
                epoch=0x1_0000_0007,
                n_channels=n_channels,
            )
            == expected_over
        )
        assert expected_over == 1 + (_fnv1a32(eui + _u32le(7) + _u32le(sfn)) % n)

    def test_gnss_zero_duration_does_not_raise(self) -> None:
        """Zero superframe duration must not crash GNSS-synced selection."""
        time_provider = SimulatedTimeProvider(
            unix_time_us=GNSS_EPOCH_BASE_US + 5 * SUPERFRAME_DURATION_US,
            has_gnss=True,
        )
        gnss_config = GnssHopConfig(enabled=True, seed=0, superframe_duration_us=0)
        ch = select_channel(
            peer_known=False,
            n_channels=8,
            time_provider=time_provider,
            gnss_config=gnss_config,
        )
        # CH0 is reserved, so eight total channels provide seven data channels.
        n = 8 - 1
        expected = 1 + (_fnv1a32(_u32le(0) + _u32le(0)) % n)
        assert ch == expected


class TestGnssHopConfig:
    """Tests for GnssHopConfig dataclass."""

    def test_defaults(self) -> None:
        """Default values should match module constants."""
        config = GnssHopConfig()
        assert config.enabled is False
        assert config.seed == 0
        assert config.superframe_duration_us == SUPERFRAME_DURATION_US
        assert config.epoch_base_us == GNSS_EPOCH_BASE_US

    def test_custom_values(self) -> None:
        """Custom values should be stored correctly."""
        config = GnssHopConfig(
            enabled=True,
            seed=12345,
            superframe_duration_us=1_000_000,
            epoch_base_us=1_000_000_000_000_000,
        )
        assert config.enabled is True
        assert config.seed == 12345
        assert config.superframe_duration_us == 1_000_000
        assert config.epoch_base_us == 1_000_000_000_000_000


# --- Test vector-driven tests ---


def _load_vectors(name: str) -> dict:
    """Load a test vector file from test/vectors/."""
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


def _hash_32_cases():
    """Load hash_32.json test vectors."""
    doc = _load_vectors("hash_32.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _hash_32_cases())
def test_hash_32_vector(name: str, vector: dict) -> None:
    """Validate hash_32 against hash_32.json vectors (independent oracle)."""
    if "input_hex" in vector:
        data = bytes.fromhex(vector["input_hex"])
    else:
        data = vector["input"].encode("utf-8")

    expected = int(vector["output"], 16)
    assert hash_32(data) == expected, f"{name}: hash_32 mismatch"


def _ccp16_hop_cases():
    """Load ccp16-hop.json test vectors."""
    doc = _load_vectors("ccp16-hop.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_hop_cases())
def test_synchronized_hop_channel_vector(name: str, vector: dict) -> None:
    """Validate synchronized_hop_channel against ccp16-hop.json vectors.

    Uses independent oracle per test integrity rules. Covers SFN wraparound,
    multi-channel (8/16), rendezvous, and density fallback.
    """
    # Skip vectors that test rendezvous beacon behavior (rx_channel preference)
    # since that is handled by select_channel, not synchronized_hop_channel
    if "rx_channel" in vector:
        pytest.skip("rendezvous beacon vector tests select_channel rx_channel preference")

    sfn = vector["sfn"]
    seed = vector.get("seed", 0)
    num_channels = vector["num_channels"]
    expected_channel = vector["expected_channel"]
    density = vector.get("density")

    # Density > 8 returns CH0 per SelectChannel pseudocode line 1
    if density is not None and density > 8:
        # This tests the density fallback rule which is in select_channel,
        # not in synchronized_hop_channel directly. Verify the vector expectation.
        assert expected_channel == 0, f"{name}: density>8 should expect channel 0"
        pytest.skip("density fallback is handled by select_channel, not synchronized_hop_channel")

    # Verify hash_32 intermediate if present
    if "hash_32" in vector:
        data = (seed & 0xFFFFFFFF).to_bytes(4, "little") + (sfn & 0xFFFFFFFF).to_bytes(4, "little")
        assert hash_32(data) == vector["hash_32"], f"{name}: hash_32 intermediate mismatch"

    channel = synchronized_hop_channel(sfn, seed=seed, n_channels=num_channels)
    assert channel == expected_channel, (
        f"{name}: channel mismatch (got {channel}, expected {expected_channel})"
    )
