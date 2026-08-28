"""Channel selection per CCP-9 rendezvous priority chain.

Priority chain (highest to lowest):
1. Announce-driven: use rx_channel from last Announce for known peer
2. GNSS-synced: use synchronized_hop_channel when GNSS time available
3. Hash-based: channel = 1 + hash_32(sfn, peer_eui) % (n_ch - 1)
4. Fallback: control channel CH0 for unknown peers / initial contact
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from lichen.time_provider import TimeProvider

logger = logging.getLogger(__name__)

# Synchronized hopping constants (CCP-12)
SUPERFRAME_DURATION_US = 2_000_000  # 2 seconds default
GNSS_EPOCH_BASE_US = 1704067200_000_000  # 2024-01-01 00:00:00 UTC


@dataclass
class GnssHopConfig:
    """Configuration for GNSS-synchronized hopping."""

    enabled: bool = False
    seed: int = 0
    superframe_duration_us: int = SUPERFRAME_DURATION_US
    epoch_base_us: int = GNSS_EPOCH_BASE_US


def hash_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


def sfn_from_unix_time(
    unix_time_us: int,
    superframe_duration_us: int = SUPERFRAME_DURATION_US,
    epoch_base_us: int = GNSS_EPOCH_BASE_US,
) -> int:
    """Derive superframe number from UTC time.

    Args:
        unix_time_us: Unix timestamp in microseconds.
        superframe_duration_us: Duration of one superframe in microseconds.
        epoch_base_us: Epoch base time in microseconds (default: 2024-01-01 00:00:00 UTC).

    Returns:
        Superframe number (0 if time is before epoch, or if
        ``superframe_duration_us`` is 0 to avoid division by zero).
    """
    if superframe_duration_us <= 0 or unix_time_us < epoch_base_us:
        return 0
    return (unix_time_us - epoch_base_us) // superframe_duration_us


def synchronized_hop_channel(sfn: int, seed: int = 0, n_channels: int = 64) -> int:
    """Compute channel for network-wide synchronized hopping.

    All nodes with the same seed and n_channels will be on the same channel
    for a given superframe number, enabling network-wide coordination.

    Per spec/appendix-ccp12-hopping.md SynchronizedHopChannel:
    - N = NChannels - 1 (exclude reserved CH0)
    - Returns 1 + (Hash MOD N), yielding channels 1..NChannels-1

    Args:
        sfn: Superframe number.
        seed: Network seed for channel hopping (default 0).
        n_channels: Number of available channels (default 64).

    Returns:
        Channel number in [1, n_channels) or 0 when no data channel exists.
    """
    data = (seed & 0xFFFFFFFF).to_bytes(4, "little") + (sfn & 0xFFFFFFFF).to_bytes(4, "little")
    h = hash_32(data)
    data_channels = n_channels - 1
    return 0 if data_channels <= 0 else 1 + (h % data_channels)


def select_channel(
    *,
    peer_eui64: bytes | None = None,
    peer_known: bool = False,
    announce_rx_channel: int | None = None,
    sfn: int = 0,
    epoch: int = 0,
    n_channels: int = 8,
    time_provider: TimeProvider | None = None,
    gnss_config: GnssHopConfig | None = None,
) -> int:
    """Select rendezvous channel per CCP-9 priority chain.

    Args:
        peer_eui64: Peer's EUI-64 for hash-based selection.
        peer_known: Whether this peer is known (has been heard from before).
        announce_rx_channel: rx_channel from peer's last Announce, if any.
        sfn: Superframe number for hash-based calculation.
        epoch: Current epoch for hash seeding.
        n_channels: Number of available channels (default 8).
        time_provider: Optional time provider for GNSS-synced hopping.
        gnss_config: Optional configuration for GNSS-synchronized hopping.

    Returns:
        Channel number (0 to n_channels-1).
    """
    # Priority 1: announce-driven (with bounds validation)
    if announce_rx_channel is not None and peer_known:
        if 0 <= announce_rx_channel < n_channels:
            logger.debug("select_channel: announce-driven channel=%d", announce_rx_channel)
            return announce_rx_channel
        logger.debug(
            "select_channel: announce_rx_channel=%d out of bounds, skipping", announce_rx_channel
        )

    # Priority 2: GNSS-synced (when enabled and time available)
    if (
        gnss_config
        and gnss_config.enabled
        and time_provider
        and time_provider.wall_clock_valid
    ):
        if n_channels <= 1:
            return 0
        unix_us = time_provider.unix_time_us()
        if unix_us is not None:
            computed_sfn = sfn_from_unix_time(
                unix_us,
                gnss_config.superframe_duration_us,
                gnss_config.epoch_base_us,
            )
            ch = synchronized_hop_channel(computed_sfn, gnss_config.seed, n_channels)
            logger.debug("select_channel: gnss-synced channel=%d sfn=%d", ch, computed_sfn)
            return ch

    # Priority 3: hash-based for known peers
    if peer_known and peer_eui64 is not None and len(peer_eui64) == 8:
        if n_channels <= 1:
            return 0
        data = (
            peer_eui64
            + (epoch & 0xFFFFFFFF).to_bytes(4, "little")
            + (sfn & 0xFFFFFFFF).to_bytes(4, "little")
        )
        h = hash_32(data)
        n = max(n_channels - 1, 1)
        ch = 1 + (h % n)
        logger.debug("select_channel: hash-based channel=%d for peer=%s", ch, peer_eui64.hex()[:8])
        return ch

    # Priority 4: fallback to control channel CH0
    logger.debug("select_channel: fallback to CH0")
    return 0
