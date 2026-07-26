"""Channel selection per CCP-9 rendezvous priority chain.

Priority chain (highest to lowest):
1. Announce-driven: use rx_channel from last Announce for known peer
2. Hash-based: channel = 1 + hash_32(sfn, peer_eui) % (n_ch - 1)
3. Synchronized hop: CCP-12 synchronized_hop_channel for known peers
4. Fallback: control channel CH0 for unknown peers / initial contact
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Synchronized hopping constants (CCP-12)
SUPERFRAME_DURATION_US = 2_000_000  # 2 seconds default
GNSS_EPOCH_BASE_US = 1704067200_000_000  # 2024-01-01 00:00:00 UTC


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
        Superframe number (0 if time is before epoch).
    """
    if unix_time_us < epoch_base_us:
        return 0
    return (unix_time_us - epoch_base_us) // superframe_duration_us


def synchronized_hop_channel(sfn: int, seed: int = 0, n_channels: int = 64) -> int:
    """Compute channel for network-wide synchronized hopping.

    All nodes with the same seed and n_channels will be on the same channel
    for a given superframe number, enabling network-wide coordination.

    Args:
        sfn: Superframe number.
        seed: Network seed for channel hopping (default 0).
        n_channels: Number of available channels (default 64).

    Returns:
        Channel number (1 to n_channels-1, avoiding CH0 control channel).
    """
    data = seed.to_bytes(4, "little") + (sfn & 0xFFFFFFFF).to_bytes(4, "little")
    h = hash_32(data)
    n = max(n_channels - 1, 1)
    return 1 + (h % n)


def select_channel(
    *,
    peer_eui64: bytes | None = None,
    peer_known: bool = False,
    announce_rx_channel: int | None = None,
    sfn: int = 0,
    epoch: int = 0,
    n_channels: int = 8,
) -> int:
    """Select rendezvous channel per CCP-9 priority chain.

    Args:
        peer_eui64: Peer's EUI-64 for hash-based selection.
        peer_known: Whether this peer is known (has been heard from before).
        announce_rx_channel: rx_channel from peer's last Announce, if any.
        sfn: Superframe number for hash-based calculation.
        epoch: Current epoch for hash seeding.
        n_channels: Number of available channels (default 8).

    Returns:
        Channel number (0 to n_channels-1).
    """
    # Priority 1: announce-driven
    if announce_rx_channel is not None and peer_known:
        logger.debug("select_channel: announce-driven channel=%d", announce_rx_channel)
        return announce_rx_channel

    # Priority 2: hash-based for known peers
    if peer_known and peer_eui64 is not None and len(peer_eui64) == 8:
        data = peer_eui64 + epoch.to_bytes(4, "little") + (sfn & 0xFFFFFFFF).to_bytes(4, "little")
        h = hash_32(data)
        n = max(n_channels - 1, 1)
        ch = 1 + (h % n)
        logger.debug("select_channel: hash-based channel=%d for peer=%s", ch, peer_eui64.hex()[:8])
        return ch

    # Priority 3: fallback to control channel CH0
    logger.debug("select_channel: fallback to CH0")
    return 0
