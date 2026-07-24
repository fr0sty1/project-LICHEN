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


def hash_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


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
