"""LICHEN announce routing (spec section 9).

Announce routing provides zero-latency peer-to-peer paths for active mesh
participants. Nodes periodically broadcast signed announcements; receivers
build gradients toward announcers.

Key insight: Most peer-to-peer traffic is between nodes that actively
participate in the mesh. These nodes announce regularly. No discovery needed.
"""

from lichen.announce.messages import (
    ANNOUNCE_TYPE,
    MAX_ANNOUNCE_HOPS,
    SIGNATURE_LENGTH,
    AnnounceError,
    AnnounceMessage,
)
from lichen.announce.processor import (
    ANNOUNCE_INTERVAL_MS,
    ANNOUNCE_JITTER_MS,
    GRADIENT_TIMEOUT_MS,
    AnnounceProcessor,
    AnnounceResult,
)
from lichen.announce.scheduler import (
    DEFAULT_INTERVAL_MS,
    DEFAULT_JITTER_MS,
    AnnounceScheduler,
    AnnounceTransmitter,
    SchedulerConfig,
)

__all__ = [
    "ANNOUNCE_INTERVAL_MS",
    "ANNOUNCE_JITTER_MS",
    "ANNOUNCE_TYPE",
    "AnnounceError",
    "AnnounceMessage",
    "AnnounceProcessor",
    "AnnounceResult",
    "AnnounceScheduler",
    "AnnounceTransmitter",
    "DEFAULT_INTERVAL_MS",
    "DEFAULT_JITTER_MS",
    "GRADIENT_TIMEOUT_MS",
    "MAX_ANNOUNCE_HOPS",
    "SIGNATURE_LENGTH",
    "SchedulerConfig",
]
