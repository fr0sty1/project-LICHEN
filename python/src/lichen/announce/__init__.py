# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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
from lichen.announce.coords import (
    APP_DATA_TYPE_COORDS,
    APP_DATA_TYPE_CONGESTION,
    APP_DATA_TYPE_DTN_EXPIRY,
    APP_DATA_TYPE_DTN_PENDING,
    HEADER_TYPE_OPPORTUNISTIC,
    MAX_OPPORTUNISTIC_CANDIDATES,
    OPPORTUNISTIC_SLOT_TIME_MS,
    decode_congestion,
    decode_coords,
    decode_dtn_expiry,
    decode_dtn_pending,
    decode_opportunistic_forwarders,
    encode_congestion,
    encode_coords,
    encode_dtn_expiry,
    encode_dtn_pending,
    encode_opportunistic_forwarders,
    opportunistic_wait_time_ms,
)
from lichen.gradient import GRADIENT_TIMEOUT_MS

__all__ = [
    "ANNOUNCE_INTERVAL_MS",
    "ANNOUNCE_JITTER_MS",
    "ANNOUNCE_TYPE",
    "APP_DATA_TYPE_COORDS",
    "APP_DATA_TYPE_CONGESTION",
    "APP_DATA_TYPE_DTN_EXPIRY",
    "APP_DATA_TYPE_DTN_PENDING",
    "AnnounceError",
    "AnnounceMessage",
    "AnnounceProcessor",
    "AnnounceResult",
    "AnnounceScheduler",
    "AnnounceTransmitter",
    "DEFAULT_INTERVAL_MS",
    "DEFAULT_JITTER_MS",
    "GRADIENT_TIMEOUT_MS",
    "HEADER_TYPE_OPPORTUNISTIC",
    "MAX_ANNOUNCE_HOPS",
    "MAX_OPPORTUNISTIC_CANDIDATES",
    "OPPORTUNISTIC_SLOT_TIME_MS",
    "SIGNATURE_LENGTH",
    "SchedulerConfig",
    "decode_congestion",
    "decode_coords",
    "decode_dtn_expiry",
    "decode_dtn_pending",
    "decode_opportunistic_forwarders",
    "encode_congestion",
    "encode_coords",
    "encode_dtn_expiry",
    "encode_dtn_pending",
    "encode_opportunistic_forwarders",
    "opportunistic_wait_time_ms",
]
