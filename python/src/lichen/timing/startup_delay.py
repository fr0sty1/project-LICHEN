# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Boot storm mitigation via density-aware startup delay.

Per spec/09-packets-timing.md section 14 (after section 14.8):

High-density deployments risk boot storms when many nodes power up
simultaneously and transmit before Trickle or CSMA/CA stabilizes the
channel. Nodes MUST implement density-aware startup to mitigate this.

Normative constants and algorithm from test/vectors/packets-timing.json
("density_startup_delay" vector).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

# Normative constants per spec 09-packets-timing.md section 14 and
# test/vectors/packets-timing.json "density_startup_delay" vector.
LISTEN_PERIOD_MIN_S = 30
LISTEN_PERIOD_MAX_S = 60
DELAY_PER_NODE_S = 5
MAX_STARTUP_DELAY_S = 300

# Millisecond equivalents for scheduler integration
LISTEN_PERIOD_MIN_MS = LISTEN_PERIOD_MIN_S * 1000
LISTEN_PERIOD_MAX_MS = LISTEN_PERIOD_MAX_S * 1000
DELAY_PER_NODE_MS = DELAY_PER_NODE_S * 1000
MAX_STARTUP_DELAY_MS = MAX_STARTUP_DELAY_S * 1000


def compute_startup_delay_s(nodes_heard: int) -> int:
    """Compute the maximum startup delay based on observed density.

    Per spec 09-packets-timing.md:
    initial_delay = min(MAX_STARTUP_DELAY, nodes_heard * DELAY_PER_NODE)

    The caller MUST then select a random value in [0, initial_delay]
    before first transmission.

    Args:
        nodes_heard: Count of unique nodes observed during listen period.
            Deduplicated by EUI-64/short address from announces, DIOs,
            DIS, and valid frames.

    Returns:
        Maximum startup delay in seconds. The caller selects random(0, result)
        as the actual delay.

    Raises:
        ValueError: If nodes_heard is negative.
    """
    if type(nodes_heard) is not int or nodes_heard < 0:
        raise ValueError(f"nodes_heard must be a non-negative integer, got {nodes_heard}")
    return min(MAX_STARTUP_DELAY_S, nodes_heard * DELAY_PER_NODE_S)


def compute_startup_delay_ms(nodes_heard: int) -> int:
    """Compute the maximum startup delay in milliseconds.

    Same as compute_startup_delay_s but returns milliseconds for
    integration with async schedulers.

    Args:
        nodes_heard: Count of unique nodes observed during listen period.

    Returns:
        Maximum startup delay in milliseconds.
    """
    return compute_startup_delay_s(nodes_heard) * 1000


def random_listen_period_s() -> int:
    """Select a random listen period duration.

    Per spec: node MUST listen-only for random duration from
    [LISTEN_PERIOD_MIN, LISTEN_PERIOD_MAX].

    Returns:
        Listen period duration in seconds.
    """
    return random.randint(LISTEN_PERIOD_MIN_S, LISTEN_PERIOD_MAX_S)


def random_listen_period_ms() -> int:
    """Select a random listen period duration in milliseconds.

    Returns:
        Listen period duration in milliseconds.
    """
    return random_listen_period_s() * 1000


def random_startup_delay_s(nodes_heard: int) -> int:
    """Compute a random startup delay based on observed density.

    Combines compute_startup_delay_s with random selection.

    Args:
        nodes_heard: Count of unique nodes observed during listen period.

    Returns:
        Random delay in [0, computed_max_delay] seconds.
    """
    max_delay = compute_startup_delay_s(nodes_heard)
    if max_delay == 0:
        return 0
    return random.randint(0, max_delay)


def random_startup_delay_ms(nodes_heard: int) -> int:
    """Compute a random startup delay in milliseconds.

    Args:
        nodes_heard: Count of unique nodes observed during listen period.

    Returns:
        Random delay in milliseconds.
    """
    return random_startup_delay_s(nodes_heard) * 1000


@dataclass
class BootStormMitigation:
    """Stateful boot storm mitigation tracker.

    Tracks unique nodes heard during the listen period and computes
    the density-aware startup delay per spec 09-packets-timing.md.

    Usage:
        mitigation = BootStormMitigation()
        await asyncio.sleep(mitigation.listen_period_s)
        # During listen, call mitigation.observe_node(eui64) for each frame
        delay = mitigation.get_random_startup_delay_s()
        await asyncio.sleep(delay)
        # Now safe to transmit first announce/DIO/DIS

    Attributes:
        listen_period_s: Random duration for initial passive listen.
        _nodes_heard: Set of unique node identifiers observed.
    """

    listen_period_s: int = field(default_factory=random_listen_period_s)
    _nodes_heard: set[bytes] = field(default_factory=set, repr=False)

    @property
    def listen_period_ms(self) -> int:
        """Listen period duration in milliseconds."""
        return self.listen_period_s * 1000

    @property
    def nodes_heard_count(self) -> int:
        """Number of unique nodes observed during listen period."""
        return len(self._nodes_heard)

    def observe_node(self, identifier: bytes) -> bool:
        """Record observation of a node during listen period.

        Args:
            identifier: Unique node identifier (EUI-64 or short address).

        Returns:
            True if this is a new node, False if already observed.
        """
        if identifier in self._nodes_heard:
            return False
        self._nodes_heard.add(identifier)
        return True

    def get_max_startup_delay_s(self) -> int:
        """Get the maximum startup delay based on observed density.

        Returns:
            Maximum delay in seconds (caller should select random in [0, result]).
        """
        return compute_startup_delay_s(len(self._nodes_heard))

    def get_max_startup_delay_ms(self) -> int:
        """Get the maximum startup delay in milliseconds."""
        return self.get_max_startup_delay_s() * 1000

    def get_random_startup_delay_s(self) -> int:
        """Get a random startup delay based on observed density.

        Returns:
            Random delay in [0, max_delay] seconds.
        """
        return random_startup_delay_s(len(self._nodes_heard))

    def get_random_startup_delay_ms(self) -> int:
        """Get a random startup delay in milliseconds."""
        return self.get_random_startup_delay_s() * 1000

    def reset(self) -> None:
        """Clear observed nodes and select a new listen period."""
        self._nodes_heard.clear()
        self.listen_period_s = random_listen_period_s()
