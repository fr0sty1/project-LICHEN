# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Base simulation class with initialization and properties.

This module provides the SimulationBase class that holds all simulation state
and exposes properties. Mixins in other modules add behavior.
"""

from __future__ import annotations

import math
import random
import time
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

import structlog
from lora_medium import Medium

from lichen.sim.events import EventQueue, ObserverRegistry, SimulationObserver
from lichen.sim.metrics import Metrics
from lichen.sim.node import SimNode

if TYPE_CHECKING:
    from lora_medium import ChaosEngine

logger = structlog.get_logger()

# Module-level debug flag for newly created simulations
DEBUG_ENABLED = False


def enable_debug() -> None:
    """Enable enhanced simulation debugging for newly created simulations."""
    global DEBUG_ENABLED
    DEBUG_ENABLED = True


def disable_debug() -> None:
    """Disable enhanced simulation debugging for newly created simulations."""
    global DEBUG_ENABLED
    DEBUG_ENABLED = False


def is_debug_enabled() -> bool:
    """Return whether enhanced simulation debugging is enabled."""
    return DEBUG_ENABLED


class TimeMode(Enum):
    """Time advancement mode for the simulation."""

    BARRIER_SYNC = auto()
    REALTIME = auto()


class PlaybackState:
    """State for simulation playback controls.

    Tracks whether simulation is paused and playback speed multiplier.
    """

    def __init__(self) -> None:
        """Initialize playback state to playing at normal speed."""
        self._paused: bool = False
        self._speed: float = 1.0

    @property
    def paused(self) -> bool:
        """Return whether simulation is paused."""
        return self._paused

    @paused.setter
    def paused(self, value: bool) -> None:
        """Set paused state."""
        self._paused = value

    @property
    def speed(self) -> float:
        """Return playback speed multiplier (1.0 = realtime)."""
        return self._speed

    @speed.setter
    def speed(self, value: float) -> None:
        """Set playback speed multiplier.

        Args:
            value: Speed multiplier. Must be positive. Values > 1 run faster,
                values < 1 run slower.

        Raises:
            ValueError: If value is not positive.
        """
        if value <= 0:
            raise ValueError(f"Speed must be positive, got {value}")
        self._speed = value

    def to_dict(self) -> dict[str, Any]:
        """Return playback state as dictionary."""
        return {
            "paused": self._paused,
            "speed": self._speed,
        }


class SimulationBase:
    """Base class for simulation state and properties.

    This class holds all simulation state and exposes read-only properties.
    Actual behavior is added by mixin classes.

    Attributes:
        id: Unique identifier for this simulation instance.
        time_mode: The time advancement mode.
        medium: The radio medium for propagation simulation.
        event_queue: Priority queue of simulation events.
    """

    def __init__(
        self,
        sim_id: str,
        time_mode: TimeMode = TimeMode.BARRIER_SYNC,
        chaos_engine: ChaosEngine | None = None,
        seed: int | None = None,
        jitter_min_us: int = 0,
        jitter_max_us: int = 0,
        density_aware_startup: bool = False,
        listen_period_us: int = 1_000_000,
        density_scale_factor: float = 1000.0,
    ) -> None:
        """Initialize a new simulation.

        Args:
            sim_id: Unique identifier for this simulation.
            time_mode: Time advancement mode. Defaults to BARRIER_SYNC.
            chaos_engine: Optional ChaosEngine for applying network fault rules.
            seed: Optional seed for the simulation's random number generator.
                Two simulations created with the same seed draw the same random
                sequence, making probabilistic runs (e.g. chaos loss) reproducible.
            jitter_min_us: Minimum TX jitter in microseconds. Defaults to 0.
            jitter_max_us: Maximum TX jitter in microseconds. Defaults to 0
                (disabled). Set to a positive value to enable TX jitter.
            density_aware_startup: If True, nodes apply listen-before-TX during
                startup, with a per-node delay scaled by estimated density.
            listen_period_us: Duration in microseconds each node listens before
                its first TX to build its heard set.
            density_scale_factor: Scaling constant for the density-derived delay.
                The actual delay is random.uniform(0, density_scale_factor *
                log(1 + heard_count)).
        """
        self._id = sim_id
        self._time_mode = time_mode
        self._current_time_us = 0
        self._nodes: dict[str, SimNode] = {}
        self._gateways: dict[str, dict[str, Any]] = {}
        self._medium = Medium()
        self._event_queue = EventQueue()
        self._pending_rx_timeouts: dict[str, int] = {}  # node_id -> timeout_time_us
        self._active_transmissions: dict[str, str] = {}  # node_id -> transmission_id
        self._chaos_engine = chaos_engine
        self._seed = seed
        self._rng = random.Random(seed)
        # Independent RNG copy so reservoir sampling cannot perturb jitter.
        self._metrics = Metrics(rng=random.Random(seed))
        self._observers = ObserverRegistry()
        self._debug_enabled = DEBUG_ENABLED
        if jitter_min_us < 0 or jitter_max_us < 0:
            raise ValueError(
                f"jitter values must be non-negative, got min={jitter_min_us} max={jitter_max_us}"
            )
        if jitter_max_us > 0 and jitter_min_us > jitter_max_us:
            raise ValueError(
                f"jitter_min_us ({jitter_min_us}) must be <= jitter_max_us ({jitter_max_us})"
            )
        self._jitter_min_us = jitter_min_us
        self._jitter_max_us = jitter_max_us
        self._density_aware_startup = density_aware_startup
        self._listen_period_us = listen_period_us
        self._density_scale_factor = density_scale_factor
        self._realtime_epoch_us: int = time.monotonic_ns() // 1000
        self._playback = PlaybackState()

    @property
    def playback(self) -> PlaybackState:
        """Return the playback state for this simulation."""
        return self._playback

    def enable_debug(self) -> None:
        """Enable enhanced debugging for this simulation instance."""
        self._debug_enabled = True

    def disable_debug(self) -> None:
        """Disable enhanced debugging for this simulation instance."""
        self._debug_enabled = False

    @property
    def debug_enabled(self) -> bool:
        """Return whether enhanced debugging is enabled for this simulation."""
        return self._debug_enabled

    @property
    def id(self) -> str:
        """Return the simulation identifier."""
        return self._id

    @property
    def current_time_us(self) -> int:
        """Return the current simulation time in microseconds."""
        return self._current_time_us

    def _debug_log(self, event: str, **fields: object) -> None:
        """Emit simulation diagnostics only when debugging is enabled."""
        if self._debug_enabled:
            logger.debug(event, **fields)

    @property
    def time_mode(self) -> TimeMode:
        """Return the time advancement mode."""
        return self._time_mode

    @property
    def medium(self) -> Medium:
        """Return the radio medium."""
        return self._medium

    @property
    def event_queue(self) -> EventQueue:
        """Return the event queue."""
        return self._event_queue

    @property
    def metrics(self) -> Metrics:
        """Return the metrics collector for this simulation."""
        return self._metrics

    @property
    def seed(self) -> int | None:
        """Return the seed used for this simulation's RNG (None if unseeded)."""
        return self._seed

    @property
    def rng(self) -> random.Random:
        """Return the simulation's seedable random number generator.

        Simulation components requiring randomness should draw from this
        generator (rather than the global :mod:`random`) so that runs are
        reproducible when a seed is set.
        """
        return self._rng

    def reseed(self, seed: int | None) -> None:
        """Reset the RNG to a new seed, restoring reproducible state."""
        self._seed = seed
        self._rng = random.Random(seed)
        self._metrics.set_rng(random.Random(seed))

    @property
    def jitter_min_us(self) -> int:
        """Return the minimum TX jitter in microseconds."""
        return self._jitter_min_us

    @property
    def jitter_max_us(self) -> int:
        """Return the maximum TX jitter in microseconds."""
        return self._jitter_max_us

    @property
    def density_aware_startup(self) -> bool:
        """Return whether density-aware startup is enabled."""
        return self._density_aware_startup

    @property
    def listen_period_us(self) -> int:
        """Return the listen-before-TX period in microseconds."""
        return self._listen_period_us

    @property
    def density_scale_factor(self) -> float:
        """Return the density scale factor for startup delay calculation."""
        return self._density_scale_factor

    def calculate_startup_delay(self, node: SimNode) -> int:
        """Calculate the density-aware startup delay for a node.

        The delay is proportional to log(1 + heard_count), so denser
        neighborhoods produce longer listen periods before first TX.
        This reduces collision probability during simultaneous boot.

        Args:
            node: The node to calculate delay for.

        Returns:
            Startup delay in microseconds.
        """
        if not node.started:
            heard = len(node.heard_set)
            scale = self._density_scale_factor * math.log1p(heard)
            if scale <= 0.0:
                return 0
            return int(self._rng.uniform(0, scale))
        return 0

    def mark_node_started(self, node_id: str) -> None:
        """Mark a node as having completed its startup listen phase.

        Once marked, the node may transmit immediately without the
        density-aware listen delay.

        Args:
            node_id: ID of the node to mark as started.
        """
        node = self._nodes.get(node_id)
        if node is not None:
            node.started = True

    def is_startup_phase(self, node: SimNode) -> bool:
        """Check if a node is still in its startup listen phase.

        During startup, the node tracks neighbors heard on the medium
        but must wait for its density-scaled delay before its first TX.

        Args:
            node: The node to check.

        Returns:
            True if the node is still in the startup phase.
        """
        return self._density_aware_startup and not node.started

    def calculate_tx_jitter(self) -> int:
        """Calculate a random TX jitter delay.

        Returns a uniformly distributed random value in the range
        [jitter_min_us, jitter_max_us] using the simulation's seedable RNG.

        Returns:
            Jitter delay in microseconds.
        """
        return self._rng.randint(self._jitter_min_us, self._jitter_max_us)

    @property
    def chaos_engine(self) -> ChaosEngine | None:
        """Return the chaos engine, if any."""
        return self._chaos_engine

    @chaos_engine.setter
    def chaos_engine(self, engine: ChaosEngine | None) -> None:
        """Set the chaos engine."""
        self._chaos_engine = engine

    def add_observer(self, observer: SimulationObserver) -> None:
        """Register an observer for simulation events.

        Observers receive callbacks for TX/RX, collisions, and node lifecycle.
        See SimulationObserver protocol for available callbacks.

        Args:
            observer: Observer to register. Duplicates are silently ignored.
        """
        self._observers.add(observer)

    def remove_observer(self, observer: SimulationObserver) -> None:
        """Unregister an observer.

        Args:
            observer: Observer to remove. No-op if not registered.
        """
        self._observers.remove(observer)
