# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Chaos rules framework for the LICHEN simulator.

This module provides a framework for injecting network faults and
degradations into the simulator for testing resilience and edge cases.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4

from lichen.sim.medium import RxCandidate
from lichen.sim.transmission import Transmission


class ChaosRule(ABC):
    """Base class for chaos rules.

    Chaos rules intercept transmissions and can modify or drop them
    to simulate network faults, interference, and degradations.
    """

    id: str  # Unique rule identifier

    @abstractmethod
    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Return True if this rule applies to the given TX/RX pair.

        Args:
            tx: The transmission being evaluated.
            rx_node_id: ID of the receiving node.

        Returns:
            True if this rule should be applied.
        """
        ...

    @abstractmethod
    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Apply the rule to a reception candidate.

        Args:
            candidate: The reception candidate to modify.
            rx_position: Position of the receiver (needed for some rules).

        Returns:
            Modified candidate, or None to drop the reception.
        """
        ...


@dataclass
class DropRule(ChaosRule):
    """Drop packets to/from a specific node.

    Can drop packets where the node is the sender, receiver, or both.

    Attributes:
        node_id: ID of the node to target.
        direction: Which direction to drop ("tx", "rx", or "both").
        id: Unique rule identifier.
    """

    node_id: str
    direction: Literal["tx", "rx", "both"] = "both"
    id: str = field(default_factory=lambda: str(uuid4()))

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if node_id is sender (tx) or receiver (rx) based on direction."""
        if self.direction == "tx":
            return tx.source_node_id == self.node_id
        elif self.direction == "rx":
            return rx_node_id == self.node_id
        else:  # both
            return tx.source_node_id == self.node_id or rx_node_id == self.node_id

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Drop the packet by returning None."""
        return None


@dataclass
class LossRule(ChaosRule):
    """Probabilistically drop packets to/from a node.

    Each matching reception is dropped with probability ``loss_probability``,
    drawing from ``rng``. Pass a seeded generator (e.g. a Simulation's ``rng``)
    to make the loss pattern reproducible.

    Attributes:
        node_id: ID of the node to target.
        loss_probability: Drop probability in [0.0, 1.0].
        direction: Which direction to affect ("tx", "rx", or "both").
        rng: Random source; defaults to an unseeded generator.
        id: Unique rule identifier.
    """

    node_id: str
    loss_probability: float
    direction: Literal["tx", "rx", "both"] = "both"
    rng: random.Random = field(default_factory=random.Random)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if not 0.0 <= self.loss_probability <= 1.0:
            raise ValueError(
                f"loss_probability must be in [0, 1], got {self.loss_probability}"
            )

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if node_id is sender (tx) or receiver (rx) based on direction."""
        if self.direction == "tx":
            return tx.source_node_id == self.node_id
        elif self.direction == "rx":
            return rx_node_id == self.node_id
        else:  # both
            return tx.source_node_id == self.node_id or rx_node_id == self.node_id

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Drop the packet with the configured probability, else pass it on."""
        if self.rng.random() < self.loss_probability:
            return None
        return candidate


@dataclass
class PartitionRule(ChaosRule):
    """Partition network into groups that cannot communicate.

    Nodes in different groups cannot send packets to each other.
    Nodes in the same group can communicate normally.
    Nodes not in any group are not affected.

    Attributes:
        groups: List of node ID sets defining the partitions.
        id: Unique rule identifier.
    """

    groups: list[set[str]]
    id: str = field(default_factory=lambda: str(uuid4()))

    def _find_group(self, node_id: str) -> int | None:
        """Find which group a node belongs to, or None if not in any group."""
        for i, group in enumerate(self.groups):
            if node_id in group:
                return i
        return None

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if sender and receiver are in different groups."""
        tx_group = self._find_group(tx.source_node_id)
        rx_group = self._find_group(rx_node_id)

        # Only match if both nodes are in groups AND they're different groups
        if tx_group is None or rx_group is None:
            return False
        return tx_group != rx_group

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Drop cross-partition packets."""
        return None


@dataclass
class DegradeRule(ChaosRule):
    """Reduce RSSI for a specific node.

    Simulates antenna degradation, obstruction, or other signal
    quality issues affecting a specific node.

    Attributes:
        node_id: ID of the node to degrade.
        rssi_penalty_db: Positive value subtracted from RSSI.
        id: Unique rule identifier.
    """

    node_id: str
    rssi_penalty_db: float
    id: str = field(default_factory=lambda: str(uuid4()))

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if node_id is sender or receiver."""
        return tx.source_node_id == self.node_id or rx_node_id == self.node_id

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate:
        """Return new RxCandidate with reduced RSSI and SNR."""
        return RxCandidate(
            transmission=candidate.transmission,
            rssi=candidate.rssi - self.rssi_penalty_db,
            snr=candidate.snr - self.rssi_penalty_db,
        )


@dataclass
class JammerRule(ChaosRule):
    """Jam all communications within a radius.

    Simulates a radio jammer at a fixed position that prevents
    reception for any receiver within its effective radius.

    Attributes:
        x: X coordinate of jammer position in meters.
        y: Y coordinate of jammer position in meters.
        z: Z coordinate of jammer position in meters.
        radius_m: Effective jamming radius in meters.
        id: Unique rule identifier.
    """

    x: float
    y: float
    z: float
    radius_m: float
    id: str = field(default_factory=lambda: str(uuid4()))

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Always return True; distance check happens in apply."""
        return True

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Jam reception if receiver is within radius.

        Args:
            candidate: The reception candidate.
            rx_position: Position of the receiver. If None, cannot determine
                if jammed, so candidate passes through unchanged.

        Returns:
            None if receiver is within jamming radius, otherwise the
            candidate unchanged.
        """
        if rx_position is None:
            return candidate

        # Calculate 3D distance from jammer to receiver
        distance = math.sqrt(
            (rx_position[0] - self.x) ** 2
            + (rx_position[1] - self.y) ** 2
            + (rx_position[2] - self.z) ** 2
        )

        if distance <= self.radius_m:
            return None  # Jammed
        return candidate


@dataclass
class LatencyRule(ChaosRule):
    """Add artificial delivery latency to a specific node.

    Sets ``added_latency_us`` on the candidate; the simulator's
    ``get_rx_result()`` filters out candidates that have not yet
    cleared their added delivery delay.

    Attributes:
        node_id: ID of the node to add latency to (sender or receiver).
        added_us: Additional delivery delay in microseconds.
        id: Unique rule identifier.
    """

    node_id: str
    added_us: int
    id: str = field(default_factory=lambda: str(uuid4()))

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if node_id is sender or receiver."""
        return tx.source_node_id == self.node_id or rx_node_id == self.node_id

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate:
        """Add latency to the candidate's delivery delay."""
        from dataclasses import replace

        return replace(candidate, added_latency_us=candidate.added_latency_us + self.added_us)


@dataclass
class TxJitterRule(ChaosRule):
    """Override TX jitter for a specific node or globally.

    Provides custom jitter parameters that the simulator can query
    when scheduling transmissions. When ``node_id`` is None, the rule
    applies globally to all nodes.

    Attributes:
        jitter_min_us: Minimum jitter delay in microseconds.
        jitter_max_us: Maximum jitter delay in microseconds.
        node_id: ID of the node to apply jitter to, or None for global.
        rng: Random source for generating jitter values.
        id: Unique rule identifier.
    """

    jitter_min_us: int
    jitter_max_us: int
    node_id: str | None = None
    rng: random.Random = field(default_factory=random.Random)
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if self.jitter_min_us < 0:
            raise ValueError(
                f"jitter_min_us must be non-negative, got {self.jitter_min_us}"
            )
        if self.jitter_max_us < self.jitter_min_us:
            raise ValueError(
                f"jitter_max_us ({self.jitter_max_us}) must be >= jitter_min_us ({self.jitter_min_us})"
            )

    def matches(self, tx: Transmission, rx_node_id: str) -> bool:
        """Match if node_id is None (global) or matches the sender."""
        if self.node_id is None:
            return True
        return tx.source_node_id == self.node_id

    def apply(
        self,
        candidate: RxCandidate,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate:
        """Pass through unchanged; jitter is applied at TX scheduling time."""
        return candidate

    def get_jitter_us(self) -> int:
        """Generate a random jitter value within the configured range.

        Returns:
            Jitter delay in microseconds, uniformly distributed
            between jitter_min_us and jitter_max_us (inclusive).
        """
        return self.rng.randint(self.jitter_min_us, self.jitter_max_us)


class ChaosEngine:
    """Manages and applies chaos rules.

    The ChaosEngine maintains a collection of chaos rules and applies
    them to reception candidates in order. Rules can drop packets or
    modify their reception characteristics.
    """

    def __init__(self) -> None:
        """Initialize an empty ChaosEngine."""
        self._rules: dict[str, ChaosRule] = {}

    def add_rule(self, rule: ChaosRule) -> str:
        """Add a rule to the engine.

        Args:
            rule: The chaos rule to add.

        Returns:
            The rule's ID.
        """
        self._rules[rule.id] = rule
        return rule.id

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine.

        Args:
            rule_id: ID of the rule to remove.

        Returns:
            True if the rule was found and removed, False otherwise.
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def clear(self) -> None:
        """Remove all rules from the engine."""
        self._rules.clear()

    def get_rules(self) -> list[ChaosRule]:
        """Get all rules in the engine.

        Returns:
            List of all chaos rules, in insertion order.
        """
        return list(self._rules.values())

    def apply_all(
        self,
        candidate: RxCandidate,
        rx_node_id: str,
        rx_position: tuple[float, float, float] | None = None,
    ) -> RxCandidate | None:
        """Apply all matching rules to a reception candidate.

        Rules are applied in the order they were added. If any rule
        returns None (drops the packet), None is returned immediately.
        Otherwise, the (possibly modified) candidate is returned.

        Args:
            candidate: The reception candidate to process.
            rx_node_id: ID of the receiving node.
            rx_position: Position of the receiver (needed for some rules).

        Returns:
            The modified candidate, or None if any rule dropped it.
        """
        current = candidate
        tx = candidate.transmission

        for rule in self._rules.values():
            if rule.matches(tx, rx_node_id):
                result = rule.apply(current, rx_position)
                if result is None:
                    return None
                current = result

        return current
