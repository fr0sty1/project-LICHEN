# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Small runtime state-machine verifier for Python simulator code."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Generic, TypeVar

from typing_extensions import Concatenate, ParamSpec

logger = logging.getLogger(__name__)

S = TypeVar("S", bound=Enum)
T = TypeVar("T")
R = TypeVar("R")
P = ParamSpec("P")


class StateError(Exception):
    """Raised when code attempts an invalid state operation."""


@dataclass(frozen=True)
class StateMachine(Generic[S]):
    """Validated state holder with explicit transition table."""

    initial: S
    transitions: Mapping[S, frozenset[S]]
    name: str = "state"
    _state: S = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.initial, Enum):
            raise StateError(f"{self.name}: invalid initial state {self.initial!r}")
        known_states = set(self.transitions)
        for allowed in self.transitions.values():
            known_states.update(allowed)
        if self.initial not in known_states:
            raise StateError(
                f"{self.name}: initial state {self.initial.name} is not in transition table"
            )
        object.__setattr__(self, "_state", self.initial)

    @property
    def state(self) -> S:
        """Return the current state."""
        return self._state

    def transition(self, new: S) -> None:
        """Move to ``new`` if the transition table permits it."""
        if not isinstance(new, type(self._state)):
            raise StateError(f"{self.name}: invalid state value {new!r}")
        if new == self._state:
            logger.debug("%s: state unchanged at %s", self.name, self._state.name)
            return
        allowed = self.transitions.get(self._state, frozenset())
        if new not in allowed:
            raise StateError(f"{self.name}: invalid transition {self._state.name} -> {new.name}")
        logger.debug("%s: %s -> %s", self.name, self._state.name, new.name)
        object.__setattr__(self, "_state", new)

    def require(self, *states: S) -> None:
        """Raise if the current state is not one of ``states``."""
        if self._state not in states:
            expected = ", ".join(state.name for state in states)
            raise StateError(f"{self.name}: expected {expected}, got {self._state.name}")


def requires_state(
    *states: S,
) -> Callable[[Callable[Concatenate[T, P], R]], Callable[Concatenate[T, P], R]]:
    """Decorate instance methods that require one or more current states."""

    def decorator(
        method: Callable[Concatenate[T, P], R],
    ) -> Callable[Concatenate[T, P], R]:
        @wraps(method)
        def wrapper(self: T, *args: P.args, **kwargs: P.kwargs) -> R:
            machine = getattr(self, "_state_machine", None)
            if not isinstance(machine, StateMachine):
                raise StateError(f"{type(self).__name__}: missing _state_machine")
            machine.require(*states)
            return method(self, *args, **kwargs)

        return wrapper

    return decorator
