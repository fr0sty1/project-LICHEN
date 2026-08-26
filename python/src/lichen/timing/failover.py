# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Time-source failover (spec 09 section 14.6).

When the preferred class is unavailable, pick the next class that can
establish wall-clock time. Monotonic never wins.
"""

from __future__ import annotations

from lichen.timing.wall_clock import TimeSourceClass

_DEFAULT_ORDER: tuple[TimeSourceClass, ...] = tuple(TimeSourceClass)


def select_wall_clock_source(
    available: object, order: tuple[TimeSourceClass, ...] = _DEFAULT_ORDER
) -> TimeSourceClass | None:
    """Return the best available wall-clock class, or None."""
    if type(available) is not list and type(available) is not tuple:
        raise TypeError("available must be a list or tuple")
    present: set[TimeSourceClass] = set()
    for item in available:
        if type(item) is not TimeSourceClass:
            raise TypeError("available items must be TimeSourceClass")
        present.add(item)
    for cls in order:
        if cls in present and cls.can_establish_wall_clock():
            return cls
    return None
