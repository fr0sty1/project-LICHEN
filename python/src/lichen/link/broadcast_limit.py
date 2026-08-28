# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Hop-aware broadcast rate limiting (spec 04-network.md section 6.3.3).

Per-sender hourly budgets tiered by hop limit; sender state expires after
two hours idle, resetting the budget.

Budget zones:
- Green zone (count < budget*0.5): deterministic relay
- Yellow zone (budget*0.5 <= count < budget): probabilistic relay (50% drop)
- Red zone (count >= budget): hard drop

Conformed against ``test/vectors/broadcast_rate_limiting.json``.
"""

from __future__ import annotations

import random
import time
from collections import defaultdict
from collections.abc import Callable

# Hourly per-sender budgets by hop-limit tier.
BUDGET_HL1_PER_HR = 200
BUDGET_HL2_PER_HR = 100
BUDGET_HL3_4_PER_HR = 30
BUDGET_HL5_7_PER_HR = 10

# Sender accounting state expires after this much idleness.
SENDER_STATE_IDLE_S = 2 * 3600


def broadcast_budget(hop_limit: int) -> int:
    """Hourly relay budget for a broadcast hop limit.

    Raises:
        ValueError: If hop_limit is outside [1, 7].
    """
    if hop_limit < 1 or hop_limit > 7:
        raise ValueError(f"hop_limit {hop_limit} outside [1, 7]")
    if hop_limit == 1:
        return BUDGET_HL1_PER_HR
    if hop_limit == 2:
        return BUDGET_HL2_PER_HR
    if hop_limit <= 4:
        return BUDGET_HL3_4_PER_HR
    return BUDGET_HL5_7_PER_HR


def classify_broadcast(hop_limit: int, count_in_window: int) -> tuple[str, int]:
    """Budget decision for one candidate relay, per spec 04-network.md 6.3.3.

    Args:
        hop_limit: Broadcast hop limit (1-7).
        count_in_window: Packets already admitted for this sender in the
            current rolling hour.

    Returns:
        ``(action, budget)`` where action is one of:
        - ``"relay"``: count is below yellow-zone threshold (green zone)
        - ``"probabilistic"``: count is in yellow zone [budget*0.5, budget),
          caller should relay with 50% probability
        - ``"drop"``: count >= budget, hard drop
    """
    budget = broadcast_budget(hop_limit)
    # Next packet would be number count_in_window + 1
    if count_in_window >= budget:
        return "drop", budget
    if count_in_window >= budget // 2:
        return "probabilistic", budget
    return "relay", budget


class BroadcastRateLimiter:
    """Stateful per-sender hourly windows with idle-state expiry.

    Per spec 04-network.md 6.3.3, the yellow zone (50-100% of budget) uses
    probabilistic relay with 50% drop probability.
    """

    def __init__(
        self,
        window_s: float = 3600.0,
        clock: Callable[[], float] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._window_s = window_s
        self._clock = clock
        self._rng = rng if rng is not None else random.Random()
        self._counts: dict[str, list[float]] = defaultdict(list)
        self._last_seen: dict[str, float] = {}

    def _now(self) -> float:
        return time.monotonic() if self._clock is None else self._clock()

    def admit(self, sender_iid: str, hop_limit: int) -> tuple[str, int]:
        """Record one candidate relay and return the decision.

        Returns:
            ``(action, budget)`` where action is ``"relay"`` or ``"drop"``.
            In the yellow zone, the probabilistic decision is resolved here.
        """
        now = self._now()
        last = self._last_seen.get(sender_iid)
        if last is not None and now - last > SENDER_STATE_IDLE_S:
            self._counts.pop(sender_iid, None)
        self._last_seen[sender_iid] = now

        window_start = now - self._window_s
        stamps = self._counts[sender_iid]
        while stamps and stamps[0] <= window_start:
            stamps.pop(0)

        action, budget = classify_broadcast(hop_limit, len(stamps))

        # Resolve probabilistic action per spec: 50% relay, 50% drop
        if action == "probabilistic":
            action = "relay" if self._rng.random() < 0.5 else "drop"

        if action == "relay":
            stamps.append(now)
        return action, budget


__all__ = [
    "BROADCAST_BUDGETS",
    "BroadcastRateLimiter",
    "BUDGET_HL1_PER_HR",
    "BUDGET_HL2_PER_HR",
    "BUDGET_HL3_4_PER_HR",
    "BUDGET_HL5_7_PER_HR",
    "SENDER_STATE_IDLE_S",
    "broadcast_budget",
    "classify_broadcast",
]

BROADCAST_BUDGETS = {
    1: BUDGET_HL1_PER_HR,
    2: BUDGET_HL2_PER_HR,
    3: BUDGET_HL3_4_PER_HR,
    4: BUDGET_HL3_4_PER_HR,
    5: BUDGET_HL5_7_PER_HR,
    6: BUDGET_HL5_7_PER_HR,
    7: BUDGET_HL5_7_PER_HR,
}
