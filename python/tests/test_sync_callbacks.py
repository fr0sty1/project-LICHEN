# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Security regressions for strictly synchronous callback boundaries."""

from __future__ import annotations

import pytest

from lichen._sync_callbacks import reject_awaitable_result


class HostileAwaitable:
    def __init__(self, *, cancel_raises: bool, close_raises: bool) -> None:
        self.cancel_calls = 0
        self.close_calls = 0
        self.cancel_raises = cancel_raises
        self.close_raises = close_raises

    def __await__(self):  # type: ignore[no-untyped-def]
        if False:
            yield None
        return None

    def cancel(self) -> None:
        self.cancel_calls += 1
        if self.cancel_raises:
            raise RuntimeError("hostile cancel")

    def close(self) -> None:
        self.close_calls += 1
        if self.close_raises:
            raise RuntimeError("hostile close")


@pytest.mark.parametrize("cancel_raises,close_raises", [(True, False), (False, True), (True, True)])
def test_awaitable_cleanup_is_best_effort_and_preserves_boundary_error(
    cancel_raises: bool, close_raises: bool
) -> None:
    value = HostileAwaitable(cancel_raises=cancel_raises, close_raises=close_raises)
    with pytest.raises(TypeError, match="must not return an awaitable"):
        reject_awaitable_result(value, "hostile callback")
    assert value.cancel_calls == 1
    assert value.close_calls == 1
