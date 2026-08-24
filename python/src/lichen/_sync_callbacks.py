# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fail-closed helpers for APIs that require synchronous callbacks."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from collections.abc import Callable


def reject_awaitable_result(value: object, name: str) -> object:
    """Cancel or close an unexpected awaitable, then reject it.

    ``Task.cancel()`` is synchronous but delivery of ``CancelledError`` occurs
    when its event loop next runs.  Plain ``Future`` objects become cancelled
    immediately.  Coroutine and custom closeable awaitables are closed before
    this function raises, preventing a rejected callback result from later
    being awaited as an accepted transaction.
    """
    if not inspect.isawaitable(value):
        return value
    cancel = getattr(value, "cancel", None)
    close = getattr(value, "close", None)
    if isinstance(value, asyncio.Future):
        cancel = value.cancel
    if callable(cancel):
        with contextlib.suppress(BaseException):
            cancel()
    if callable(close):
        with contextlib.suppress(BaseException):
            close()
    raise TypeError(f"{name} must not return an awaitable")


def require_sync_callable(callback: object, name: str) -> Callable[..., object]:
    """Return an exact synchronous callable or reject it before registration."""
    if not callable(callback):
        raise TypeError(f"{name} must be callable")
    if inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        type(callback).__call__
    ):
        raise TypeError(f"{name} must be synchronous")
    return callback
