# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Announce scheduler for periodic transmission (spec section 9.4).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from lichen.announce.messages import AnnounceMessage
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_MS = 300_000
DEFAULT_JITTER_MS = 30_000


class AnnounceTransmitter(Protocol):
    """Protocol for transmitting announces."""

    async def transmit_announce(self, data: bytes) -> bool:
        """Transmit announce data. Returns True on success."""
        ...


@dataclass
class SchedulerConfig:
    """Configuration for the announce scheduler."""

    interval_ms: int = DEFAULT_INTERVAL_MS
    jitter_ms: int = DEFAULT_JITTER_MS
    initial_delay_ms: int = 0

    def __post_init__(self) -> None:
        if self.interval_ms <= 0:
            raise ValueError(f"interval_ms must be > 0, got {self.interval_ms}")
        if self.jitter_ms < 0:
            raise ValueError(f"jitter_ms must be >= 0, got {self.jitter_ms}")
        if self.initial_delay_ms < 0:
            raise ValueError(f"initial_delay_ms must be >= 0, got {self.initial_delay_ms}")


@dataclass
class AnnounceScheduler:
    """Periodic announce transmission scheduler (spec 9.4).

    Why this class: Encapsulates the announce loop, sequence number
    management, and timing. Can be started/stopped independently.

    Attributes:
        identity: This node's cryptographic identity.
        transmitter: How to send announces (link layer or mock).
        config: Scheduler configuration.
        app_data: Optional application data to include in announces.
        _seq_num: Current sequence number (16-bit, wraps).
        _running: Whether the scheduler is running.
        _task: The async task running the loop.
    """

    identity: Identity
    transmitter: AnnounceTransmitter
    config: SchedulerConfig = field(default_factory=SchedulerConfig)
    app_data: bytes = field(default=b"")
    rx_channel: int = field(default=0)

    # Internal state
    _seq_num: int = field(default=0, init=False, repr=False)
    _running: bool = field(default=False, init=False, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)

    # Callbacks for persistence (optional)
    _on_seq_change: Callable[[int], None] | None = field(
        default=None, init=False, repr=False
    )

    def set_seq_num(self, seq_num: int) -> None:
        """Set the sequence number (for persistence restore).

        Why exposed: On startup, caller loads persisted seq_num and
        sets it here before starting the scheduler.

        Args:
            seq_num: The sequence number to restore.

        Raises:
            ValueError: If seq_num is out of range.
        """
        if not 0 <= seq_num <= 0xFFFF:
            raise ValueError(f"seq_num out of range: {seq_num}")
        self._seq_num = seq_num
        logger.info("sequence number set to %d", seq_num)

    def get_seq_num(self) -> int:
        """Get the current sequence number (for persistence save)."""
        return self._seq_num

    def set_on_seq_change(self, callback: Callable[[int], None]) -> None:
        """Set callback for sequence number changes (for persistence).

        Why callback: Caller owns persistence. We notify when seq_num
        changes so they can save it.

        Args:
            callback: Called with new seq_num whenever it increments.
        """
        self._on_seq_change = callback

    def _increment_seq(self) -> int:
        """Increment and return the new sequence number.

        Persistence callback runs BEFORE in-memory update. Failure is
        escalated to prevent transmitting with unpersisted seq_num
        (avoids STALE_SEQNUM after restart; follows oscore.py pattern).
        """
        new_seq = (self._seq_num + 1) & 0xFFFF

        if self._on_seq_change:
            try:
                self._on_seq_change(new_seq)
            except Exception as e:
                logger.error(
                    "seq_change callback failed for seq_num=%d: %s. "
                    "Aborting announce to prevent desync on restart.",
                    new_seq,
                    e,
                    exc_info=True,
                )
                raise RuntimeError(f"seq persistence failed: {new_seq}") from e

        self._seq_num = new_seq
        return self._seq_num

    def build_announce(self) -> AnnounceMessage:
        """Build a signed announce message.

        Returns:
            A fully signed AnnounceMessage ready for transmission.
        """
        seq = (self._seq_num + 1) & 0xFFFF
        msg = AnnounceMessage(
            originator_iid=self.identity.iid,
            pubkey=self.identity.pubkey,
            seq_num=seq,
            hop_count=0,
            rx_channel=self.rx_channel,
            app_data=self.app_data,
        )
        signature = sign(
            self.identity.privkey,
            self.identity.pubkey,
            msg.signed_data(),
        )
        self._increment_seq()
        return AnnounceMessage(
            originator_iid=msg.originator_iid,
            pubkey=msg.pubkey,
            seq_num=msg.seq_num,
            hop_count=msg.hop_count,
            rx_channel=self.rx_channel,
            signature=signature,
            app_data=msg.app_data,
        )

    async def start(self) -> None:
        """Start the announce scheduler.

        Why async: Creates a background task that runs until stop().

        Raises:
            RuntimeError: If already running.
        """
        if self._running:
            raise RuntimeError("scheduler already running")

        SchedulerConfig(
            interval_ms=self.config.interval_ms,
            jitter_ms=self.config.jitter_ms,
            initial_delay_ms=self.config.initial_delay_ms,
        )

        self._task = asyncio.create_task(
            self._loop(),
            name=f"announce-{self.identity.iid.hex()[:8]}",
        )
        self._running = True
        logger.info("announce scheduler started")

    async def stop(self) -> None:
        """Stop the announce scheduler.

        Why graceful: Cancels the task and waits for it to finish.
        Safe to call even if not running.
        """
        if not self._running:
            return

        self._running = False

        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        logger.info("announce scheduler stopped")

    async def _loop(self) -> None:
        """The main announce loop.

        Why infinite loop: Runs until cancelled by stop().

        Flow:
        1. Wait initial delay (let node discover peers first)
        2. Loop forever:
           a. Build and send announce
           b. Wait interval + random jitter
        """
        while self._running:
            try:
                initial_delay = self.config.initial_delay_ms
                if initial_delay == 0:
                    initial_delay = random.randint(
                        1000, max(1000, self.config.jitter_ms)
                    )
                await asyncio.sleep(initial_delay / 1000)
                break
            except asyncio.CancelledError:
                return
            except ValueError as e:
                logger.error("invalid announce scheduler config: %s", e)
                await asyncio.sleep(1)

        while self._running:
            try:
                await self._send_announce()

                jitter = random.randint(0, self.config.jitter_ms)
                delay = (self.config.interval_ms + jitter) / 1000
                await asyncio.sleep(delay)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("error in announce loop: %s", e)
                await asyncio.sleep(1)

    async def _send_announce(self) -> None:
        """Build and transmit an announce.

        Why separate method: Allows manual triggering for testing.
        """
        announce = self.build_announce()
        data = announce.to_bytes()

        success = await self.transmitter.transmit_announce(data)
        if success:
            logger.info("sent announce seq=%d", announce.seq_num)
        else:
            logger.warning("failed to send announce seq=%d", announce.seq_num)

    async def send_now(self) -> bool:
        """Manually trigger an immediate announce.

        Why exposed: Useful for testing and for triggering announces
        after significant events (e.g., topology change).

        Returns:
            True if announce was sent successfully.
        """
        if not self._running:
            logger.warning("cannot send announce: scheduler not running")
            return False

        announce = self.build_announce()
        data = announce.to_bytes()
        return await self.transmitter.transmit_announce(data)

    @property
    def is_running(self) -> bool:
        """Whether the scheduler is currently running."""
        return self._running
