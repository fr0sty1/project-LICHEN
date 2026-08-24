# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link-layer replay protection (spec section 4.4).

Replay protection orders the 8-bit epoch as a finite value and uses a sliding
window only for the 16-bit sequence number within that epoch. A higher epoch
starts a fresh sequence window; a lower epoch is always stale. Epoch 255 is
terminal, so advancing from ``(255, 65535)`` to ``(0, 0)`` requires a new key
and replay state.

Each receiver keeps, per sender, the highest counter seen plus a sliding
bitmap window so that out-of-order-but-recent frames are still accepted exactly
once. This implements the spec's acceptance rules:

    Epoch  > LastEpoch                          -> accept
    Epoch == LastEpoch, SeqNum > LastSeqNum     -> accept
    Epoch == LastEpoch, SeqNum within window    -> accept iff not already seen
    Epoch  < LastEpoch                          -> reject (replay)
    Epoch == LastEpoch, SeqNum <= window floor  -> reject (replay)

Sequence numbers do not wrap within an epoch. Ordinary sequence exhaustion is
handled by advancing to the next epoch, up to the finite epoch limit.

The 24-bit logical counter (epoch<<16 | seqnum) uses half-space arithmetic in
some comparison paths (see seqnum.signed_diff, CoAP observe, gradient timers).
The boundary at diff=0x800000 treats frames exactly 8,388,608 positions 'ahead'
as old/replay. This is intentional and conservative: frames more than half the
counter space away could be either very old OR very far ahead, so reject. The
WRAPAROUND_WARNING_THRESHOLD at 0xFF0000 ensures re-keying happens before the
ambiguous zone. This is defense in depth; epoch logic and spec prohibition on
full wrap make the edge case unreachable in normal operation.
"""

from __future__ import annotations

import threading
import warnings
from collections import OrderedDict

WINDOW_SIZE = 32  # out-of-order tolerance, in counter positions (spec 4.4)

# SECURITY: Warn when the finite counter approaches its terminal value. At this
# threshold (~64K frames remaining), the receiver should expect re-keying.
WRAPAROUND_WARNING_THRESHOLD = 0xFF0000


def logical_counter(epoch: int, seqnum: int) -> int:
    """Combine an 8-bit epoch and 16-bit seqnum into the 24-bit counter."""
    if type(epoch) is not int:
        raise TypeError("epoch must be an exact integer")
    if type(seqnum) is not int:
        raise TypeError("seqnum must be an exact integer")
    if not 0 <= epoch <= 0xFF:
        raise ValueError(f"epoch out of range: {epoch}")
    if not 0 <= seqnum <= 0xFFFF:
        raise ValueError(f"seqnum out of range: {seqnum}")
    return (epoch << 16) | seqnum


class ReplayWindow:
    """Anti-replay sliding window over the logical counter, for a single sender.

    The window tracks the highest accepted counter and a same-epoch sequence
    bitmap where bit ``i`` means ``highest_seqnum - i`` has been seen.

    Thread safety: The check_and_update() method is fully atomic and thread-safe.
    The two-phase methods check() and commit() are NOT individually thread-safe;
    callers using the two-phase pattern must provide external synchronization to
    prevent TOCTOU races where concurrent threads both pass check() before either
    commits.
    """

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        if window_size != WINDOW_SIZE:
            raise ValueError(f"window_size must be {WINDOW_SIZE}, got {window_size}")
        self._window_size = window_size
        self._highest = -1  # no frame accepted yet
        self._bitmap = 0
        self._wraparound_warned = False
        self._lock = threading.Lock()

    @property
    def highest(self) -> int:
        """Highest logical counter accepted so far, or -1 if none."""
        return self._highest

    def check(self, epoch: int, seqnum: int) -> bool:
        """Check if a frame's (epoch, seqnum) is fresh WITHOUT updating state.

        This is the first phase of two-phase replay checking. Call this to
        validate, then call commit() only AFTER all other validation passes.

        Returns:
            True if the frame is fresh (would be accepted); False if it is a
            replay or falls below the window floor.
        """
        # Validate inputs via logical_counter (raises on out-of-range)
        logical_counter(epoch, seqnum)

        # First frame from this sender.
        if self._highest < 0:
            return True

        highest_epoch = self._highest >> 16
        if epoch < highest_epoch:
            return False

        if epoch > highest_epoch:
            return True

        highest_seqnum = self._highest & 0xFFFF
        if seqnum > highest_seqnum:
            return True

        # Within or below the same-epoch window.
        offset = highest_seqnum - seqnum
        if offset >= self._window_size:
            return False  # below the window floor: too old
        mask = 1 << offset
        # Return False if already seen (replay), True if fresh
        return not (self._bitmap & mask)

    def commit(self, epoch: int, seqnum: int) -> None:
        """Commit the replay floor for a validated frame.

        This is the second phase of two-phase replay checking. MUST only be
        called after check() returned True AND all other validation passed.
        Calling commit() for a counter that would fail check() is undefined.
        """
        counter = logical_counter(epoch, seqnum)

        # First frame from this sender.
        if self._highest < 0:
            self._highest = counter
            self._bitmap = 1
            # SECURITY: Warn if the first frame is already near exhaustion.
            if counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return

        highest_epoch = self._highest >> 16
        if epoch > highest_epoch:
            self._highest = counter
            self._bitmap = 1
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return

        highest_seqnum = self._highest & 0xFFFF
        if seqnum > highest_seqnum:
            shift = seqnum - highest_seqnum
            if shift >= self._window_size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self._window_size) - 1)
            self._highest = counter
            # SECURITY: Warn once when approaching the terminal counter value.
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=2,
                )
            return

        # Within the same-epoch window.
        offset = highest_seqnum - seqnum
        mask = 1 << offset
        self._bitmap |= mask

    def check_and_update(self, epoch: int, seqnum: int) -> bool:
        """Validate a frame's (epoch, seqnum) and record it if fresh.

        This is a convenience method that combines check() and commit() into
        one atomic operation. Use check() + commit() separately when validation
        must complete between the two phases.

        Thread safety: This method is fully atomic - no other thread can
        observe the state between check and commit. The two-phase pattern
        (separate check() + commit()) is NOT atomic; callers using that
        pattern must provide external synchronization.

        Returns:
            True if the frame is fresh (accepted); False if it is a replay or
            falls below the window floor. State is only updated on acceptance.
        """
        # SECURITY: Hold lock for entire check+commit to prevent TOCTOU race.
        # Without this, two threads could both pass check() for the same counter
        # before either commits, causing duplicate acceptance.
        with self._lock:
            if not self._check_unlocked(epoch, seqnum):
                return False
            self._commit_unlocked(epoch, seqnum)
            return True

    def _check_unlocked(self, epoch: int, seqnum: int) -> bool:
        """Internal check without lock - caller must hold _lock."""
        # Validate inputs (raises on out-of-range)
        logical_counter(epoch, seqnum)

        # First frame from this sender.
        if self._highest < 0:
            return True

        highest_epoch = self._highest >> 16
        if epoch < highest_epoch:
            return False

        if epoch > highest_epoch:
            return True

        highest_seqnum = self._highest & 0xFFFF
        if seqnum > highest_seqnum:
            return True

        # Within or below the same-epoch window.
        offset = highest_seqnum - seqnum
        if offset >= self._window_size:
            return False  # below the window floor: too old
        mask = 1 << offset
        return not (self._bitmap & mask)

    def _commit_unlocked(self, epoch: int, seqnum: int) -> None:
        """Internal commit without lock - caller must hold _lock."""
        counter = logical_counter(epoch, seqnum)

        # First frame from this sender.
        if self._highest < 0:
            self._highest = counter
            self._bitmap = 1
            # SECURITY: Warn if the first frame is already near exhaustion.
            if counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=4,  # Adjusted for internal call depth
                )
            return

        highest_epoch = self._highest >> 16
        if epoch > highest_epoch:
            self._highest = counter
            self._bitmap = 1
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=4,
                )
            return

        highest_seqnum = self._highest & 0xFFFF
        if seqnum > highest_seqnum:
            shift = seqnum - highest_seqnum
            if shift >= self._window_size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self._window_size) - 1)
            self._highest = counter
            # SECURITY: Warn once when approaching the terminal counter value.
            if not self._wraparound_warned and counter >= WRAPAROUND_WARNING_THRESHOLD:
                self._wraparound_warned = True
                warnings.warn(
                    f"Replay counter {counter:#x} approaching 24-bit limit (0xFFFFFF). "
                    "Re-key this link before counter exhaustion.",
                    UserWarning,
                    stacklevel=4,
                )
            return

        # Within the same-epoch window.
        offset = highest_seqnum - seqnum
        mask = 1 << offset
        self._bitmap |= mask


class ReplayProtector:
    """Per-sender replay protection.

    Maintains an independent :class:`ReplayWindow` for each sender identity, so
    senders never interfere with one another.

    Thread safety: The check_and_update() method is fully atomic and thread-safe.
    The two-phase methods check() and commit() protect window table access but
    are NOT atomic across the check-then-commit sequence; callers using the
    two-phase pattern must provide external synchronization to prevent TOCTOU
    races.
    """

    def __init__(
        self,
        window_size: int = WINDOW_SIZE,
        max_peers: int = 32,
        max_retained_floors: int = 128,
    ) -> None:
        if window_size != WINDOW_SIZE:
            raise ValueError(f"window_size must be {WINDOW_SIZE}, got {window_size}")
        if max_peers < 1:
            raise ValueError(f"max_peers must be positive, got {max_peers}")
        if max_retained_floors < max_peers:
            raise ValueError("max_retained_floors must be at least max_peers")
        self._window_size = window_size
        self._max_peers = max_peers
        self._max_retained_floors = max_retained_floors
        self._windows: OrderedDict[bytes | str | int, ReplayWindow] = OrderedDict()
        # A floor survives window eviction.  Reconstructing only the high-water
        # deliberately rejects formerly out-of-order counters rather than risk
        # accepting a replay after losing the bitmap.
        self._floors: OrderedDict[bytes | str | int, int] = OrderedDict()
        self._pins: dict[bytes | str | int, int] = {}
        self._lock = threading.RLock()
        self._owner_token: object | None = None

    def _claim_owner(self, token: object) -> None:
        """Seal lifecycle mutation to one owning LinkLayer."""
        with self._lock:
            if self._owner_token is not None:
                raise RuntimeError("replay protector already has an owner")
            self._owner_token = token

    def _require_admin_unlocked(self, token: object | None) -> None:
        if self._owner_token is not None and token is not self._owner_token:
            raise RuntimeError("live replay state is owned by LinkLayer")

    def _remember_floor_unlocked(self, sender: bytes | str | int, floor: int) -> None:
        if sender not in self._floors and len(self._floors) >= self._max_retained_floors:
            raise ReplayCapacityError("replay floor registry is full")
        self._floors[sender] = max(floor, self._floors.get(sender, -1))
        self._floors.move_to_end(sender)

    def _evict_window_unlocked(self) -> None:
        for candidate in self._windows:
            if self._pins.get(candidate, 0) == 0:
                del self._windows[candidate]
                return
        raise ReplayCapacityError("all replay windows are pinned")

    def _get_or_create_window_unlocked(self, sender: bytes | str | int) -> ReplayWindow:
        """Get or create the replay window for a sender. Caller must hold _lock."""
        if sender in self._windows:
            self._windows.move_to_end(sender)
            return self._windows[sender]
        # Preflight every bounded table before evicting anything.  A rejected
        # admission must not degrade an unrelated sender's exact replay bitmap
        # or LRU position.
        if sender not in self._floors and len(self._floors) >= self._max_retained_floors:
            raise ReplayCapacityError("replay floor registry is full")
        if len(self._windows) >= self._max_peers:
            self._evict_window_unlocked()
        window = ReplayWindow(self._window_size)
        floor = self._floors.get(sender, -1)
        if floor >= 0:
            # The exact historic bitmap may have been evicted.  Mark the whole
            # restored window as seen, which is conservative and fail-closed.
            window._highest = floor
            window._bitmap = (1 << self._window_size) - 1
        self._windows[sender] = window
        self._windows.move_to_end(sender)
        return window

    def _candidate_window_unlocked(self, sender: bytes | str | int) -> ReplayWindow:
        """Return current or conservative temporary state without mutating tables."""
        window = self._windows.get(sender)
        if window is not None:
            return window
        window = ReplayWindow(self._window_size)
        floor = self._floors.get(sender, -1)
        if floor >= 0:
            window._highest = floor
            window._bitmap = (1 << self._window_size) - 1
        return window

    def _admit_window_unlocked(
        self,
        sender: bytes | str | int,
        window: ReplayWindow,
    ) -> None:
        """Admit an already-accepted candidate after every bound is preflighted."""
        if sender not in self._floors and len(self._floors) >= self._max_retained_floors:
            raise ReplayCapacityError("replay floor registry is full")
        if sender not in self._windows and len(self._windows) >= self._max_peers:
            self._evict_window_unlocked()
        self._windows[sender] = window
        self._windows.move_to_end(sender)

    def check(self, sender: bytes | str | int, epoch: int, seqnum: int) -> bool:
        """Check if a frame from sender is fresh WITHOUT updating state.

        This is the first phase of two-phase replay checking. Call this to
        validate, then call commit() only AFTER all other validation passes.

        Returns:
            True if fresh (would be accepted), False if a replay / below window.
        """
        logical_counter(epoch, seqnum)
        with self._lock:
            window = self._candidate_window_unlocked(sender)
            return window.check(epoch, seqnum)

    def commit(self, sender: bytes | str | int, epoch: int, seqnum: int) -> None:
        """Commit the replay floor for a validated frame from sender.

        This is the second phase of two-phase replay checking. MUST only be
        called after check() returned True AND all other validation passed.
        """
        logical_counter(epoch, seqnum)
        with self._lock:
            self._require_admin_unlocked(None)
            window = self._candidate_window_unlocked(sender)
            window.commit(epoch, seqnum)
            self._admit_window_unlocked(sender, window)
            self._remember_floor_unlocked(sender, window.highest)

    def check_and_update(self, sender: bytes | str | int, epoch: int, seqnum: int) -> bool:
        """Validate and record a frame from ``sender``.

        This is a convenience method that combines check() and commit() into
        one atomic operation. Use check() + commit() separately when validation
        must complete between the two phases.

        Thread safety: This method is fully atomic - no other thread can
        observe the state between check and commit. The two-phase pattern
        (separate check() + commit()) is NOT atomic at this level; callers
        using that pattern must provide external synchronization.

        Returns:
            True if fresh (accepted), False if a replay / below the window.
        """
        # SECURITY: Hold lock for entire check+commit to prevent TOCTOU race.
        # Without this, two threads could both pass check() for the same counter
        # before either commits, causing duplicate acceptance.
        return self._check_and_update(sender, epoch, seqnum, owner_token=None)

    def _check_and_update_owned(
        self,
        sender: bytes | str | int,
        epoch: int,
        seqnum: int,
        owner_token: object,
    ) -> bool:
        return self._check_and_update(sender, epoch, seqnum, owner_token=owner_token)

    def _check_and_update(
        self,
        sender: bytes | str | int,
        epoch: int,
        seqnum: int,
        *,
        owner_token: object | None,
    ) -> bool:
        logical_counter(epoch, seqnum)
        with self._lock:
            self._require_admin_unlocked(owner_token)
            window = self._candidate_window_unlocked(sender)
            accepted = window.check_and_update(epoch, seqnum)
            if accepted:
                self._admit_window_unlocked(sender, window)
                self._remember_floor_unlocked(sender, window.highest)
            return accepted

    def highest(self, sender: bytes | str | int) -> int:
        """Return the sender's accepted high-water counter, or ``-1``.

        The snapshot is taken under the same lock that protects window lookup
        and replay updates.  It intentionally does not allocate a window for an
        unseen peer, so opening a higher-layer session cannot evict replay
        state for another peer.
        """
        with self._lock:
            window = self._windows.get(sender)
            return self._floors.get(sender, -1) if window is None else window.highest

    def pin(self, sender: bytes | str | int) -> None:
        """Prevent an active or tombstoned peer window from being evicted."""
        self._pin(sender, owner_token=None)

    def _pin_owned(self, sender: bytes | str | int, owner_token: object) -> None:
        self._pin(sender, owner_token=owner_token)

    def _pin(self, sender: bytes | str | int, *, owner_token: object | None) -> None:
        with self._lock:
            self._require_admin_unlocked(owner_token)
            self._get_or_create_window_unlocked(sender)
            self._pins[sender] = self._pins.get(sender, 0) + 1

    def unpin(self, sender: bytes | str | int) -> None:
        """Release one replay-window pin while retaining the permanent floor."""
        self._unpin(sender, owner_token=None)

    def _unpin_owned(self, sender: bytes | str | int, owner_token: object) -> None:
        self._unpin(sender, owner_token=owner_token)

    def _unpin(self, sender: bytes | str | int, *, owner_token: object | None) -> None:
        with self._lock:
            self._require_admin_unlocked(owner_token)
            count = self._pins.get(sender, 0)
            if count <= 1:
                self._pins.pop(sender, None)
            else:
                self._pins[sender] = count - 1

    def reset(self, sender: bytes | str | int) -> None:
        """Forget all state for a sender (e.g. on re-keying)."""
        with self._lock:
            self._require_admin_unlocked(None)
            self._windows.pop(sender, None)
            self._floors.pop(sender, None)
            self._pins.pop(sender, None)

    def has_state(self, sender: bytes | str | int) -> bool:
        """Return whether ``sender`` owns any replay, floor, or pin state."""
        with self._lock:
            return sender in self._windows or sender in self._floors or sender in self._pins

    def export_state(self) -> dict[str, object]:
        """Return a JSON-safe exact replay snapshot under the protector lock."""
        with self._lock:
            def encode_sender(sender: bytes | str | int) -> dict[str, object]:
                if type(sender) is bytes:
                    return {"type": "bytes", "value": sender.hex()}
                if type(sender) is str:
                    return {"type": "str", "value": sender}
                if type(sender) is int:
                    return {"type": "int", "value": sender}
                raise TypeError("unsupported replay sender identity type")

            return {
                "windows": [
                    {
                        "sender": encode_sender(sender),
                        "highest": window._highest,
                        "bitmap": window._bitmap,
                        "warned": window._wraparound_warned,
                    }
                    for sender, window in self._windows.items()
                ],
                "floors": [
                    {"sender": encode_sender(sender), "floor": floor}
                    for sender, floor in self._floors.items()
                ],
                "pins": [
                    {"sender": encode_sender(sender), "count": count}
                    for sender, count in self._pins.items()
                ],
            }

    def import_state(self, state: object) -> None:
        """Atomically restore a validated JSON-safe replay snapshot."""
        self._import_state(state, owner_token=None)

    def _import_owned(self, state: object, owner_token: object) -> None:
        self._import_state(state, owner_token=owner_token)

    def _import_state(self, state: object, *, owner_token: object | None) -> None:
        """Restore one validated snapshot through the lifecycle owner."""
        if type(state) is not dict:
            raise ValueError("replay state must be an object")

        def decode_sender(encoded: object) -> bytes | str | int:
            if type(encoded) is not dict or set(encoded) != {"type", "value"}:
                raise ValueError("invalid replay sender encoding")
            kind, value = encoded["type"], encoded["value"]
            if kind == "bytes" and type(value) is str:
                sender = bytes.fromhex(value)
                if not sender:
                    raise ValueError("empty replay sender identity")
                return sender
            if kind == "str" and type(value) is str:
                return value
            if kind == "int" and type(value) is int:
                return value
            raise ValueError("invalid replay sender encoding")

        if set(state) != {"windows", "floors", "pins"}:
            raise ValueError("invalid replay state fields")
        raw_windows, raw_floors, raw_pins = state["windows"], state["floors"], state["pins"]
        if not all(type(value) is list for value in (raw_windows, raw_floors, raw_pins)):
            raise ValueError("invalid replay state tables")
        windows: OrderedDict[bytes | str | int, ReplayWindow] = OrderedDict()
        floors: OrderedDict[bytes | str | int, int] = OrderedDict()
        pins: dict[bytes | str | int, int] = {}
        for item in raw_floors:
            if type(item) is not dict or set(item) != {"sender", "floor"}:
                raise ValueError("invalid replay floor")
            sender = decode_sender(item["sender"])
            floor = item["floor"]
            if type(floor) is not int or not -1 <= floor <= 0xFF_FFFF or sender in floors:
                raise ValueError("invalid replay floor")
            floors[sender] = floor
        for item in raw_windows:
            if type(item) is not dict or set(item) != {"sender", "highest", "bitmap", "warned"}:
                raise ValueError("invalid replay window")
            sender = decode_sender(item["sender"])
            highest, bitmap, warned = item["highest"], item["bitmap"], item["warned"]
            if (
                type(highest) is not int
                or not -1 <= highest <= 0xFF_FFFF
                or type(bitmap) is not int
                or not 0 <= bitmap < (1 << self._window_size)
                or (highest == -1 and bitmap != 0)
                or (highest >= 0 and (bitmap == 0 or not bitmap & 1))
                or type(warned) is not bool
                or sender in windows
                or (highest >= 0 and (sender not in floors or floors[sender] != highest))
                or (highest == -1 and sender in floors)
            ):
                raise ValueError("invalid replay window")
            window = ReplayWindow(self._window_size)
            window._highest = highest
            window._bitmap = bitmap
            window._wraparound_warned = warned
            windows[sender] = window
        for item in raw_pins:
            if type(item) is not dict or set(item) != {"sender", "count"}:
                raise ValueError("invalid replay pin")
            sender = decode_sender(item["sender"])
            count = item["count"]
            if type(count) is not int or count < 1 or sender in pins or sender not in windows:
                raise ValueError("invalid replay pin")
            pins[sender] = count
        if len(windows) > self._max_peers or len(floors) > self._max_retained_floors:
            raise ValueError("persisted replay state exceeds configured capacity")
        with self._lock:
            self._require_admin_unlocked(owner_token)
            self._windows = windows
            self._floors = floors
            self._pins = pins

    def rotate(self, old_sender: bytes | str | int, new_sender: bytes | str | int) -> None:
        """Atomically retire an old key and initialize a replacement key."""
        self._rotate(old_sender, new_sender, owner_token=None)

    def _rotate_owned(
        self,
        old_sender: bytes | str | int,
        new_sender: bytes | str | int,
        owner_token: object,
    ) -> None:
        self._rotate(old_sender, new_sender, owner_token=owner_token)

    def _rotate(
        self,
        old_sender: bytes | str | int,
        new_sender: bytes | str | int,
        *,
        owner_token: object | None,
    ) -> None:
        """Rotate state only through the lifecycle owner once sealed."""
        if old_sender == new_sender:
            raise ValueError("key rotation requires a distinct replacement sender")
        with self._lock:
            self._require_admin_unlocked(owner_token)
            if (
                new_sender in self._windows
                or new_sender in self._floors
                or new_sender in self._pins
            ):
                raise ValueError("replacement sender already has replay state")
            self._windows.pop(old_sender, None)
            self._floors.pop(old_sender, None)
            self._pins.pop(old_sender, None)


class ReplayCapacityError(RuntimeError):
    """Replay state cannot safely admit another authenticated peer."""
