# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SCHC reassembly — receiver side (RFC 8724 section 8)."""

from __future__ import annotations

from lichen.schc.fragment import Fragment, FragmentSender
from lichen.schc.reassembly import FragmentReceiver, ReassemblyManager


def _deliver(payload, tile_size, window_size, drop_once=()):
    """Run a full ACK-on-Error exchange; return the receiver.

    ``drop_once`` is a set of global tile indices dropped on first transmission.
    """
    sender = FragmentSender(payload, rule_id=20, tile_size=tile_size, window_size=window_size)
    receiver = FragmentReceiver(window_size)
    dropped: set[int] = set(drop_once)

    for abs_w in range(sender.window_count):
        window_frags = sender.fragments_in_window(abs_w)
        result = None
        for pos, frag in enumerate(window_frags):
            gidx = abs_w * window_size + pos
            if gidx in dropped:
                dropped.discard(gidx)  # only dropped once
                continue
            result = receiver.receive(frag)

        # Retransmit until this window is satisfied (bounded loop).
        for _ in range(10):
            if receiver.done or result is None or result.ack is None:
                break
            missing = sender.retransmit(abs_w, result.ack.bitmap)
            if not missing:
                break
            for frag in missing:
                result = receiver.receive(frag)
    return receiver


def test_clean_multi_window_reassembly() -> None:
    payload = bytes(range(7))
    receiver = _deliver(payload, tile_size=1, window_size=3)
    assert receiver.done
    assert receiver.reassembled == payload


def test_single_fragment_reassembly() -> None:
    payload = b"hello"
    receiver = _deliver(payload, tile_size=64, window_size=3)
    assert receiver.done
    assert receiver.reassembled == payload


def test_reassembly_with_dropped_regular_fragment() -> None:
    payload = bytes(range(7))
    # Drop window 0, position 1 (global index 1) on first send.
    receiver = _deliver(payload, tile_size=1, window_size=3, drop_once={1})
    assert receiver.done
    assert receiver.reassembled == payload


def test_reassembly_with_dropped_final_window_fragment() -> None:
    payload = bytes(range(8))  # 8 tiles, window_size 3 -> windows 0,1,2(2 tiles)
    # Drop a tile in the final window (global index 6 = window 2, pos 0).
    receiver = _deliver(payload, tile_size=1, window_size=3, drop_once={6})
    assert receiver.done
    assert receiver.reassembled == payload


def test_larger_payload_round_trip() -> None:
    payload = bytes((i * 7) % 256 for i in range(50))
    receiver = _deliver(payload, tile_size=4, window_size=5)
    assert receiver.done
    assert receiver.reassembled == payload


def test_mic_failure_does_not_complete() -> None:
    payload = b"abcdef"
    sender = FragmentSender(payload, rule_id=20, tile_size=2, window_size=3)
    receiver = FragmentReceiver(window_size=3)
    frags = sender.all_fragments()
    # Corrupt the payload of the first fragment before delivery.
    frags[0] = Fragment(
        frags[0].rule_id, frags[0].window, frags[0].fcn, b"ZZ", frags[0].mic
    )
    result = None
    for frag in frags:
        result = receiver.receive(frag)
    assert receiver.done is False
    assert result is not None and result.mic_ok is False


def test_manager_completes_and_clears_context() -> None:
    payload = bytes(range(4))
    sender = FragmentSender(payload, rule_id=20, tile_size=1, window_size=3)
    mgr = ReassemblyManager(window_size=3)
    result = None
    for frag in sender.all_fragments():
        result = mgr.receive("nodeA", frag)
    assert result is not None and result.reassembled == payload
    assert len(mgr) == 0  # cleared on completion


def test_manager_evicts_oldest() -> None:
    mgr = ReassemblyManager(window_size=3, max_contexts=2)
    # Start three partial reassemblies; the first should be evicted.
    f = Fragment(rule_id=20, window=0, fcn=2, payload=b"x")
    mgr.receive("a", f)
    mgr.receive("b", f)
    mgr.receive("c", f)
    assert len(mgr) == 2


def test_manager_drop() -> None:
    mgr = ReassemblyManager(window_size=3)
    mgr.receive("a", Fragment(rule_id=20, window=0, fcn=2, payload=b"x"))
    mgr.drop("a")
    assert len(mgr) == 0


def test_fcn_out_of_range_ignored() -> None:
    """Fragments with FCN >= window_size are silently discarded (no negative indices)."""
    receiver = FragmentReceiver(window_size=3)
    # Valid FCN values for window_size=3 are 0, 1, 2 (plus ALL_1 sentinel).
    # FCN=10 would cause pos = 3 - 1 - 10 = -8 without validation.
    bad_frag = Fragment(rule_id=20, window=0, fcn=10, payload=b"malicious")
    result = receiver.receive(bad_frag)
    # Fragment should be ignored: no ACK, no reassembly, tiles dict stays empty.
    assert result.ack is None
    assert result.reassembled is None
    assert len(receiver._tiles) == 0


def test_stale_retransmission_does_not_corrupt_later_window() -> None:
    """A delayed fragment from window 0 must not overwrite window 2 data.

    SCHC ACK-on-Error uses a 1-bit W field that alternates 0/1. Windows 0, 2, 4...
    all have W=0. If a delayed retransmission from window 0 arrives when we're at
    window 2, it must be rejected rather than stored at window 2's position.

    Failure scenario (before fix):
    1. Receiver completes windows 0 and 1, _current_window=2
    2. Window 2's first tile arrives (index 6)
    3. Delayed duplicate from window 0 position 0 (W=0, FCN=2) arrives
    4. Bug: fragment mapped to window 2, overwrites index 6 with stale data
    5. Reassembly produces corrupted output
    """
    window_size = 3
    receiver = FragmentReceiver(window_size)

    # Complete window 0 (tiles 0, 1, 2) - all with W=0
    for fcn in [2, 1, 0]:  # FCN counts down
        frag = Fragment(rule_id=20, window=0, fcn=fcn, payload=bytes([fcn]))
        receiver.receive(frag)
    assert 0 in receiver._completed_windows

    # Complete window 1 (tiles 3, 4, 5) - all with W=1
    for fcn in [2, 1, 0]:
        frag = Fragment(rule_id=20, window=1, fcn=fcn, payload=bytes([10 + fcn]))
        receiver.receive(frag)
    assert 1 in receiver._completed_windows
    assert receiver._current_window == 2

    # Receive first tile of window 2 (index 6, FCN=2, W=0)
    window2_tile0 = Fragment(rule_id=20, window=0, fcn=2, payload=b"\x20")
    receiver.receive(window2_tile0)
    assert receiver._tiles.get(6) == b"\x20"

    # Now a delayed retransmission from window 0, position 0 (FCN=2, W=0)
    # arrives. It has different payload than window 2's tile at same position.
    stale_frag = Fragment(rule_id=20, window=0, fcn=2, payload=b"\x02")
    result = receiver.receive(stale_frag)

    # The stale fragment must be rejected:
    # - No ACK generated (we already ACKed window 0)
    # - Window 2 tile at index 6 must NOT be overwritten
    # - _current_window must not regress
    assert result.ack is None
    assert receiver._tiles.get(6) == b"\x20", "Window 2 data was corrupted by stale fragment"
    assert receiver._current_window == 2, "_current_window regressed"
