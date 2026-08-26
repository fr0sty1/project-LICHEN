# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consumers for the previously orphaned CCP sync/hop/desync/rendezvous vectors.

Drives the real lichen Python implementation through every vector case in:

- ``test/vectors/sync_hop.json``        via :mod:`lichen.link.channel`
  (``sfn_from_unix_time``, ``synchronized_hop_channel``, ``select_channel``)
- ``test/vectors/ccp16-hop.json``       via :mod:`lichen.sim.tdma`
  (``synchronized_hop_channel``, spec 02a SelectChannel ``1 + h % max(n, 3)``),
  :func:`lichen.ccp.select_channel` (density gate), and
  :func:`lichen.link.channel.select_channel` (announce-driven rendezvous)
- ``test/vectors/ccp16-desync.json``    via :mod:`lichen.timing.sfn`
  (``sfn_delta``, ``DesyncFSM``) and
  :class:`lichen.link.slot_coordination.MultiRootState`
- ``test/vectors/ccp9_rendezvous.json`` via :func:`lichen.link.channel.select_channel`,
  ``lichen.sim.tdma.synchronized_hop_channel``, :mod:`lichen.l2_payload`, and
  :class:`lichen.announce.messages.AnnounceMessage`
- ``test/vectors/ccp9-rendezvous.json`` (content-overlapping twin; consolidation
  is a flagged human call, so both are consumed) via the same rendezvous and
  TDMA scheduler surfaces.

Known divergences (real behavior asserted; tracked in beads):

- **Two real CCP-12 channel mappings disagree.** ``lichen.link.channel.
  synchronized_hop_channel`` computes ``1 + h % max(n_channels - 1, 1)``
  (avoids CH0), while ``lichen.sim.tdma.synchronized_hop_channel`` computes
  ``1 + h % max(n, 3)`` per the spec 02a pseudocode. On identical inputs they
  return different channels (sfn=0/seed=0/8ch: link=4, sim=6). Each vector
  file pins a different implementation: sync_hop.json matches link, ccp16-hop.json
  matches sim. Both are driven through their matching real surface; the hazard
  is filed in beads.
- ``ccp16-hop.json`` ``hop_sfn0_8ch``/``sfn_wrap`` channels (6, 2) contradict
  sync_hop.json's channels (4, 4) for identical (sfn, seed, n_channels) inputs;
  each file is faithful to a *different* real implementation (see above).
- ``ccp16-desync.json`` ``excessive_clock_drift_desync`` has no enforcement
  surface: no Python code compares measured drift ppm against a guard ppm to
  trigger recovery (UNDRIVABLE, skipped with evidence).
- ``ccp9-rendezvous.json`` ``scheduled_rendezvous`` ``valid_until_sfn`` and
  ``ccp16-hop.json`` ``rendezvous_beacon_announce`` ``next_rendezvous_us``:
  timing-window fields with no code surface (prose policy only).

Undrivable cases (no Python enforcement surface; not fabricated):

- ``excessive_clock_drift_desync`` (see above).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.ccp import select_channel as ccp_select_channel
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.link.channel import (
    GnssHopConfig,
    select_channel,
    sfn_from_unix_time,
)
from lichen.link.channel import (
    hash_32 as link_hash_32,
)
from lichen.link.channel import (
    synchronized_hop_channel as link_synchronized_hop_channel,
)
from lichen.link.slot_coordination import (
    MultiRootState,
    RootCandidate,
    VersionChangeOutcome,
)
from lichen.sim.tdma import TDMAScheduler
from lichen.sim.tdma import synchronized_hop_channel as sim_synchronized_hop_channel
from lichen.time_provider import SimulatedTimeProvider
from lichen.timing.sfn import DesyncFSM, DesyncState, sfn_delta

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load(name: str) -> object:
    return json.loads((VECTORS_DIR / name).read_text())


def _cases(name: str) -> list[tuple[str, dict]]:
    """Load (name, vector) pairs from an envelope or bare-array vector file."""
    doc = _load(name)
    if isinstance(doc, dict):
        assert doc["format_version"] == 2
        return [(v["name"], v) for v in doc["vectors"]]
    return [(v["name"], v) for v in doc]


def _case(filename: str, target: str) -> dict:
    return next(v for _, v in _cases(filename) if v["name"] == target)


SYNC_HOP = "sync_hop.json"
CCP16_HOP = "ccp16-hop.json"
CCP16_DESYNC = "ccp16-desync.json"
CCP9_UNDERSCORE = "ccp9_rendezvous.json"
CCP9_HYPHEN = "ccp9-rendezvous.json"


# ---------------------------------------------------------------------------
# sync_hop.json — GNSS SFN derivation + synchronized hop via lichen.link.channel
# ---------------------------------------------------------------------------


def _sync_hop_of_type(vector_type: str) -> list[tuple[str, dict]]:
    return [(n, v) for n, v in _cases(SYNC_HOP) if v["type"] == vector_type]


@pytest.mark.parametrize("name,vector", _sync_hop_of_type("sfn_derivation"))
def test_sync_hop_sfn_derivation(name: str, vector: dict) -> None:
    inp = vector["input"]
    computed = sfn_from_unix_time(
        inp["unix_time_us"], inp["superframe_duration_us"], inp["epoch_base_us"]
    )
    assert computed == vector["output"]["expected_sfn"], f"sfn drift: {name}"


@pytest.mark.parametrize(
    "name,vector",
    _sync_hop_of_type("channel_selection") + _sync_hop_of_type("sfn_wrap_edge_case"),
)
def test_sync_hop_channel_selection(name: str, vector: dict) -> None:
    inp = vector["input"]
    # The pinned preimage must reconstruct from (seed LE u32 || sfn LE u32).
    preimage = (inp["seed"] & 0xFFFFFFFF).to_bytes(4, "little") + (
        inp["sfn"] & 0xFFFFFFFF
    ).to_bytes(4, "little")
    assert preimage.hex() == vector["output"]["hash_input_hex"], f"preimage drift: {name}"
    assert link_hash_32(preimage) == vector["output"]["hash_32"], f"hash drift: {name}"
    computed = link_synchronized_hop_channel(inp["sfn"], inp["seed"], inp["n_channels"])
    assert computed == vector["output"]["expected_channel"], f"channel drift: {name}"


@pytest.mark.parametrize("name,vector", _sync_hop_of_type("sequence_consistency"))
def test_sync_hop_hopping_sequence(name: str, vector: dict) -> None:
    inp = vector["input"]
    sequence = [
        link_synchronized_hop_channel(sfn, inp["seed"], inp["n_channels"])
        for sfn in range(inp["sfn_start"], inp["sfn_start"] + inp["sfn_count"])
    ]
    assert sequence == vector["output"]["sequence"], f"sequence drift: {name}"
    # Deterministic non-degeneracy claimed by the vector description.
    assert len(set(sequence)) > 1, name


def test_sync_hop_fallback_gnss_unavailable() -> None:
    """GNSS time unavailable must fall through to the hash tier, not fail.

    The vector carries no numeric pin ("fallback_to": "hash_based_ccp16"), so
    the assertions are behavioral: the call succeeds, lands on a data channel
    (never CH0) for a known peer, and is indistinguishable from a call with
    GNSS disabled entirely (same tier reached). An unknown peer still gets the
    CH0 control fallback below it in the chain.
    """
    vector = _case(SYNC_HOP, "fallback_gnss_unavailable")
    assert vector["input"]["gnss_available"] is False
    assert vector["output"]["fallback_to"] == "hash_based_ccp16"
    eui64 = bytes.fromhex(vector["input"]["peer_eui64"])
    gnss_down = GnssHopConfig(enabled=True)
    without_gnss = select_channel(
        peer_eui64=eui64,
        peer_known=True,
        sfn=100,
        epoch=vector["input"]["epoch"],
        n_channels=8,
        gnss_config=gnss_down,
        time_provider=SimulatedTimeProvider(unix_time_us=None),
    )
    gnss_absent = select_channel(peer_eui64=eui64, peer_known=True, sfn=100, epoch=1, n_channels=8)
    assert without_gnss == gnss_absent
    assert 1 <= without_gnss <= 7  # data-channel range [1, n_channels-1], never CH0


def test_sync_hop_cross_seed_diversity() -> None:
    vector = _case(SYNC_HOP, "cross_seed_diversity")
    inp = vector["input"]
    entries = vector["output"]["channels"]
    assert len(entries) == len(inp["seeds"])
    for entry in entries:
        computed = link_synchronized_hop_channel(inp["sfn"], entry["seed"], inp["n_channels"])
        assert computed == entry["channel"], f"seed {entry['seed']} drift"


# ---------------------------------------------------------------------------
# ccp16-hop.json — spec 02a SelectChannel formula via lichen.sim.tdma
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["hop_sfn0_8ch", "hop_sfn1_16ch", "sfn_wrap"],
)
def test_ccp16_hop_sim_select_channel(name: str) -> None:
    vec = _case(CCP16_HOP, name)
    preimage = (vec["seed"] & 0xFFFFFFFF).to_bytes(4, "little") + (
        vec["sfn"] & 0xFFFFFFFF
    ).to_bytes(4, "little")
    assert link_hash_32(preimage) == vec["hash_32"], f"hash drift: {name}"
    computed = sim_synchronized_hop_channel(vec["sfn"], vec["seed"], vec["num_channels"])
    assert computed == vec["expected_channel"], f"channel drift: {name}"


def test_ccp16_hop_density_high_ch0() -> None:
    vec = _case(CCP16_HOP, "density_high_ch0")
    assert vec["density"] == 9
    # ccp.select_channel implements the density gate of the same 02a pseudocode:
    # density > 8 forces CH0 before any hashing (EUI/epoch are irrelevant here).
    ch = ccp_select_channel(eui64=bytes(8), epoch=0, density=vec["density"],
                            n_channels=vec["num_channels"])
    assert ch == vec["expected_channel"] == 0
    # Gate-boundary control: at density == 8 (not > 8) hashing proceeds and the
    # result is a data channel, never the forced CH0 (the two surfaces use
    # different preimages — eui||epoch vs seed||sfn — so values are not shared).
    boundary = ccp_select_channel(eui64=bytes(8), epoch=0, density=8,
                                  n_channels=vec["num_channels"])
    assert 1 <= boundary <= vec["num_channels"]


def test_ccp16_hop_rendezvous_beacon_announce() -> None:
    """Beacon/DIO rendezvous honors the announced rx_channel for known peers."""
    vec = _case(CCP16_HOP, "rendezvous_beacon_announce")
    ch = select_channel(
        peer_known=True, announce_rx_channel=vec["rx_channel"], sfn=vec["sfn"], n_channels=8
    )
    assert ch == vec["expected_channel"]
    # Negative control: the same announced channel is ignored for unknown peers
    # (they fall through to CH0 until the peer is known).
    assert select_channel(
        peer_known=False, announce_rx_channel=vec["rx_channel"], sfn=vec["sfn"], n_channels=8
    ) == 0
    # next_rendezvous_us is prose policy: no scheduling surface consumes it.


def test_ccp12_dual_formula_divergence_documented() -> None:
    """The two real CCP-12 implementations disagree on identical inputs.

    sync_hop.json pins the link-layer mapping (mod n-1); ccp16-hop.json pins
    the simulator/spec mapping (mod n). Neither file is wrong against its own
    implementation, but the reference tree contains both, which is an interop
    hazard filed in beads.
    """
    for sfn in (0, 1, 0xFFFFFFFF):
        link_ch = link_synchronized_hop_channel(sfn, 0, 8)
        sim_ch = sim_synchronized_hop_channel(sfn, 0, 8)
        assert link_ch == 1 + link_hash_32(
            (0).to_bytes(4, "little") + sfn.to_bytes(4, "little")
        ) % 7
        assert sim_ch == 1 + link_hash_32(
            (0).to_bytes(4, "little") + sfn.to_bytes(4, "little")
        ) % 8
        if link_ch != sim_ch:
            break
    else:  # pragma: no cover - divergence is structural, not incidental
        pytest.fail("link and sim CCP-12 formulas unexpectedly agree everywhere")


# ---------------------------------------------------------------------------
# ccp16-desync.json — u32 wrap arithmetic, DesyncFSM, multi-root version conflict
# ---------------------------------------------------------------------------


def test_desync_on_sfn_wrap() -> None:
    vec = _case(CCP16_DESYNC, "desync_on_sfn_wrap")
    assert vec["current_sfn"] == 0 and vec["last_sfn"] == 65535
    # Unsigned 32-bit delta wraps to a huge value, flagging desynchronization.
    assert sfn_delta(vec["current_sfn"], vec["last_sfn"]) == 4294901761
    fsm = DesyncFSM()
    assert fsm.state is DesyncState.SYNCED
    # The wrap with invalid time engages the desync recovery state machine...
    assert fsm.on_sfn_wrap(time_valid=False) is DesyncState.DESYNCED
    # ...whose recovery half re-locks on valid beacons.
    assert fsm.on_beacon(valid=True) is DesyncState.RECOVERING


def test_multi_root_version_conflict_desync() -> None:
    vec = _case(CCP16_DESYNC, "multi_root_version_conflict_desync")
    assert vec["version"] == 0 and vec["alternate_version"] == 1
    root = RootCandidate.from_beacon(bytes.fromhex("0011223344556677"), signature_valid=True)
    state = MultiRootState(current_root=root, current_version=vec["version"])
    state.set_desync_state_version(vec["version"])

    # Negative control: a beacon carrying the SAME version changes nothing.
    same = state.on_version_change(vec["version"], signature_valid=True)
    assert same.outcome is VersionChangeOutcome.NO_CHANGE
    assert state.current_root is root

    # Conflicting version that fails re-verification: fail-closed desync —
    # the current root is discarded and remaining candidates are re-evaluated.
    conflict = state.on_version_change(vec["alternate_version"], signature_valid=False)
    assert conflict.outcome is VersionChangeOutcome.SIG_FAILED_DISCARD
    assert state.current_root is None
    assert conflict.evaluate_candidates is True
    # Fail-closed ordering note: the discard path returns before any state
    # revalidation, so version-tied desync state survives verbatim here.
    assert state.desync_state_version == vec["version"]

    # Accepted conflicting-version path (signature verifies): SFN resets and,
    # per 2a.5.4 step 2, desync state tied to the OLD version is invalidated.
    fresh_root = RootCandidate.from_beacon(
        bytes.fromhex("0011223344556677"), signature_valid=True
    )
    accepted_state = MultiRootState(current_root=fresh_root, current_version=vec["version"])
    accepted_state.set_desync_state_version(vec["version"])
    accepted = accepted_state.on_version_change(vec["alternate_version"], signature_valid=True)
    assert accepted.outcome is VersionChangeOutcome.ACCEPTED
    assert accepted.sfn_reset is True
    assert accepted.new_version == vec["alternate_version"]
    assert accepted_state.desync_state_version is None


def test_desync_recovery_beacon_revalidate_real_fsm() -> None:
    """Real 14.7 FSM: first valid beacon starts RECOVERY, 3 consecutive for SYNCED."""
    vec = _case(CCP16_DESYNC, "desync_recovery_beacon_revalidate")
    assert vec["expected"] == "recovering"
    fsm = DesyncFSM()
    fsm.on_sfn_wrap(time_valid=False)
    assert fsm.state is DesyncState.DESYNCED
    # First valid beacon: state resets into RECOVERING with streak 1.
    state = fsm.on_beacon(valid=True)
    assert state is DesyncState.RECOVERING
    assert fsm.consecutive_valid == 1
    # Verify vector expectation matches implementation.
    assert {"recovering": DesyncState.RECOVERING}[vec["expected"]] is state
    # Second beacon: still recovering. Third consecutive: fully synced/joined.
    assert fsm.on_beacon(valid=True) is DesyncState.RECOVERING
    assert fsm.on_beacon(valid=True) is DesyncState.SYNCED
    # A bad beacon during recovery drops the node back to DESYNCED.
    fsm2 = DesyncFSM()
    fsm2.on_sfn_wrap(time_valid=False)
    fsm2.on_beacon(valid=True)
    assert fsm2.on_beacon(valid=False) is DesyncState.DESYNCED


def test_excessive_clock_drift_desync_unenforced() -> None:
    """UNDRIVABLE: no drift-guard enforcement surface exists.

    The vector's arithmetic (12000 ppm over a 5000 ms superframe = 60 ms
    accumulated error vs a 5000 ppm ≈ 25 ms guard) is plain prose policy:
    no Python module reads a guard_ppm/drift threshold to trigger
    desync_recovery, and no desync_recovery()/epoch_floor function exists.
    Skipped rather than fabricated; filed in beads.
    """
    vec = _case(CCP16_DESYNC, "excessive_clock_drift_desync")
    assert vec["drift_ppm"] > vec["guard_ppm"]  # vector premise holds
    pytest.skip(
        "UNDRIVABLE: excessive_clock_drift_desync has no enforcement surface; "
        "no lichen code compares drift_ppm against guard_ppm or exposes "
        "desync_recovery()/epoch_floor revalidation"
    )


# ---------------------------------------------------------------------------
# ccp9_rendezvous.json — rendezvous priority chain + announce wire roundtrip
# ---------------------------------------------------------------------------


def test_ccp9_announce_rendezvous_channel() -> None:
    vec = _case(CCP9_UNDERSCORE, "announce_rendezvous_channel")
    assert vec["peer_known"] is True and vec["control_fallback"] is False
    ch = select_channel(peer_known=True, announce_rx_channel=vec["rx_channel"], n_channels=8)
    assert ch == vec["expected_channel"]
    assert ch != 0  # control_fallback false: announce tier wins, never CH0


def test_ccp9_initial_unknown_peer_control_ch0() -> None:
    vec = _case(CCP9_UNDERSCORE, "initial_unknown_peer_control_ch0")
    assert vec["peer_known"] is False and vec["control_fallback"] is True
    # Unknown peers land on CH0 even when an announce channel is present:
    # the announce tier requires peer_known.
    ch = select_channel(peer_known=False, announce_rx_channel=3, n_channels=8)
    assert ch == vec["expected_channel"] == 0


def test_ccp9_known_peer_synchronized_hop_preference() -> None:
    """CCP-12 normative sync hop for t=1000 yields the pinned channel 5.

    Driven through the CCP-12-normative surface established by ccp16-hop.json
    (spec 02a formula in lichen.sim.tdma): sfn=t, seed=epoch=0.
    """
    vec = _case(CCP9_UNDERSCORE, "known_peer_synchronized_hop_preference")
    assert vec["uses_sync_hop"] is True
    ch = sim_synchronized_hop_channel(vec["t"], vec["epoch"], vec["n_channels"])
    assert ch == vec["expected_channel"] == 5
    # Negative/reject side: the pure-hash peer rendezvous tier would NOT yield
    # this value at the same inputs (the preference genuinely differs).

    assert select_channel(
        peer_known=True, peer_eui64=bytes.fromhex(vec["eui64_hex"]), sfn=vec["t"], epoch=0,
        n_channels=vec["n_channels"],
    ) != ch


def test_ccp9_announce_channel_parse_roundtrip() -> None:
    """Dispatch 21 + announce wire bytes parse; rx_channel survives roundtrip."""
    vec = _case(CCP9_UNDERSCORE, "announce_channel_parse_roundtrip")
    encoded = bytes.fromhex(vec["encoded"])
    # Byte 1 is the L2 routing dispatch (21), byte 2 the announce type.
    assert encoded[0] == vec["l2_dispatch"] == 21
    assert classify_l2_payload(encoded) is L2PayloadKind.ROUTING
    body = l2_payload_body(encoded)
    msg = AnnounceMessage.from_bytes(body)
    # Wire byte 2 is rx_channel (no flags field in announce format).
    assert msg.rx_channel == vec["expected_channel"] == vec["channel"] == vec["rx_channel_byte"]
    assert msg.seq_num == int.from_bytes(body[3:5], "big")
    # Full encode/decode roundtrip is byte-stable (signature field is present).
    assert AnnounceMessage.from_bytes(msg.to_bytes()) == msg
    assert msg.to_bytes() == body


# ---------------------------------------------------------------------------
# ccp9-rendezvous.json — hyphen twin (shapes differ; consumed separately)
# ---------------------------------------------------------------------------


def test_hyphen_hash_based_peer_rendezvous() -> None:
    """Hash-based rendezvous: channel = 1 + hash_32(eui||epoch_le||sfn_le) % (n-1).

    Real priority-3 surface yields channel 5 at epoch=0.
    """
    vec = _case(CCP9_HYPHEN, "hash_based_peer_rendezvous")
    assert vec["mechanism"] == "hash_based"
    eui64 = bytes.fromhex(vec["peer_eui64"])
    ch = select_channel(peer_known=True, peer_eui64=eui64, sfn=vec["sfn"], epoch=0,
                        n_channels=vec["n_channels"])
    assert ch == vec["expected_channel"] == 5


def test_hyphen_scheduled_rendezvous() -> None:
    """Beacon/DIO-assigned slot is adopted verbatim by the TDMA scheduler.

    valid_until_sfn is prose policy: the scheduler carries no validity window.
    """
    vec = _case(CCP9_HYPHEN, "scheduled_rendezvous")
    assert vec["expected"]["mechanism"] == "scheduled"
    scheduler = TDMAScheduler()
    scheduler.sync_from_beacon(rx_time_us=1_000_000, sfn=vec["sfn"], assigned=5)
    assert scheduler.assigned_slot == vec["assigned_slot"] == 5
    assert scheduler.clock.sfn == vec["sfn"]
    # Negative controls around the assigned window: TX allowed inside the
    # slot start, refused once past it (guard region excluded).
    d, guard_us = scheduler._timing_us()
    slot_start = scheduler.clock.base_time_us + scheduler.assigned_slot * d
    assert scheduler.is_tx_allowed(slot_start) is True
    assert scheduler.is_tx_allowed(slot_start + d - guard_us) is False


def test_hyphen_announce_driven_rendezvous() -> None:
    vec = _case(CCP9_HYPHEN, "announce_driven_rendezvous")
    assert vec["mechanism"] == "announce_driven"
    ch = select_channel(peer_known=True, announce_rx_channel=vec["rx_channel"], n_channels=8)
    assert ch == vec["expected_channel"]


def test_hyphen_fallback_control_channel() -> None:
    vec = _case(CCP9_HYPHEN, "fallback_control_channel")
    assert vec["mechanism"] == "fallback"
    # Empty priority chain resolves to CH0 ...
    assert select_channel(n_channels=8) == vec["expected_channel"] == 0
    # ... and the unsynced scheduler sits on contention slot 0.
    assert TDMAScheduler().assigned_slot == vec["expected_slot"] == 0
    assert TDMAScheduler().state.name == "UNSYNCED"


# ---------------------------------------------------------------------------
# Guard: every vector in each file is accounted for by this module
# ---------------------------------------------------------------------------


class TestAllVectorsAccountedFor:
    EXPECTED_COUNTS = {
        SYNC_HOP: 24,
        CCP16_HOP: 5,
        CCP16_DESYNC: 4,
        CCP9_UNDERSCORE: 4,
        CCP9_HYPHEN: 4,
    }

    @pytest.mark.parametrize("filename", sorted(EXPECTED_COUNTS))
    def test_vector_count_matches_expectation(self, filename: str) -> None:
        cases = _cases(filename)
        assert len(cases) == self.EXPECTED_COUNTS[filename], filename
        assert len({name for name, _ in cases}) == len(cases), f"duplicate names: {filename}"

    def test_ccp16_desync_is_bare_array(self) -> None:
        """Documented schema quirk: ccp16-desync.json uses a bare array root."""
        doc = _load(CCP16_DESYNC)
        assert isinstance(doc, list)

    def test_ccp9_twin_files_are_shape_incompatible(self) -> None:
        """Both twins consumed because their vector shapes differ (human call
        pending on consolidation); neither is deleted."""
        underscore_names = {n for n, _ in _cases(CCP9_UNDERSCORE)}
        hyphen_names = {n for n, _ in _cases(CCP9_HYPHEN)}
        assert underscore_names.isdisjoint(hyphen_names)
