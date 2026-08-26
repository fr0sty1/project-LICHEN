# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: LR-FHSS capability exchange vs shared vectors.

Drives ``lichen.link.lr_fhss`` (spec 02-physical-link.md §3.7) against
``test/vectors/lr_fhss_capability.json``: flag codec round-trips and
PHY-mode negotiation for gateway uplink, downlink symmetry, and
peer-to-peer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.lr_fhss import (
    AnnounceLrFhssFlags,
    DioLrFhssFlags,
    PhyMode,
    downlink_mode_for_node,
    negotiate_uplink_mode,
    peer_to_peer_mode,
)

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "lr_fhss_capability.json"


def _load_vectors() -> list[dict]:
    with open(_VECTORS_PATH) as f:
        return json.load(f)["vectors"]


_PHY_BY_NAME = {"lora": PhyMode.LORA, "lr_fhss": PhyMode.LR_FHSS}


class TestDioFlagCodec:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "dio_flags" in v],
        ids=lambda v: v["name"],
    )
    def test_dio_flags_roundtrip(self, case: dict) -> None:
        flags = DioLrFhssFlags.decode(case["dio_flags"])
        assert flags.lr_fhss_supported is case["lr_fhss_supported"]
        assert flags.encode() == case["dio_flags"]


class TestAnnounceFlagCodec:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "announce_app_data_first_byte" in v],
        ids=lambda v: v["name"],
    )
    def test_announce_flags_roundtrip(self, case: dict) -> None:
        byte = case["announce_app_data_first_byte"]
        flags = AnnounceLrFhssFlags.decode(byte)
        assert flags.lr_fhss_capable is case["lr_fhss_capable"]
        assert flags.encode() == byte


class TestUplinkNegotiation:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "node_capable" in v and "expected_phy_mode" in v],
        ids=lambda v: v["name"],
    )
    def test_uplink_mode(self, case: dict) -> None:
        mode = negotiate_uplink_mode(
            node_capable=case["node_capable"],
            gateway_supported=case["gateway_supported"],
            node_prefers_lr_fhss=case.get("node_prefers_lr_fhss", False),
        )
        assert mode is _PHY_BY_NAME[case["expected_phy_mode"]], case["description"]


class TestDownlinkSymmetry:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "last_uplink_mode" in v],
        ids=lambda v: v["name"],
    )
    def test_downlink_matches_uplink(self, case: dict) -> None:
        uplink = _PHY_BY_NAME[case["last_uplink_mode"]]
        assert downlink_mode_for_node(uplink) is uplink
        assert downlink_mode_for_node(uplink).name.lower() == case["expected_downlink_mode"]


class TestPeerToPeer:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "a_capable" in v],
        ids=lambda v: v["name"],
    )
    def test_p2p_mode(self, case: dict) -> None:
        mode = peer_to_peer_mode(
            a_capable=case["a_capable"],
            b_capable=case["b_capable"],
            negotiated=case.get("negotiated", False),
        )
        assert mode is _PHY_BY_NAME[case["expected_phy_mode"]], case["description"]
