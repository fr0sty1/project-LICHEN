# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: position privacy auth vs shared vectors.

Drives ``lichen.coap.position_privacy`` against every vector in
``test/vectors/position_privacy_auth.json`` (spec 12-apps.md 18.1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.coap.position_privacy import PositionPrivacyPolicy

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "position_privacy_auth.json"


def _load_vectors() -> list[dict]:
    return json.loads(_VECTORS_PATH.read_text())["vectors"]


def _policy_for(case: dict) -> PositionPrivacyPolicy:
    return PositionPrivacyPolicy(
        case["mode"],
        member_groups={case["group_id"]} if case.get("group_id") else None,
        allowed_peer_iid=case.get("allowed_peer_iid"),
    )


class TestAuthorizationMatrix:
    @pytest.mark.parametrize(
        "case",
        [v for v in _load_vectors() if "request" in v and "initial_mode" not in v],
        ids=lambda v: v["name"],
    )
    def test_read_authorization(self, case: dict) -> None:
        req = case["request"]
        accept, code = _policy_for(case).check_read(
            oscore=req.get("oscore", False),
            oscore_context=req.get("oscore_context"),
            requester_iid=req.get("requester_iid"),
        )
        expected = case["expected"]
        assert accept is expected["accept"], case["description"]
        assert code == expected["response_code"], case["name"]


class TestModeSwitchImmediate:
    def test_public_to_private_blocks_subsequent(self) -> None:
        case = next(v for v in _load_vectors() if v["name"] == "mode_switch_immediate")
        policy = PositionPrivacyPolicy(case["initial_mode"])
        assert policy.check_read()[0] is True
        # action: PUT /config/position/mode = private
        policy.mode = "private"
        sub = case["subsequent_request"]
        accept, code = policy.check_read(oscore=sub.get("oscore", False))
        assert accept is case["expected"]["accept"]
        assert code == case["expected"]["response_code"]


class TestBeaconFollowsMode:
    @pytest.mark.parametrize(
        "entry",
        next(v for v in _load_vectors() if v["name"] == "position_beacon_follows_mode")["modes"],
        ids=lambda e: e["mode"],
    )
    def test_beacon_inclusion(self, entry: dict) -> None:
        policy = PositionPrivacyPolicy(entry["mode"])
        assert policy.include_position_in_beacon() is entry["position_in_beacon"]
