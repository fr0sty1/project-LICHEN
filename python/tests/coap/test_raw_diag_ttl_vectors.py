# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: raw-diag TTL enforcement vs shared vectors.

Drives ``lichen.coap.raw_diag.RawDiagTTL`` against every vector in
``test/vectors/raw_diag_ttl.json`` (spec/11-lci.md 17.5.4).
"""

from __future__ import annotations

import json
from pathlib import Path

from lichen.coap.raw_diag import MAX_TTL_S, RawDiagTTL

_VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "raw_diag_ttl.json"


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _load_vectors() -> list[dict]:
    return json.loads(_VECTORS_PATH.read_text())["vectors"]


def _by_name(name: str) -> dict:
    return next(v for v in _load_vectors() if v["name"] == name)


class TestDefaults:
    def test_ttl_default_max(self) -> None:
        case = _by_name("ttl_default_max")
        assert RawDiagTTL().max_ttl_s == case["expected"]["max_ttl_s"] == 300
        assert MAX_TTL_S == 300

    def test_disabled_by_default(self) -> None:
        case = _by_name("disabled_by_default")
        diag = RawDiagTTL()
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]
        assert diag.max_ttl_s == case["expected"]["max_ttl_s"]


class TestArming:
    def test_within_max_accepted(self) -> None:
        case = _by_name("ttl_request_within_max")
        clock = FakeClock()
        diag = RawDiagTTL(clock=clock)
        accepted, code = diag.arm(**case["request"])
        assert (accepted, code) == (True, case["expected"]["response_code"])
        assert diag.remaining_s() == case["expected"]["accepted_ttl_s"]

    def test_exceeds_max_clamped(self) -> None:
        case = _by_name("ttl_request_exceeds_max_clamped")
        diag = RawDiagTTL(clock=FakeClock())
        accepted, code = diag.arm(**case["request"])
        assert (accepted, code) == (True, case["expected"]["response_code"])
        assert diag.remaining_s() == case["expected"]["accepted_ttl_s"]

    def test_zero_disables_immediately(self) -> None:
        case = _by_name("ttl_zero_disables_immediately")
        diag = RawDiagTTL(clock=FakeClock())
        accepted, _ = diag.arm(**case["request"])
        assert accepted is True
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]

    def test_negative_rejected(self) -> None:
        case = _by_name("ttl_negative_rejected")
        diag = RawDiagTTL(clock=FakeClock())
        accepted, code = diag.arm(**case["request"])
        assert (accepted, code) == (False, case["expected"]["response_code"])

    def test_missing_ttl_rejected_when_enabling(self) -> None:
        case = _by_name("ttl_required_for_enable")
        diag = RawDiagTTL(clock=FakeClock())
        request = case["request"]
        accepted, code = diag.arm(enabled=request["enabled"], ttl_s=None)
        assert (accepted, code) == (False, case["expected"]["response_code"])


class TestCountdown:
    def test_auto_disable_at_expiry(self) -> None:
        case = _by_name("ttl_countdown_auto_disable")
        clock = FakeClock()
        diag = RawDiagTTL(clock=clock)
        diag.arm(**case["request"])
        clock.t += case["elapsed_seconds"]
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]

    def test_remaining_decrements(self) -> None:
        case = _by_name("ttl_remaining_decrements")
        clock = FakeClock()
        diag = RawDiagTTL(clock=clock)
        diag.arm(**case["request"])
        clock.t += case["elapsed_seconds"]
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]

    def test_rearm_resets_countdown(self) -> None:
        case = _by_name("ttl_rearm_resets")
        clock = FakeClock()
        diag = RawDiagTTL(clock=clock)
        diag.arm(**case["initial"])
        clock.t += case["elapsed_seconds"]
        diag.arm(**case["rearm"])
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]


class TestExplicitDisable:
    def test_disable_overrides_remaining(self) -> None:
        case = _by_name("ttl_explicit_disable")
        clock = FakeClock()
        diag = RawDiagTTL(clock=clock)
        diag.arm(**case["initial"])
        clock.t += case["elapsed_seconds"]
        diag.arm(enabled=False)
        assert diag.enabled is case["expected"]["enabled"]
        assert diag.remaining_s() == case["expected"]["remaining_s"]
