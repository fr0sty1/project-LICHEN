# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for spinbead claim coordination. No LLM, no live bd writes."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import spinbead  # noqa: E402


def _proc(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["bd"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_claim_accepted_spinbead_actor() -> None:
    payload = json.dumps({"id": "x", "status": "in_progress", "assignee": "spinbead"})
    assert spinbead.claim_accepted(_proc(0, payload), actor="spinbead") is True


def test_claim_rejected_nonzero_exit() -> None:
    assert spinbead.claim_accepted(
        _proc(1, "", "Error claiming x: issue already claimed by Mark Atwood"),
        actor="spinbead",
    ) is False


def test_claim_rejected_other_assignee() -> None:
    payload = json.dumps({"id": "x", "status": "in_progress", "assignee": "Mark Atwood"})
    assert spinbead.claim_accepted(_proc(0, payload), actor="spinbead") is False


def test_claim_rejected_not_in_progress() -> None:
    payload = json.dumps({"id": "x", "status": "open", "assignee": "spinbead"})
    assert spinbead.claim_accepted(_proc(0, payload), actor="spinbead") is False


def test_claim_accepted_list_payload() -> None:
    payload = json.dumps([{"id": "x", "status": "in_progress", "assignee": "spinbead"}])
    assert spinbead.claim_accepted(_proc(0, payload), actor="spinbead") is True


def test_beads_from_ready_json_tags_epics() -> None:
    beads = spinbead.beads_from_ready_json(
        [
            {"id": "a", "priority": 1, "title": "epic work", "issue_type": "epic"},
            {"id": "b", "priority": 1, "title": "real bug", "issue_type": "bug"},
        ]
    )
    assert [b.id for b in beads] == ["a", "b"]
    assert spinbead.is_actionable(beads[0]) is False
    assert spinbead.is_actionable(beads[1]) is True


def test_parse_beads_human_format() -> None:
    text = "○ project-LICHEN-worker6-9un7 ● P1 [bug] Duplicate select_channel"
    beads = spinbead.parse_beads(text)
    assert len(beads) == 1
    assert beads[0].id == "project-LICHEN-worker6-9un7"
    assert beads[0].priority == 1
    assert "bug" in beads[0].tags


def test_release_if_clean_unclaims_only_without_edits(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(spinbead, "unclaim_bead", lambda i, r: calls.append((i, r)))
    spinbead.release_if_clean("id-1", 0, "no edits")
    spinbead.release_if_clean("id-2", 3, "close failed")
    assert calls == [("id-1", "no edits")]
