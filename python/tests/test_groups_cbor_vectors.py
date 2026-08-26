# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Spec 18.8 group CBOR field sets vs shared vectors."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"

GROUP_FIELDS = {
    "id",
    "name",
    "mcast",
    "owner",
    "admins",
    "members",
    "key_id",
    "created",
    "key_epoch",
}
LIST_ITEM_FIELDS = {"id", "name", "members"}


def test_groups_cbor_vectors_match_spec_keys() -> None:
    document = json.loads((VECTORS / "groups_cbor.json").read_text(encoding="utf-8"))
    by_name = {case["name"]: case for case in document["vectors"]}
    group = by_name["group_document"]["payload"]
    assert set(group) == GROUP_FIELDS
    assert group["id"] == "team-alpha"
    assert group["key_epoch"] == 1
    assert group["created"] == 1716742800
    assert len(group["members"]) == 3
    listing = by_name["groups_list"]["payload"]
    assert set(listing) == {"groups"}
    for item in listing["groups"]:
        assert set(item) == LIST_ITEM_FIELDS
        assert type(item["members"]) is int
