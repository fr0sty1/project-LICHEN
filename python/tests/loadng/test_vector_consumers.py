# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume committed LOADng JSON vectors through the Python codecs.

``test/vectors/loadng.json`` is RFC 1982 sequence freshness.
``test/vectors/loadng_messages.json`` is RREQ/RREP/RERR wire encoding.
"""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.loadng.cache import _is_seq_fresher
from lichen.loadng.messages import RERR, RREP, RREQ

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> dict:
    doc = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    assert doc["format_version"] == 2
    return doc


def _seq_cases():
    return [(v["name"], v) for v in _load("loadng.json")["vectors"]]


def _message_cases():
    return [(v["name"], v) for v in _load("loadng_messages.json")["vectors"]]


@pytest.mark.parametrize("name,vector", _seq_cases())
def test_loadng_seq_freshness_vector(name: str, vector: dict) -> None:
    got = _is_seq_fresher(vector["a"], vector["b"])
    assert got is vector["b_fresher"], f"{name}: {got} != {vector['b_fresher']}"


@pytest.mark.parametrize("name,vector", _message_cases())
def test_loadng_message_vector(name: str, vector: dict) -> None:
    encoded = bytes.fromhex(vector["encoded"])
    fields = vector["fields"]
    msg_type = vector["type"]

    if msg_type == "rreq":
        parsed = RREQ.from_bytes(encoded)
        assert parsed.flags == fields["flags"], f"{name}: flags"
        assert parsed.hop_limit == fields["hop_limit"], f"{name}: hop_limit"
        assert parsed.seq_num == fields["seq_num"], f"{name}: seq_num"
        assert str(parsed.originator) == fields["originator"], f"{name}: originator"
        assert str(parsed.destination) == fields["destination"], f"{name}: destination"
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        assert parsed.signature == sig, f"{name}: signature"
        rebuilt = RREQ(
            originator=IPv6Address(fields["originator"]),
            destination=IPv6Address(fields["destination"]),
            seq_num=fields["seq_num"],
            hop_limit=fields["hop_limit"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"
        return

    if msg_type == "rrep":
        parsed = RREP.from_bytes(encoded)
        assert parsed.flags == fields["flags"], f"{name}: flags"
        assert parsed.hop_count == fields["hop_count"], f"{name}: hop_count"
        assert parsed.seq_num == fields["seq_num"], f"{name}: seq_num"
        assert str(parsed.originator) == fields["originator"], f"{name}: originator"
        assert str(parsed.destination) == fields["destination"], f"{name}: destination"
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        assert parsed.signature == sig, f"{name}: signature"
        rebuilt = RREP(
            originator=IPv6Address(fields["originator"]),
            destination=IPv6Address(fields["destination"]),
            seq_num=fields["seq_num"],
            hop_count=fields["hop_count"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"
        return

    if msg_type == "rerr":
        parsed = RERR.from_bytes(encoded)
        assert parsed.flags == fields["flags"], f"{name}: flags"
        assert parsed.error_code == fields["error_code"], f"{name}: error_code"
        assert str(parsed.unreachable) == fields["unreachable"], f"{name}: unreachable"
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        assert parsed.signature == sig, f"{name}: signature"
        rebuilt = RERR(
            unreachable=IPv6Address(fields["unreachable"]),
            error_code=fields["error_code"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"
        return

    raise AssertionError(f"{name}: unknown type {msg_type}")


def test_loadng_vector_files_cover_required_kinds() -> None:
    seq_names = {name for name, _ in _seq_cases()}
    assert "half_to_zero_wrap" in seq_names
    assert "wrap_forward_FFFF_to_0000" in seq_names

    kinds = {vector["type"] for _, vector in _message_cases()}
    assert kinds == {"rreq", "rrep", "rerr"}
