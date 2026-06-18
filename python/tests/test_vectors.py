"""Validate the Python implementation against the committed cross-language vectors.

These guard against drift between the reference implementation and the JSON
vectors that the Rust/C implementations validate against (test/vectors/, issue
ajr / gate ijj). If a vector changes intentionally, regenerate with
``PYTHONPATH=python/src python3 test/vectors/generate.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.schc.headers import compress_packet, decompress_packet

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def test_vectors_directory_exists() -> None:
    assert VECTORS_DIR.is_dir(), f"missing {VECTORS_DIR}"
    assert (VECTORS_DIR / "schema.json").is_file()


def _schc_cases():
    doc = _load("schc_compression.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _frame_cases():
    doc = _load("link_frame.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _schc_cases())
def test_schc_vector(name: str, vector: dict) -> None:
    packet = bytes.fromhex(vector["packet"])
    compressed = bytes.fromhex(vector["compressed"])
    assert compress_packet(packet) == compressed, f"compress drift: {name}"
    assert decompress_packet(compressed) == packet, f"decompress drift: {name}"
    assert compressed[0] == vector["rule_id"]


@pytest.mark.parametrize("name,vector", _frame_cases())
def test_frame_vector(name: str, vector: dict) -> None:
    f = vector["fields"]
    frame = LichenFrame(
        epoch=f["epoch"],
        seqnum=f["seqnum"],
        dst_addr=bytes.fromhex(f["dst_addr"]),
        payload=bytes.fromhex(f["payload"]),
        mic=bytes.fromhex(f["mic"]),
        addr_mode=AddrMode(f["addr_mode"]),
        mic_length=MicLength(f["mic_length"]),
        signature_present=f["signature_present"],
        encrypted=f["encrypted"],
    )
    encoded = bytes.fromhex(vector["encoded"])
    assert frame.to_bytes() == encoded, f"encode drift: {name}"

    decoded = LichenFrame.from_bytes(encoded)
    assert decoded.epoch == f["epoch"]
    assert decoded.seqnum == f["seqnum"]
    assert decoded.dst_addr == bytes.fromhex(f["dst_addr"])
    assert decoded.payload == bytes.fromhex(f["payload"])
    assert decoded.mic == bytes.fromhex(f["mic"])
    assert int(decoded.addr_mode) == f["addr_mode"]
    assert int(decoded.mic_length) == f["mic_length"]
    assert decoded.signature_present == f["signature_present"]
    assert decoded.encrypted == f["encrypted"]


def test_all_schc_rules_covered() -> None:
    rule_ids = {v["rule_id"] for _, v in _schc_cases()}
    assert {0, 1, 2, 3, 4} <= rule_ids  # every whole-packet rule has a vector
