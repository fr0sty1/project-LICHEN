# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validation tests for presence CBOR encoding against shared vectors."""

from __future__ import annotations

import json
from pathlib import Path

import cbor2
import pytest


def _load_vectors() -> list[dict]:
    """Load presence_cbor.json test vectors."""
    vectors_path = Path(__file__).parents[3] / "test" / "vectors" / "presence_cbor.json"
    with open(vectors_path) as f:
        data = json.load(f)
    return data["vectors"]


@pytest.fixture(scope="module")
def vectors() -> list[dict]:
    return _load_vectors()


class TestPresenceEncoding:
    """Test that Python cbor2 encoding matches the shared test vectors."""

    def test_minimal_available(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "minimal_available")
        encoded = cbor2.dumps(v["input"])
        assert encoded.hex() == v["encoded_hex"]

    def test_all_fields(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "all_fields")
        encoded = cbor2.dumps(v["input"])
        assert encoded.hex() == v["encoded_hex"]

    def test_all_presence_vectors(self, vectors: list[dict]) -> None:
        """Validate all non-cache presence vectors."""
        for v in vectors:
            if "cache" not in v["name"]:
                encoded = cbor2.dumps(v["input"])
                assert encoded.hex() == v["encoded_hex"], f"Vector '{v['name']}' mismatch"


class TestPresenceCacheEncoding:
    """Test that Python cbor2 encoding matches cache vectors."""

    def test_cache_empty(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "cache_empty")
        encoded = cbor2.dumps(v["input"])
        assert encoded.hex() == v["encoded_hex"]

    def test_cache_single_node(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "cache_single_node")
        encoded = cbor2.dumps(v["input"])
        assert encoded.hex() == v["encoded_hex"]

    def test_all_cache_vectors(self, vectors: list[dict]) -> None:
        """Validate all cache vectors."""
        for v in vectors:
            if "cache" in v["name"]:
                encoded = cbor2.dumps(v["input"])
                assert encoded.hex() == v["encoded_hex"], f"Vector '{v['name']}' mismatch"


class TestPresenceDecoding:
    """Test that Python cbor2 decoding produces expected dicts."""

    def test_decode_all_vectors(self, vectors: list[dict]) -> None:
        """Decode each vector and verify round-trip."""
        for v in vectors:
            expected_bytes = bytes.fromhex(v["encoded_hex"])
            decoded = cbor2.loads(expected_bytes)
            assert decoded == v["input"], f"Vector '{v['name']}' decode mismatch"
