# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validation tests for presence CBOR encoding against shared vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.presence import Presence, PresenceCache


def _load_vectors() -> list[dict]:
    """Load presence_cbor.json test vectors."""
    vectors_path = Path(__file__).parents[3] / "test" / "vectors" / "presence_cbor.json"
    with open(vectors_path) as f:
        data = json.load(f)
    return data["vectors"]


@pytest.fixture(scope="module")
def vectors() -> list[dict]:
    return _load_vectors()


def _oracle(vector: dict) -> Presence | PresenceCache:
    if "cache" in vector["name"]:
        return PresenceCache.from_mapping(vector["input"])
    return Presence.from_mapping(vector["input"])


class TestPresenceEncoding:
    """Test that the presence oracle matches the shared test vectors."""

    def test_minimal_available(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "minimal_available")
        assert Presence.from_mapping(v["input"]).to_cbor().hex() == v["encoded_hex"]

    def test_all_fields(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "all_fields")
        assert Presence.from_mapping(v["input"]).to_cbor().hex() == v["encoded_hex"]

    def test_all_presence_vectors(self, vectors: list[dict]) -> None:
        """Validate all non-cache presence vectors through the oracle."""
        for v in vectors:
            if "cache" not in v["name"]:
                encoded = Presence.from_mapping(v["input"]).to_cbor()
                assert encoded.hex() == v["encoded_hex"], f"Vector '{v['name']}' mismatch"


class TestPresenceCacheEncoding:
    """Test that the cache oracle matches cache vectors."""

    def test_cache_empty(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "cache_empty")
        assert PresenceCache.from_mapping(v["input"]).to_cbor().hex() == v["encoded_hex"]

    def test_cache_single_node(self, vectors: list[dict]) -> None:
        v = next(x for x in vectors if x["name"] == "cache_single_node")
        assert PresenceCache.from_mapping(v["input"]).to_cbor().hex() == v["encoded_hex"]

    def test_all_cache_vectors(self, vectors: list[dict]) -> None:
        """Validate all cache vectors through the oracle."""
        for v in vectors:
            if "cache" in v["name"]:
                encoded = PresenceCache.from_mapping(v["input"]).to_cbor()
                assert encoded.hex() == v["encoded_hex"], f"Vector '{v['name']}' mismatch"


class TestPresenceDecoding:
    """Test that oracle decoding produces expected maps."""

    def test_decode_all_vectors(self, vectors: list[dict]) -> None:
        """Decode each vector and verify round-trip against the input map."""
        for v in vectors:
            expected_bytes = bytes.fromhex(v["encoded_hex"])
            decoded = _oracle(v).__class__.from_cbor(expected_bytes)
            assert decoded.to_map() == v["input"], f"Vector '{v['name']}' decode mismatch"
