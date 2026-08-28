# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Regression tests for the C tx_queue vector generator's JSON loader.

The generator that produces ``lichen_generated_tx_queue_vectors.h`` must
reject duplicate JSON object keys (last-key-wins would desynchronize the
C consumer from stricter cross-implementation parsers) and non-finite
JSON numbers (NaN/Infinity literals and overflow to inf).
"""

from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).parents[3]
_GEN_VECTORS_PATH = _REPO_ROOT / "lichen" / "tests" / "tx_queue" / "gen_vectors.py"
_VECTORS_DIR = _REPO_ROOT / "test" / "vectors"

CANONICAL_VECTORS = (
    "tx_queue_bounded.json",
    "tx_queue_expiry.json",
    "tx_queue_priority.json",
    "tx_queue_implementation.json",
)


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("tx_queue_gen_vectors", _GEN_VECTORS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    return _load_generator()


def _write(tmp_path: Path, name: str, payload: str) -> Path:
    path = tmp_path / name
    path.write_text(payload, encoding="utf-8")
    return path


class TestDuplicateKeyRejection:
    def test_duplicate_top_level_key_rejected(self, gen: ModuleType, tmp_path: Path) -> None:
        path = _write(tmp_path, "v.json", '{"constants": {"A": 1}, "constants": {"A": 2}}')
        with pytest.raises(ValueError, match="duplicate JSON object key"):
            gen.load(tmp_path, path.name)

    def test_duplicate_nested_key_rejected(self, gen: ModuleType, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "v.json",
            '{"outer": {"a": 1, "b": 2, "a": 3}}',
        )
        with pytest.raises(ValueError, match="duplicate JSON object key"):
            gen.load(tmp_path, path.name)

    def test_last_key_wins_semantics_are_not_silent(self, gen: ModuleType, tmp_path: Path) -> None:
        # Plain json.load silently keeps the last value; the loader must not.
        document = json.loads('{"a": 1, "a": 2}')
        assert document == {"a": 2}
        path = _write(tmp_path, "v.json", '{"a": 1, "a": 2}')
        with pytest.raises(ValueError):
            gen.load(tmp_path, path.name)


class TestNonFiniteRejection:
    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_constants_rejected(
        self, gen: ModuleType, tmp_path: Path, constant: str
    ) -> None:
        path = _write(tmp_path, "v.json", f'{{"value": {constant}}}')
        with pytest.raises(ValueError, match="non-finite"):
            gen.load(tmp_path, path.name)

    def test_overflowing_number_rejected(self, gen: ModuleType, tmp_path: Path) -> None:
        # 1e999 is valid JSON syntax but parses to inf; parse_constant does
        # not see it, so the post-load finite scan must reject it.
        path = _write(tmp_path, "v.json", '{"value": 1e999}')
        with pytest.raises(ValueError, match="non-finite"):
            gen.load(tmp_path, path.name)

    def test_finite_floats_accepted(self, gen: ModuleType, tmp_path: Path) -> None:
        path = _write(tmp_path, "v.json", '{"value": 1.5}')
        assert gen.load(tmp_path, path.name)["value"] == pytest.approx(1.5)


class TestCanonicalVectorsStillLoad:
    @pytest.mark.parametrize("name", CANONICAL_VECTORS)
    def test_canonical_vector_loads_strictly(self, gen: ModuleType, name: str) -> None:
        document = gen.load(_VECTORS_DIR, name)
        assert isinstance(document, dict)

    def test_all_canonical_vectors_have_finite_numbers(self) -> None:
        def walk(value: object) -> None:
            if isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, float):
                assert math.isfinite(value)

        for name in CANONICAL_VECTORS:
            walk(json.loads((_VECTORS_DIR / name).read_text(encoding="utf-8")))
