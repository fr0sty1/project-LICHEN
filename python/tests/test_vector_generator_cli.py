# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Safety checks for the in-place shared-vector generator CLI."""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO_ROOT / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

import atomic_json  # noqa: E402
import generate_dao_origin_signature as dao_generator  # noqa: E402

GENERATOR = REPO_ROOT / "test" / "vectors" / "generate.py"
SCHC_COMPRESSION = REPO_ROOT / "test" / "vectors" / "schc_compression.json"
PACKETS_TIMING_GENERATOR = REPO_ROOT / "test" / "vectors" / "generate_packets_timing.py"
AUTHENTICATED_DIO_GENERATOR = REPO_ROOT / "test" / "vectors" / "generate_authenticated_schc_dio.py"
AUTHENTICATED_DIO_OUTPUT = REPO_ROOT / "test" / "vectors" / "authenticated_schc_dio.json"
PACKETS_OUTPUTS = (
    REPO_ROOT / "test" / "vectors" / "packets-formats.json",
    REPO_ROOT / "test" / "vectors" / "packets-timing.json",
)


def test_incomplete_schc_builder_is_not_an_overwrite_target() -> None:
    before = SCHC_COMPRESSION.read_bytes()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "python" / "src")

    result = subprocess.run(
        [sys.executable, str(GENERATOR), SCHC_COMPRESSION.name],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unknown vector file" in result.stderr
    assert SCHC_COMPRESSION.read_bytes() == before


def test_shared_generator_fnv_oracle_is_literal_and_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(GENERATOR.parent))
    generator = runpy.run_path(str(GENERATOR), run_name="shared_vector_oracle_check")
    oracle = generator["_oracle_hash_32"]

    assert oracle(b"") == 0x811C9DC5
    assert oracle(b"\x00") == 0x050C5D1F
    assert oracle(bytes.fromhex("0011223344556677")) == 0xC0E31BBD


def test_packets_timing_check_is_byte_exact_and_read_only() -> None:
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in PACKETS_OUTPUTS}
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "python" / "src")

    result = subprocess.run(
        [sys.executable, str(PACKETS_TIMING_GENERATOR), "--check"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in PACKETS_OUTPUTS
    } == before


def test_packets_timing_generator_rejects_unknown_arguments_without_writing() -> None:
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in PACKETS_OUTPUTS}
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "python" / "src")

    result = subprocess.run(
        [sys.executable, str(PACKETS_TIMING_GENERATOR), "--unknown"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in PACKETS_OUTPUTS}
    assert after == before


def test_packets_timing_check_reports_missing_outputs_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    generator = runpy.run_path(str(PACKETS_TIMING_GENERATOR), run_name="packets_timing_check")
    monkeypatch.setitem(generator["main"].__globals__, "VECTORS_DIR", tmp_path)

    result = generator["main"](["--check"])

    assert result == 1
    assert "packets-formats.json" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_authenticated_dio_check_is_byte_exact_and_read_only() -> None:
    before = (
        AUTHENTICATED_DIO_OUTPUT.read_bytes(),
        AUTHENTICATED_DIO_OUTPUT.stat().st_mtime_ns,
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "python" / "src")

    result = subprocess.run(
        [sys.executable, str(AUTHENTICATED_DIO_GENERATOR), "--check"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (
        AUTHENTICATED_DIO_OUTPUT.read_bytes(),
        AUTHENTICATED_DIO_OUTPUT.stat().st_mtime_ns,
    ) == before


def test_authenticated_dio_generator_rejects_unknown_arguments_without_writing() -> None:
    before = (
        AUTHENTICATED_DIO_OUTPUT.read_bytes(),
        AUTHENTICATED_DIO_OUTPUT.stat().st_mtime_ns,
    )
    result = subprocess.run(
        [sys.executable, str(AUTHENTICATED_DIO_GENERATOR), "--unknown"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert (
        AUTHENTICATED_DIO_OUTPUT.read_bytes(),
        AUTHENTICATED_DIO_OUTPUT.stat().st_mtime_ns,
    ) == before


@pytest.mark.parametrize(
    "mutation",
    ["formatting", "key_order", "duplicate_key", "missing", "oversized"],
)
def test_dao_check_rejects_every_noncanonical_or_unsafe_artifact_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    document = dao_generator.generate()
    canonical = atomic_json.json_bytes(document)
    destination = tmp_path / "dao_origin_signature.json"
    monkeypatch.setattr(dao_generator, "OUTPUT", destination)

    if mutation == "formatting":
        artifact = (json.dumps(document, indent=4, allow_nan=False) + "\n").encode()
    elif mutation == "key_order":
        artifact = (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    elif mutation == "duplicate_key":
        needle = b'  "format_version": 2,\n'
        assert needle in canonical
        artifact = canonical.replace(needle, needle + needle, 1)
    elif mutation == "oversized":
        artifact = canonical
        monkeypatch.setattr(atomic_json, "_MAX_VECTOR_CHECK_BYTES", len(canonical) - 1)
    else:
        artifact = None

    if artifact is not None:
        destination.write_bytes(artifact)
        before = (destination.read_bytes(), destination.stat().st_mtime_ns)
        if mutation != "oversized":
            assert json.loads(artifact) == document
    else:
        before = None

    assert dao_generator.main(["--check"]) == 1
    assert "not deterministically generated" in capsys.readouterr().err
    if before is None:
        assert not destination.exists()
    else:
        assert (destination.read_bytes(), destination.stat().st_mtime_ns) == before


def test_dao_check_accepts_canonical_bytes_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "dao_origin_signature.json"
    destination.write_bytes(atomic_json.json_bytes(dao_generator.generate()))
    monkeypatch.setattr(dao_generator, "OUTPUT", destination)
    before = (destination.read_bytes(), destination.stat().st_mtime_ns)

    assert dao_generator.main(["--check"]) == 0
    assert (destination.read_bytes(), destination.stat().st_mtime_ns) == before
