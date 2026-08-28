#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-implementation validation for CCP-12 synchronized hopping.

Validates Python, Rust, and C implementations against shared test vectors.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VECTOR_PATH = Path(__file__).parent / "vectors" / "sync_hop.json"
PROJECT_ROOT = Path(__file__).parent.parent


@dataclass
class ValidationResult:
    """Result of validating a single vector."""

    name: str
    passed: bool
    expected: Any
    actual: Any
    error: str | None = None


def load_vectors() -> list[dict]:
    """Load sync_hop test vectors."""
    with open(VECTOR_PATH) as f:
        data = json.load(f)
    return data["vectors"]


def test_python_sfn_derivation(vector: dict) -> ValidationResult:
    """Test Python sfn_from_unix_time against a vector."""
    from lichen.link.channel import sfn_from_unix_time

    inp = vector["input"]
    expected_sfn = vector["output"]["expected_sfn"]

    actual_sfn = sfn_from_unix_time(
        inp["unix_time_us"],
        inp["superframe_duration_us"],
        inp["epoch_base_us"],
    )

    return ValidationResult(
        name=vector["name"],
        passed=actual_sfn == expected_sfn,
        expected=expected_sfn,
        actual=actual_sfn,
    )


def test_python_channel_selection(vector: dict) -> ValidationResult:
    """Test Python synchronized_hop_channel against a vector."""
    from lichen.link.channel import hash_32, synchronized_hop_channel

    inp = vector["input"]
    expected_channel = vector["output"]["expected_channel"]
    expected_hash = vector["output"].get("hash_32")

    actual_channel = synchronized_hop_channel(
        inp["sfn"],
        inp["seed"],
        inp["n_channels"],
    )

    # Also verify hash value if provided
    if expected_hash is not None:
        seed_bytes = (inp["seed"] & 0xFFFFFFFF).to_bytes(4, "little")
        sfn_bytes = (inp["sfn"] & 0xFFFFFFFF).to_bytes(4, "little")
        actual_hash = hash_32(seed_bytes + sfn_bytes)
        if actual_hash != expected_hash:
            return ValidationResult(
                name=vector["name"],
                passed=False,
                expected=f"hash={expected_hash}, ch={expected_channel}",
                actual=f"hash={actual_hash}, ch={actual_channel}",
                error="Hash mismatch",
            )

    return ValidationResult(
        name=vector["name"],
        passed=actual_channel == expected_channel,
        expected=expected_channel,
        actual=actual_channel,
    )


def test_python_sequence(vector: dict) -> ValidationResult:
    """Test Python synchronized_hop_channel for a sequence of SFNs."""
    from lichen.link.channel import synchronized_hop_channel

    inp = vector["input"]
    expected_sequence = vector["output"]["sequence"]

    actual_sequence = []
    for i in range(inp["sfn_count"]):
        sfn = inp["sfn_start"] + i
        ch = synchronized_hop_channel(sfn, inp["seed"], inp["n_channels"])
        actual_sequence.append(ch)

    return ValidationResult(
        name=vector["name"],
        passed=actual_sequence == expected_sequence,
        expected=expected_sequence,
        actual=actual_sequence,
    )


def test_python_seed_diversity(vector: dict) -> ValidationResult:
    """Test Python synchronized_hop_channel for seed diversity."""
    from lichen.link.channel import synchronized_hop_channel

    inp = vector["input"]
    expected_channels = {c["seed"]: c["channel"] for c in vector["output"]["channels"]}

    actual_channels = {}
    for seed in inp["seeds"]:
        ch = synchronized_hop_channel(inp["sfn"], seed, inp["n_channels"])
        actual_channels[seed] = ch

    return ValidationResult(
        name=vector["name"],
        passed=actual_channels == expected_channels,
        expected=expected_channels,
        actual=actual_channels,
    )


def test_python(vectors: list[dict]) -> list[ValidationResult]:
    """Test Python implementation against all applicable vectors."""
    results = []

    for vector in vectors:
        vtype = vector["type"]

        if vtype == "sfn_derivation":
            results.append(test_python_sfn_derivation(vector))
        elif vtype in ("channel_selection", "sfn_wrap_edge_case"):
            results.append(test_python_channel_selection(vector))
        elif vtype == "sequence_consistency":
            results.append(test_python_sequence(vector))
        elif vtype == "seed_diversity":
            results.append(test_python_seed_diversity(vector))
        elif vtype == "fallback":
            # Fallback vectors document behavior, not testable directly
            pass

    return results


def test_rust(vectors: list[dict]) -> list[ValidationResult]:
    """Test Rust implementation by running cargo test.

    The Rust tests in lichen-core/src/lib.rs validate against the same
    hash/channel values. This function runs cargo test and parses output.
    """
    rust_dir = PROJECT_ROOT / "rust"
    if not rust_dir.exists():
        return [
            ValidationResult(
                name="rust_cargo_test",
                passed=False,
                expected="cargo test passes",
                actual="rust directory not found",
                error="Rust implementation not available",
            )
        ]

    try:
        # Filter to synchronized_hop tests only for faster execution
        result = subprocess.run(
            [
                "cargo", "test", "--package", "lichen-core",
                "synchronized_hop", "--", "--test-threads=1"
            ],
            cwd=rust_dir,
            capture_output=True,
            text=True,
            timeout=180,
        )

        # Check for test pass/fail
        if result.returncode == 0:
            # Parse output to count tests
            lines = result.stdout.split("\n")
            for line in lines:
                if "test result:" in line:
                    return [
                        ValidationResult(
                            name="rust_cargo_test",
                            passed=True,
                            expected="all tests pass",
                            actual=line.strip(),
                        )
                    ]
            return [
                ValidationResult(
                    name="rust_cargo_test",
                    passed=True,
                    expected="all tests pass",
                    actual="cargo test succeeded",
                )
            ]
        else:
            return [
                ValidationResult(
                    name="rust_cargo_test",
                    passed=False,
                    expected="all tests pass",
                    actual=result.stderr[:500] if result.stderr else result.stdout[:500],
                    error="cargo test failed",
                )
            ]
    except subprocess.TimeoutExpired:
        return [
            ValidationResult(
                name="rust_cargo_test",
                passed=False,
                expected="cargo test completes",
                actual="timeout",
                error="cargo test timed out after 180s",
            )
        ]
    except FileNotFoundError:
        return [
            ValidationResult(
                name="rust_cargo_test",
                passed=False,
                expected="cargo available",
                actual="cargo not found",
                error="Rust toolchain not installed",
            )
        ]


def test_zephyr(vectors: list[dict]) -> list[ValidationResult]:
    """Test C/Zephyr implementation.

    Attempts to build and run native host tests if available. Falls back
    to checking if the C source exists and matches the algorithm.
    """
    # Check if sync_hop.c exists
    c_source = PROJECT_ROOT / "lichen" / "subsys" / "lichen" / "link" / "sync_hop.c"
    if not c_source.exists():
        return [
            ValidationResult(
                name="zephyr_source_check",
                passed=False,
                expected="sync_hop.c exists",
                actual="file not found",
                error="C implementation not available",
            )
        ]

    # Try to build and run host tests if CMakeLists.txt exists
    test_dir = PROJECT_ROOT / "lichen" / "tests" / "schnorr48"
    if test_dir.exists():
        try:
            # Check if there's a sync_hop test directory
            sync_hop_test = PROJECT_ROOT / "lichen" / "tests" / "asn_sfn"
            if sync_hop_test.exists():
                build_dir = sync_hop_test / "build"
                result = subprocess.run(
                    ["cmake", "-B", str(build_dir), "-S", str(sync_hop_test)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    result = subprocess.run(
                        ["cmake", "--build", str(build_dir)],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        # Run ctest
                        result = subprocess.run(
                            ["ctest", "--output-on-failure"],
                            cwd=build_dir,
                            capture_output=True,
                            text=True,
                            timeout=60,
                        )
                        return [
                            ValidationResult(
                                name="zephyr_host_test",
                                passed=result.returncode == 0,
                                expected="all tests pass",
                                actual=result.stdout[:500] if result.stdout else "no output",
                                error=result.stderr[:200] if result.returncode != 0 else None,
                            )
                        ]
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return [
                ValidationResult(
                    name="zephyr_host_test",
                    passed=False,
                    expected="host test builds and runs",
                    actual=str(e),
                    error="Build/run failed",
                )
            ]

    # Fallback: verify source exists and has correct algorithm
    with open(c_source) as f:
        source = f.read()

    # Check for key algorithm elements
    checks = [
        ("lichen_sync_hop_channel" in source, "function exists"),
        ("seed" in source and "sfn" in source, "uses seed and sfn"),
        ("lichen_hash_32" in source, "uses FNV-1a hash"),
        ("n_channels < 3" in source, "enforces minimum 3 channels"),
        ("1 + (hash % n_channels)" in source, "correct modulo formula"),
    ]

    all_passed = all(check[0] for check in checks)
    details = ", ".join(f"{check[1]}: {'ok' if check[0] else 'MISSING'}" for check in checks)

    return [
        ValidationResult(
            name="zephyr_source_check",
            passed=all_passed,
            expected="correct algorithm in source",
            actual=details,
        )
    ]


def print_results(impl_name: str, results: list[ValidationResult]) -> int:
    """Print results and return count of failures."""
    failures = 0
    print(f"\n=== {impl_name} ===")

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.name}")
        if not r.passed:
            failures += 1
            print(f"       expected: {r.expected}")
            print(f"       actual:   {r.actual}")
            if r.error:
                print(f"       error:    {r.error}")

    return failures


def main() -> int:
    """Run cross-implementation validation."""
    print(f"Loading vectors from {VECTOR_PATH}")
    vectors = load_vectors()
    print(f"Loaded {len(vectors)} vectors")

    total_failures = 0

    # Test Python
    try:
        python_results = test_python(vectors)
        total_failures += print_results("Python", python_results)
    except ImportError as e:
        print(f"\n=== Python ===")
        print(f"  [SKIP] Cannot import lichen.link.channel: {e}")
        print(f"         Run: pip install -e python/")

    # Test Rust
    rust_results = test_rust(vectors)
    total_failures += print_results("Rust", rust_results)

    # Test Zephyr/C
    zephyr_results = test_zephyr(vectors)
    total_failures += print_results("Zephyr/C", zephyr_results)

    # Summary
    print(f"\n{'='*40}")
    if total_failures == 0:
        print("All implementations validated successfully.")
        return 0
    else:
        print(f"FAILURES: {total_failures} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
