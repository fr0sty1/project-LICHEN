#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Run the bounded Python/Rust/C SCHC whole-packet parity gate."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def run(command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")

    repo = Path(__file__).resolve().parents[1]
    build_root = args.build_root.resolve()
    if build_root == repo or repo in build_root.parents:
        parser.error("--build-root must be outside the shared repository")
    build_root.mkdir(parents=True, exist_ok=True)
    c_build = build_root / "c"

    run(
        [
            "uv",
            "run",
            "--project",
            "python",
            "pytest",
            "python/tests/test_vectors.py::test_schc_vector",
            "python/tests/test_vectors.py::test_all_schc_rules_covered",
            "python/tests/schc/test_rule1.py",
            "python/tests/schc/test_rule2.py",
            "python/tests/schc/test_rule3.py",
            "python/tests/schc/test_rule4.py",
            "python/tests/schc/test_rule5.py",
            "python/tests/schc/test_rule6.py",
            "python/tests/schc/test_rule6_decompression.py",
            "-q",
        ],
        cwd=repo,
        timeout=args.timeout,
    )

    cargo_env = os.environ.copy()
    cargo_env["CARGO_TARGET_DIR"] = str(build_root / "cargo-target")
    run(
        ["cargo", "test", "-p", "lichen-schc", "--test", "shared_vectors"],
        cwd=repo / "rust",
        timeout=args.timeout,
        env=cargo_env,
    )

    run(
        ["cmake", "-S", "lichen/tests/schc_parity", "-B", str(c_build)],
        cwd=repo,
        timeout=args.timeout,
    )
    run(["cmake", "--build", str(c_build), "-j4"], cwd=repo, timeout=args.timeout)
    run(
        ["ctest", "--test-dir", str(c_build), "--output-on-failure"],
        cwd=repo,
        timeout=args.timeout,
    )
    print("PASS: canonical SCHC parity agrees across Python, Rust, and C")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as error:
        print(f"ERROR: command timed out after {error.timeout}s: {error.cmd}", file=sys.stderr)
        raise SystemExit(124) from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from error
