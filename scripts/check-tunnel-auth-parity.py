#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Run the authoritative Python/Rust/C tunnel-authorization parity gate."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 300) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", action="store_true", help="also run the Zephyr qemu_x86 corpus")
    parser.add_argument(
        "--build-root",
        type=Path,
        default=ROOT / "build" / "tunnel-auth-parity",
        help="isolated build/cache directory",
    )
    args = parser.parse_args()
    build_root = args.build_root.resolve()
    build_root.mkdir(parents=True, exist_ok=True)

    # The Python consumer validates schema, generator freshness, independent
    # crypto intermediates, and exact denial/code output for all fixture cases.
    run([sys.executable, "test/vectors/generate_tunnel_authorization.py", "--check"])
    run(
        [
            "uv", "run", "--project", "python", "python", "-m", "pytest", "-q",
            "python/tests/gateway/test_tunnel_auth_vectors.py",
        ]
    )

    # Rust and C consume that same immutable JSON, not outputs from Python.
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", str(build_root / "cargo"))
    run(
        [
            "cargo", "test", "-p", "lichen-gateway", "--test", "tunnel_auth_vectors",
            "--manifest-path", "rust/Cargo.toml",
        ],
        env=env,
        timeout=900,
    )
    host = build_root / "host-c"
    run(["cmake", "-S", "lichen/tests/tunnel_auth", "-B", str(host)])
    run(["cmake", "--build", str(host), "--parallel"])
    run(["ctest", "--test-dir", str(host), "--output-on-failure"])

    if args.qemu:
        if "ZEPHYR_BASE" not in env:
            parser.error("--qemu requires ZEPHYR_BASE and a configured west environment")
        qemu = build_root / "qemu"
        run(
            [
                "west", "build", "-p", "always", "-b", "qemu_x86", "-d", str(qemu),
                str(ROOT / "lichen/tests/tunnel_auth_zephyr"), "--",
                f"-DZEPHYR_EXTRA_MODULES={ROOT / 'lichen'}",
            ],
            env=env,
            timeout=900,
        )
        print("+ west build -t run (bounded)", flush=True)
        try:
            completed = subprocess.run(
                ["west", "build", "-d", str(qemu), "-t", "run"],
                cwd=ROOT,
                env=env,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
            )
            output = completed.stdout
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
        print(output)
        if "PROJECT EXECUTION SUCCESSFUL" not in output or "FAIL -" in output:
            raise RuntimeError("Zephyr tunnel-auth corpus did not pass")

    print("tunnel-auth parity: Python/Rust/C decisions and canonical bytes agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
