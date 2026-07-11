# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "lichen" / "cmake" / "lichen_build_epoch.cmake"
FIRMWARE_ENTRYPOINTS = (
    ROOT / "lichen" / "apps" / "gateway",
    ROOT / "lichen" / "apps" / "puck",
    ROOT / "firmware" / "bridge-zephyr",
)


def _run_cmake_script(
    script: str, *, source_date_epoch: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if source_date_epoch is None:
        env.pop("SOURCE_DATE_EPOCH", None)
    else:
        env["SOURCE_DATE_EPOCH"] = source_date_epoch

    # A real file, not /dev/stdin: cmake -P seeks the script to check for a
    # byte-order mark, which fails on a non-seekable pipe.
    with tempfile.NamedTemporaryFile("w", suffix=".cmake", delete=False) as f:
        f.write(textwrap.dedent(script))
        script_path = f.name
    try:
        return subprocess.run(
            ["cmake", "-P", script_path],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        os.unlink(script_path)


def test_production_fails_without_deterministic_metadata() -> None:
    result = _run_cmake_script(
        f"""
        include({HELPER})
        lichen_configure_time_build_epoch()
        """
    )

    assert result.returncode != 0
    assert "requires SOURCE_DATE_EPOCH" in result.stderr


def test_firmware_entrypoints_fail_without_deterministic_metadata() -> None:
    env = os.environ.copy()
    env.pop("SOURCE_DATE_EPOCH", None)

    for entrypoint in FIRMWARE_ENTRYPOINTS:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(entrypoint),
                    "-B",
                    tmpdir,
                    "-DBOARD=qemu_x86",
                    f"-DZEPHYR_EXTRA_MODULES={ROOT / 'lichen'}",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

        assert result.returncode != 0, entrypoint
        assert "requires SOURCE_DATE_EPOCH" in result.stderr, entrypoint
        assert "find_package" not in result.stderr, entrypoint


def test_source_date_epoch_takes_precedence_over_release_epoch() -> None:
    result = _run_cmake_script(
        f"""
        include({HELPER})
        lichen_time_build_epoch_resolve(
          MODE production
          RELEASE_EPOCH 1712222222
          OUT_EPOCH epoch
          OUT_SOURCE source
        )
        message("epoch=${{epoch}};source=${{source}}")
        """,
        source_date_epoch="1711111111",
    )

    assert result.returncode == 0, result.stderr
    assert "epoch=1711111111;source=SOURCE_DATE_EPOCH" in result.stderr


def test_developer_generated_mode_uses_host_timestamp_path() -> None:
    result = _run_cmake_script(
        f"""
        include({HELPER})
        lichen_time_build_epoch_resolve(
          MODE developer-generated
          OUT_EPOCH epoch
          OUT_SOURCE source
          OUT_GENERATED generated
        )
        message("epoch=${{epoch}};source=${{source}};generated=${{generated}}")
        """
    )

    assert result.returncode == 0, result.stderr
    assert ";source=DEVELOPER_GENERATED;generated=TRUE" in result.stderr


def test_developer_fixed_epoch_has_distinct_source_metadata() -> None:
    result = _run_cmake_script(
        f"""
        include({HELPER})
        lichen_time_build_epoch_resolve(
          MODE developer-generated
          DEVELOPER_EPOCH 1713333333
          OUT_EPOCH epoch
          OUT_SOURCE source
          OUT_GENERATED generated
        )
        message("epoch=${{epoch}};source=${{source}};generated=${{generated}}")
        """
    )

    assert result.returncode == 0, result.stderr
    assert "epoch=1713333333;source=DEVELOPER_FIXED;generated=FALSE" in result.stderr
