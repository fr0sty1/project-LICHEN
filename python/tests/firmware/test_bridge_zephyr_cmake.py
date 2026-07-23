# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
BRIDGE_CMAKE = ROOT / "firmware" / "bridge-zephyr" / "CMakeLists.txt"
BRIDGE_KCONFIG = ROOT / "firmware" / "bridge-zephyr" / "Kconfig"
L2_KCONFIG = ROOT / "lichen" / "subsys" / "lichen" / "l2" / "Kconfig"
BRIDGE_BOARDS = ROOT / "firmware" / "bridge-zephyr" / "boards"
BRIDGE_AUTO_MERGE_BOARD_FILES = (
    "heltec_vision_master_e213",
    "heltec_vision_master_e290",
    "heltec_wifi_lora32_v3_esp32s3_procpu",
    "heltec_wireless_tracker",
    "lilygo_tbeam",
    "rak19007_wisblock",
    "rak4631_nrf52840",
    "station_g2",
    "t1000_e_nrf52840",
    "t_deck_esp32s3_procpu",
    "t_echo_nrf52840",
    "xiao_s3_wio_sx1262",
)
BRIDGE_OBSOLETE_ALIAS_BOARD_FILES = (
    "heltec_lora32_v3",
    "heltec_t114",
    "lilygo_tdeck",
    "lilygo_techo",
    "seeed_t1000e",
)


def _non_comment_cmake_lines() -> list[str]:
    return [
        line.strip()
        for line in BRIDGE_CMAKE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]



def test_bridge_zephyr_does_not_compile_vendored_lichen_sources() -> None:
    cmake = BRIDGE_CMAKE.read_text(encoding="utf-8")
    cmake_lines = "\n".join(_non_comment_cmake_lines())

    assert "subsys/lichen/ipv6_addr.c" not in cmake
    assert "subsys/lichen/lichen_util.c" not in cmake
    assert "subsys/lichen/crash_info.c" not in cmake
    assert "subsys/lichen/lora_l2.c" not in cmake
    assert "subsys/lichen/lichen_l2.c" not in cmake
    assert "target_sources_ifdef(CONFIG_LICHEN_LORA_L2" not in cmake
    assert "target_sources_ifdef(CONFIG_LICHEN_L2" not in cmake
    assert "add_subdirectory(subsys" not in cmake_lines
    assert "file(GLOB" not in cmake_lines
    assert "${CMAKE_CURRENT_SOURCE_DIR}/subsys" not in cmake_lines
    assert "../../lichen/subsys/lichen/l2" in cmake


def test_bridge_zephyr_does_not_source_legacy_lichen_kconfig() -> None:
    kconfig = BRIDGE_KCONFIG.read_text(encoding="utf-8")

    assert 'rsource "subsys/Kconfig"' not in kconfig


def test_module_lora_l2_selects_link_layer_dependency() -> None:
    kconfig = L2_KCONFIG.read_text(encoding="utf-8")
    lora_l2_block = kconfig.split("config LICHEN_LORA_L2", maxsplit=1)[1].split(
        "config LICHEN_LORA_L2_LOG_LEVEL", maxsplit=1
    )[0]

    assert "select LICHEN_LINK" in lora_l2_block


def test_bridge_zephyr_has_target_qualified_board_fragments() -> None:
    for board in BRIDGE_AUTO_MERGE_BOARD_FILES:
        assert (BRIDGE_BOARDS / f"{board}.conf").is_file(), board
        assert (BRIDGE_BOARDS / f"{board}.overlay").is_file(), board


def test_bridge_zephyr_omits_obsolete_alias_board_fragments() -> None:
    for board in BRIDGE_OBSOLETE_ALIAS_BOARD_FILES:
        assert not (BRIDGE_BOARDS / f"{board}.conf").exists(), board
        assert not (BRIDGE_BOARDS / f"{board}.overlay").exists(), board


@pytest.mark.skipif(
    os.environ.get("LICHEN_RUN_ZEPHYR_SMOKE") != "1",
    reason="set LICHEN_RUN_ZEPHYR_SMOKE=1 in a Zephyr workspace",
)
def test_bridge_zephyr_qemu_smoke_uses_module_owned_l2_sources(tmp_path: Path) -> None:
    if shutil.which("west") is None:
        pytest.skip("west is not installed")

    build_dir = tmp_path / "bridge_qemu_source_epoch"
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1717777777"
    result = subprocess.run(
        [
            "west",
            "build",
            "-p",
            "always",
            "-b",
            "qemu_x86",
            "-d",
            str(build_dir),
            str(ROOT / "firmware" / "bridge-zephyr"),
            "--",
            f"-DZEPHYR_EXTRA_MODULES={ROOT / 'lichen'}",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "multiple definition" not in result.stdout + result.stderr
    assert "undefined reference" not in result.stdout + result.stderr
    config = (build_dir / "zephyr" / ".config").read_text(encoding="utf-8")
    assert "CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX=1717777777" in config
    assert "CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_DATE_EPOCH=y" in config

    compile_commands = json.loads(
        (build_dir / "compile_commands.json").read_text(encoding="utf-8")
    )
    l2_common_sources = {
        Path(entry["file"]).name: Path(entry["file"])
        for entry in compile_commands
        if Path(entry["file"]).name
        in {"crash_info.c", "lichen_util.c", "ipv6_addr.c"}
    }

    assert set(l2_common_sources) == {
        "crash_info.c",
        "lichen_util.c",
        "ipv6_addr.c",
    }
    for source in l2_common_sources.values():
        assert ROOT / "lichen" / "subsys" / "lichen" / "l2" in source.parents
        assert ROOT / "firmware" / "bridge-zephyr" / "subsys" not in source.parents


@pytest.mark.skipif(
    os.environ.get("LICHEN_RUN_ZEPHYR_SMOKE") != "1",
    reason="set LICHEN_RUN_ZEPHYR_SMOKE=1 in a Zephyr workspace",
)
def test_bridge_zephyr_native_sim_lora_loopback_enables_full_l2(
    tmp_path: Path,
) -> None:
    if shutil.which("west") is None:
        pytest.skip("west is not installed")

    extra_conf = tmp_path / "native_sim_lora_loopback.conf"
    extra_conf.write_text(
        "\n".join(
            [
                "CONFIG_LORA=y",
                "CONFIG_LORA_LOOPBACK=y",
                "CONFIG_LORA_LOOPBACK_MTU=255",
                "CONFIG_LICHEN_LORA_L2_RX_TIMEOUT_MS=100",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    overlay = tmp_path / "native_sim_lora_loopback.overlay"
    overlay.write_text(
        """
        / {
            aliases {
                lora0 = &lora_loopback0;
            };

            chosen {
                zephyr,lora = &lora_loopback0;
            };

            lora_loopback0: lora {
                compatible = "lichen,lora-loopback";
                status = "okay";
            };
        };
        """,
        encoding="utf-8",
    )

    build_dir = tmp_path / "bridge_native_sim_lora_loopback"
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1717777777"
    result = subprocess.run(
        [
            "west",
            "build",
            "-p",
            "always",
            "-b",
            "native_sim",
            "-d",
            str(build_dir),
            str(ROOT / "firmware" / "bridge-zephyr"),
            "--",
            f"-DZEPHYR_EXTRA_MODULES={ROOT / 'lichen'}",
            f"-DEXTRA_CONF_FILE={extra_conf}",
            f"-DDTC_OVERLAY_FILE={overlay}",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "multiple definition" not in result.stdout + result.stderr
    assert "undefined reference" not in result.stdout + result.stderr
    config = (build_dir / "zephyr" / ".config").read_text(encoding="utf-8")
    assert "CONFIG_LORA=y" in config
    assert "CONFIG_LORA_LOOPBACK=y" in config
    assert "CONFIG_LICHEN_LORA_L2=y" in config
    assert "CONFIG_LICHEN_LINK=y" in config
    assert "CONFIG_LICHEN_L2=y" in config

    compile_commands = json.loads(
        (build_dir / "compile_commands.json").read_text(encoding="utf-8")
    )
    l2_sources = {
        Path(entry["file"]).name: Path(entry["file"])
        for entry in compile_commands
        if Path(entry["file"]).name
        in {
            "crash_info.c",
            "lichen_util.c",
            "ipv6_addr.c",
            "lora_l2.c",
            "lichen_l2.c",
        }
    }

    assert set(l2_sources) == {
        "crash_info.c",
        "lichen_util.c",
        "ipv6_addr.c",
        "lora_l2.c",
        "lichen_l2.c",
    }
    for source in l2_sources.values():
        assert ROOT / "lichen" / "subsys" / "lichen" / "l2" in source.parents
        assert ROOT / "firmware" / "bridge-zephyr" / "subsys" not in source.parents


@pytest.mark.skipif(
    os.environ.get("LICHEN_RUN_ZEPHYR_SMOKE") != "1",
    reason="set LICHEN_RUN_ZEPHYR_SMOKE=1 in a Zephyr workspace",
)
def test_bridge_zephyr_heltec_target_auto_merges_lora_board_files(
    tmp_path: Path,
) -> None:
    if shutil.which("west") is None:
        pytest.skip("west is not installed")

    build_dir = tmp_path / "bridge_heltec_auto_merge"
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1717777777"
    result = subprocess.run(
        [
            "west",
            "build",
            "-p",
            "always",
            "-b",
            "heltec_wifi_lora32_v3/esp32s3/procpu",
            "-d",
            str(build_dir),
            str(ROOT / "firmware" / "bridge-zephyr"),
            "--",
            f"-DZEPHYR_EXTRA_MODULES={ROOT / 'lichen'}",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "multiple definition" not in result.stdout + result.stderr
    assert "undefined reference" not in result.stdout + result.stderr
    config = (build_dir / "zephyr" / ".config").read_text(encoding="utf-8")
    assert "CONFIG_LORA=y" in config
    assert "CONFIG_LICHEN_LORA_L2=y" in config
    assert "CONFIG_LICHEN_LINK=y" in config
    assert "CONFIG_LICHEN_L2=y" in config

    compile_commands = json.loads(
        (build_dir / "compile_commands.json").read_text(encoding="utf-8")
    )
    l2_sources = {
        Path(entry["file"]).name: Path(entry["file"])
        for entry in compile_commands
        if Path(entry["file"]).name in {"lora_l2.c", "lichen_l2.c"}
    }

    assert set(l2_sources) == {"lora_l2.c", "lichen_l2.c"}
    for source in l2_sources.values():
        assert ROOT / "lichen" / "subsys" / "lichen" / "l2" in source.parents
        assert ROOT / "firmware" / "bridge-zephyr" / "subsys" not in source.parents
