# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
from pathlib import Path

from lichen.board_intake import build_report, main


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def assert_every_fact_has_source(report: dict) -> None:
    for fact in report["parsed_facts"]:
        assert fact["sources"], fact
        assert fact["id"].startswith("fact.")
        assert fact["confidence"] == "observed"
        for ref in fact["sources"]:
            assert ref["path"]
            assert ref["line_start"] >= 1
            assert ref["line_end"] >= ref["line_start"]
            assert ref["extract"]


def test_meshtastic_like_variant_report_separates_facts_inferences_and_decisions(
    tmp_path: Path,
) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:t-echo]
board = t-echo
board_build.variant = t_echo
monitor_port = /dev/ttyACM0
build_flags =
    -D LORA_SX1262
    -D HAS_GPS=1
""".strip(),
    )
    board_json = write(
        tmp_path / "boards" / "t-echo.json",
        json.dumps(
            {
                "id": "t-echo",
                "name": "LilyGO T-Echo",
                "mcu": "nrf52840",
                "frameworks": ["arduino"],
                "build": {"f_cpu": "64000000L", "variant": "t_echo"},
                "upload": {"maximum_size": 1048576, "maximum_ram_size": 262144},
            },
            indent=2,
        ),
    )
    variant = write(
        tmp_path / "variants" / "t_echo" / "variant.h",
        """
#define USE_SX1262
#define PIN_GPS_RX 8
#define EINK_DISPLAY_MODEL "GDEW0154M10"
#define USER_BUTTON 11
""".strip(),
    )

    report = build_report(
        source_project="meshtastic",
        board_id="t-echo",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[variant],
    )

    assert report["format_version"] == 1
    assert report["source_set"]["source_project"] == "meshtastic"
    assert report["parsed_facts"]
    assert_every_fact_has_source(report)
    assert report["human_decisions"] == []
    assert report["zephyr_support_status"] == "needs_validation"
    assert report["zephyr_port_checklist"]
    assert report["follow_up_beads"][0]["blocked_by_hardware_validation"] is True

    inferred = {
        (item["kind"], item["key"], item["value"]) for item in report["inferred_suggestions"]
    }
    assert ("radio", "chip", "SX1262") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_LORA", "y") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_GNSS", "y") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_DISPLAY", "y") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_BUTTONS", "y") in inferred
    lora_fact = next(fact for fact in report["parsed_facts"] if "-D LORA_SX1262" in fact["value"])
    assert lora_fact["sources"][0]["line_end"] > lora_fact["sources"][0]["line_start"]
    assert "-D LORA_SX1262" in lora_fact["sources"][0]["extract"]


def test_meshcore_like_variant_report_flags_lr1110_and_power_questions(tmp_path: Path) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:arduino_base]
build_flags = -D RADIO_LR1110 -D PMU_AXP2101

[env:tracker_lr1110]
extends = env:arduino_base
board = tracker_lr1110
board_build.variant = tracker_lr1110
upload_protocol = nrfutil
""".strip(),
    )
    board_json = write(
        tmp_path / "boards" / "tracker_lr1110.json",
        json.dumps(
            {
                "id": "tracker_lr1110",
                "name": "MeshCore LR1110 Tracker",
                "mcu": "nrf52840",
                "frameworks": ["arduino"],
                "build": {"variant": "tracker_lr1110"},
                "upload": {"maximum_size": 1048576, "maximum_ram_size": 262144},
            },
            indent=2,
        ),
    )
    variant = write(
        tmp_path / "variants" / "tracker_lr1110" / "board.h",
        """
#define RADIO_LR1110 1
#define PMU_AXP2101 1
#define LED_PIN 13
""".strip(),
    )

    report = build_report(
        source_project="meshcore",
        board_id="tracker_lr1110",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[variant],
    )

    assert_every_fact_has_source(report)
    inferred = {
        (item["kind"], item["key"], item["value"]) for item in report["inferred_suggestions"]
    }
    assert ("radio", "chip", "LR1110") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_RADIO_MODEL_LR1110", "y") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_BATTERY", "y") in inferred
    assert ("lichen_kconfig", "CONFIG_LICHEN_HAS_LEDS", "y") in inferred
    assert any(fact["key"] == "extends" for fact in report["parsed_facts"])
    assert any("RADIO_LR1110" in fact["value"] for fact in report["parsed_facts"])
    assert all(item["confidence"] != "valid" for item in report["inferred_suggestions"])
    assert all(item["status"] != "valid" for item in report["zephyr_port_checklist"])


def test_cli_writes_deterministic_json(tmp_path: Path) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:heltec_v3]
board = heltec_v3
board_build.variant = heltec_v3
build_flags = -D SX1262
""".strip(),
    )
    board_json = write(
        tmp_path / "heltec_v3.json",
        json.dumps({"id": "heltec_v3", "name": "Heltec V3", "mcu": "esp32s3"}),
    )
    variant = write(tmp_path / "variant.h", "#define HAS_OLED 1\n")
    out = tmp_path / "report.json"

    assert (
        main(
            [
                "--source-project",
                "meshtastic",
                "--board-id",
                "heltec_v3",
                "--platformio-ini",
                str(platformio),
                "--board-json",
                str(board_json),
                "--variant-header",
                str(variant),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    first = out.read_text(encoding="utf-8")
    assert json.loads(first)["source_set"]["board_id"] == "heltec_v3"

    assert (
        main(
            [
                "--source-project",
                "meshtastic",
                "--board-id",
                "heltec_v3",
                "--platformio-ini",
                str(platformio),
                "--board-json",
                str(board_json),
                "--variant-header",
                str(variant),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    assert out.read_text(encoding="utf-8") == first


def test_conflicting_radio_sources_create_unresolved_question(tmp_path: Path) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:mixed]
board = mixed
build_flags = -D SX1262
""".strip(),
    )
    board_json = write(tmp_path / "mixed.json", json.dumps({"id": "mixed", "mcu": "esp32s3"}))
    variant = write(tmp_path / "variant.h", "#define USE_SX1276 1\n")

    report = build_report(
        source_project="meshtastic",
        board_id="mixed",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[variant],
    )

    assert report["unresolved_questions"]
    assert report["unresolved_questions"][0]["id"] == "question.radio.conflict"
    assert "SX1262" in report["unresolved_questions"][0]["question"]
    assert "SX1276" in report["unresolved_questions"][0]["question"]
    assert len(report["unresolved_questions"][0]["sources"]) >= 2


def test_conflicting_mcu_and_variant_sources_create_unresolved_questions(
    tmp_path: Path,
) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:base]
board_build.mcu = esp32s3

[env:mixed]
extends = env:base
board = mixed
board_build.variant = header_variant
""".strip(),
    )
    board_json = write(
        tmp_path / "mixed.json",
        json.dumps(
            {
                "id": "mixed",
                "mcu": "nrf52840",
                "build": {"variant": "json_variant"},
            }
        ),
    )

    report = build_report(
        source_project="meshcore",
        board_id="mixed",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[],
    )

    questions = {item["id"]: item for item in report["unresolved_questions"]}
    assert "question.mcu.conflict" in questions
    assert "esp32s3" in questions["question.mcu.conflict"]["question"]
    assert "nrf52840" in questions["question.mcu.conflict"]["question"]
    assert len(questions["question.mcu.conflict"]["sources"]) == 2
    assert "question.variant.conflict" in questions
    assert "header_variant" in questions["question.variant.conflict"]["question"]
    assert "json_variant" in questions["question.variant.conflict"]["question"]


def test_conflicting_pin_and_peripheral_sources_create_unresolved_questions(
    tmp_path: Path,
) -> None:
    platformio = write(
        tmp_path / "platformio.ini",
        """
[env:pinmix]
board = pinmix
build_flags =
    -D PIN_SCK=5
    -D DISPLAY_MODEL=SSD1306
""".strip(),
    )
    board_json = write(tmp_path / "pinmix.json", json.dumps({"id": "pinmix", "mcu": "esp32s3"}))
    variant = write(
        tmp_path / "variant.h",
        """
#define PIN_SCK 6
#define DISPLAY_MODEL ST7789
""".strip(),
    )

    report = build_report(
        source_project="meshtastic",
        board_id="pinmix",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[variant],
    )

    questions = {item["id"]: item for item in report["unresolved_questions"]}
    assert "question.peripheral.pin-sck.conflict" in questions
    assert "5" in questions["question.peripheral.pin-sck.conflict"]["question"]
    assert "6" in questions["question.peripheral.pin-sck.conflict"]["question"]
    assert "question.peripheral.display-model.conflict" in questions
    assert "SSD1306" in questions["question.peripheral.display-model.conflict"]["question"]
    assert "ST7789" in questions["question.peripheral.display-model.conflict"]["question"]


def test_report_sections_do_not_duplicate_ids(tmp_path: Path) -> None:
    platformio = write(tmp_path / "platformio.ini", "[env:rak]\nboard = rak\n")
    board_json = write(tmp_path / "rak.json", json.dumps({"id": "rak", "mcu": "nrf52840"}))
    report = build_report(
        source_project="meshcore",
        board_id="rak",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[],
    )

    ids = []
    for section in (
        "parsed_facts",
        "inferred_suggestions",
        "unresolved_questions",
        "zephyr_port_checklist",
    ):
        ids.extend(item["id"] for item in report[section])
    assert len(ids) == len(set(ids))


def test_missing_scope_facts_create_unresolved_questions(tmp_path: Path) -> None:
    platformio = write(tmp_path / "platformio.ini", "[env:minimal]\nboard = minimal\n")
    board_json = write(tmp_path / "minimal.json", json.dumps({"id": "minimal", "mcu": "esp32s3"}))
    report = build_report(
        source_project="meshcore",
        board_id="minimal",
        platformio_ini=platformio,
        board_json=board_json,
        variant_headers=[],
    )

    question_ids = {item["id"] for item in report["unresolved_questions"]}
    assert "question.radio.missing" in question_ids
    assert "question.pins.missing" in question_ids
    assert "question.gnss.missing" in question_ids
    assert "question.display.missing" in question_ids
    assert "question.power.missing" in question_ids
