# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Deterministic board intake reports for PlatformIO-oriented LoRa firmware.

The intake tool extracts reviewable facts from PlatformIO board JSON,
``platformio.ini`` environments, and variant headers. It deliberately does not
generate or claim valid Zephyr board support. Its output separates parsed facts,
derived suggestions, and human decisions that require build or hardware
evidence.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1


class Confidence(StrEnum):
    """Confidence level for a parsed fact or inference."""

    OBSERVED = "observed"
    INFERRED = "inferred"


class QuestionKind(StrEnum):
    """Classification for unresolved questions requiring human review."""

    CONFLICT = "conflict"
    MISSING_FACT = "missing_fact"


class ChecklistStatus(StrEnum):
    """Status values for Zephyr port checklist items."""

    NEEDS_VALIDATION = "needs_validation"
    VALIDATED = "validated"
    FAILED = "failed"

RADIO_CAPABILITIES = {
    "SX1261": ("sx126x", "CONFIG_LICHEN_RADIO_MODEL_SX126X"),
    "SX1262": ("sx126x", "CONFIG_LICHEN_RADIO_MODEL_SX126X"),
    "SX1272": ("sx127x", "CONFIG_LICHEN_RADIO_MODEL_SX127X"),
    "SX1276": ("sx127x", "CONFIG_LICHEN_RADIO_MODEL_SX127X"),
    "SX1278": ("sx127x", "CONFIG_LICHEN_RADIO_MODEL_SX127X"),
    "LR1110": ("lr1110", "CONFIG_LICHEN_RADIO_MODEL_LR1110"),
}


@dataclass(frozen=True)
class SourceRef:
    """A source location backing a parsed fact or inference."""

    path: str
    line_start: int
    line_end: int
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "extract": self.label,
        }


@dataclass(frozen=True)
class IniValue:
    """One parsed PlatformIO setting with its source span."""

    value: str
    ref: SourceRef


@dataclass(frozen=True)
class IniSection:
    """One PlatformIO section preserving item source spans."""

    name: str
    line: int
    items: dict[str, IniValue]


@dataclass(frozen=True)
class Fact:
    """A directly parsed fact with at least one source reference."""

    category: str
    key: str
    value: str
    source_refs: tuple[SourceRef, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": f"fact.{self.category}.{self.key}.{_slug(self.value)}",
            "kind": self.category,
            "key": self.key,
            "value": self.value,
            "confidence": Confidence.OBSERVED,
            "sources": [ref.to_dict() for ref in self.source_refs],
        }


@dataclass(frozen=True)
class Inference:
    """A deterministic suggestion derived from one or more parsed facts."""

    category: str
    key: str
    value: str
    confidence: str
    reason: str
    based_on: tuple[SourceRef, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": f"infer.{self.category}.{self.key}.{_slug(self.value)}",
            "kind": self.category,
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "sources": [ref.to_dict() for ref in self.based_on],
        }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "empty"


def _line_for_text(path: Path, needle: str) -> int:
    try:
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if needle in line:
                return index
    except FileNotFoundError:
        return 1
    return 1


def _source_ref(path: Path, label: str, needle: str | None = None) -> SourceRef:
    line = _line_for_text(path, needle if needle is not None else label)
    return SourceRef(
        path=path.as_posix(),
        line_start=line,
        line_end=line,
        label=label,
    )


def _add_json_fact(
    facts: list[Fact],
    path: Path,
    category: str,
    key: str,
    value: Any,
    needle: str | None = None,
) -> None:
    if value is None:
        return
    facts.append(
        Fact(
            category=category,
            key=key,
            value=str(value),
            source_refs=(_source_ref(path, key, needle or key),),
        )
    )


def parse_board_json(path: Path) -> list[Fact]:
    """Extract board facts from a PlatformIO board JSON file."""

    data = json.loads(path.read_text(encoding="utf-8"))
    build = data.get("build", {})
    upload = data.get("upload", {})
    facts: list[Fact] = []

    _add_json_fact(facts, path, "board_json", "id", data.get("id"), '"id"')
    _add_json_fact(facts, path, "board_json", "name", data.get("name"), '"name"')
    _add_json_fact(facts, path, "mcu", "mcu", data.get("mcu") or build.get("mcu"), '"mcu"')
    _add_json_fact(facts, path, "mcu", "f_cpu", build.get("f_cpu"), '"f_cpu"')
    frameworks = data.get("frameworks")
    if frameworks is not None:
        _add_json_fact(facts, path, "framework", "frameworks", ",".join(frameworks))
    _add_json_fact(facts, path, "flash", "maximum_size", upload.get("maximum_size"))
    _add_json_fact(facts, path, "ram", "maximum_ram_size", upload.get("maximum_ram_size"))
    _add_json_fact(facts, path, "variant", "variant", build.get("variant"), '"variant"')
    return facts


def parse_platformio_sections(path: Path) -> dict[str, IniSection]:
    """Parse PlatformIO sections while preserving value line spans."""

    sections: dict[str, IniSection] = {}
    current_name: str | None = None
    current_line = 1
    current_items: dict[str, IniValue] = {}
    pending_key: str | None = None
    pending_value: list[str] = []
    pending_start = 1
    pending_end = 1

    def flush_pending() -> None:
        nonlocal pending_key, pending_value, pending_start, pending_end
        if current_name is None or pending_key is None:
            return
        value = " ".join(part.strip() for part in pending_value if part.strip())
        current_items[pending_key] = IniValue(
            value=value,
            ref=SourceRef(
                path.as_posix(),
                pending_start,
                pending_end,
                "\n".join(pending_value).strip(),
            ),
        )
        pending_key = None
        pending_value = []
        pending_start = 1
        pending_end = 1

    def flush_section() -> None:
        if current_name is None:
            return
        sections[current_name] = IniSection(current_name, current_line, dict(current_items))

    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            flush_pending()
            flush_section()
            current_name = stripped[1:-1]
            current_line = line_no
            current_items = {}
            pending_key = None
            pending_value = []
            pending_start = 1
            pending_end = 1
            continue
        if current_name is None or not stripped or stripped.startswith(("#", ";")):
            continue
        if raw[:1].isspace() and pending_key is not None:
            pending_value.append(stripped)
            pending_end = line_no
            continue
        if "=" in raw:
            flush_pending()
            key, value = raw.split("=", 1)
            pending_key = key.strip()
            pending_value = [value.strip()]
            pending_start = line_no
            pending_end = line_no
    flush_pending()
    flush_section()
    return sections


def _resolve_ini_items(
    sections: dict[str, IniSection],
    section_name: str,
    visiting: frozenset[str] = frozenset(),
) -> dict[str, IniValue]:
    if section_name in visiting or section_name not in sections:
        return {}
    section = sections[section_name]
    merged: dict[str, IniValue] = {}
    extends = section.items.get("extends")
    if extends is not None:
        for parent in re.split(r"[\s,]+", extends.value):
            if parent:
                merged.update(_resolve_ini_items(sections, parent, visiting | {section_name}))
    merged.update(section.items)
    return merged


def parse_platformio_ini(path: Path, board_id: str) -> list[Fact]:
    """Extract matching environment facts from ``platformio.ini``."""

    sections = parse_platformio_sections(path)
    facts: list[Fact] = []
    for section in sorted(sections):
        if not section.startswith("env:"):
            continue
        env_name = section.removeprefix("env:")
        items = _resolve_ini_items(sections, section)
        values = {key: item.value for key, item in items.items()}
        candidate_names = {
            env_name,
            values.get("board", ""),
            values.get("board_build.variant", ""),
        }
        if board_id not in candidate_names:
            continue
        section_ref = SourceRef(
            path.as_posix(),
            sections[section].line,
            sections[section].line,
            f"[{section}]",
        )
        facts.append(Fact("platformio_env", "env", env_name, (section_ref,)))
        for key in sorted(items):
            facts.append(
                Fact(
                    category="platformio_env",
                    key=key,
                    value=items[key].value,
                    source_refs=(items[key].ref,),
                )
            )
            if key == "build_flags":
                for match in BUILD_FLAG_DEFINE_RE.finditer(items[key].value):
                    facts.append(
                        Fact(
                            category="platformio_define",
                            key=match.group(1),
                            value=match.group(2) or "1",
                            source_refs=(items[key].ref,),
                        )
                    )
    return facts


DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$")
BUILD_FLAG_DEFINE_RE = re.compile(r"(?:^|\s)-D\s*([A-Za-z_][A-Za-z0-9_]*)(?:=([^\s]+))?")


def parse_variant_header(path: Path) -> list[Fact]:
    """Extract macro facts from one variant header."""

    facts: list[Fact] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = DEFINE_RE.match(line)
        if match is None:
            continue
        name = match.group(1)
        value = match.group(2).strip() or "1"
        facts.append(
            Fact(
                category="variant_define",
                key=name,
                value=value.strip('"'),
                source_refs=(SourceRef(path.as_posix(), index, index, line.strip()),),
            )
        )
    return facts


def _fact_text(fact: Fact) -> str:
    return f"{fact.key} {fact.value}".upper()


def infer_from_facts(facts: list[Fact]) -> list[Inference]:
    """Create deterministic Zephyr/LICHEN suggestions from parsed facts."""

    inferences: list[Inference] = []
    seen: set[tuple[str, str, str]] = set()

    def add(category: str, key: str, value: str, confidence: str, reason: str, fact: Fact) -> None:
        identity = (category, key, value)
        if identity in seen:
            return
        seen.add(identity)
        inferences.append(
            Inference(category, key, value, confidence, reason, fact.source_refs)
        )

    for fact in facts:
        text = _fact_text(fact)
        for chip, (radio_family, radio_config) in RADIO_CAPABILITIES.items():
            if chip in text:
                add("radio", "chip", chip, "high", f"matched {chip} in parsed source", fact)
                add(
                    "lichen_kconfig",
                    "CONFIG_LICHEN_HAS_LORA",
                    "y",
                    "medium",
                    "radio chip found",
                    fact,
                )
                add(
                    "lichen_kconfig",
                    radio_config,
                    "y",
                    "medium",
                    f"{radio_family} radio family",
                    fact,
                )
        if any(token in text for token in ("GPS", "GNSS", "L76K", "AG3335")):
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_GNSS",
                "y",
                "medium",
                "GNSS-like token found",
                fact,
            )
        if any(token in text for token in ("DISPLAY", "OLED", "SSD1306", "ST7789", "EINK", "GDEW")):
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_DISPLAY",
                "y",
                "low",
                "display-like token found",
                fact,
            )
        if any(token in text for token in ("BUTTON", "BTN", "KEY", "SWITCH")):
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_BUTTONS",
                "y",
                "low",
                "input-like token found",
                fact,
            )
        if "LED" in text:
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_LEDS",
                "y",
                "low",
                "LED-like token found",
                fact,
            )
        if any(token in text for token in ("BAT", "BATTERY", "PMU", "PMIC", "AXP")):
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_BATTERY",
                "y",
                "low",
                "power token found",
                fact,
            )
        if any(token in text for token in ("FLASH", "SD", "SDCARD", "SPIFLASH")):
            add(
                "lichen_kconfig",
                "CONFIG_LICHEN_HAS_EXTERNAL_FLASH",
                "y",
                "low",
                "storage token found",
                fact,
            )

    board_name = next((fact.value for fact in facts if fact.key in {"id", "board"}), "unknown")
    first_ref = facts[0].source_refs[0] if facts else SourceRef("unknown", 1, 1, "unknown")
    inferences.append(
        Inference(
            category="zephyr_candidate",
            key="suggested_files",
            value=f"lichen/boards/<vendor>/{board_name}/ plus app board overlays",
            confidence="low",
            reason="Zephyr board ownership must be reviewed manually",
            based_on=(first_ref,),
        )
    )
    return sorted(inferences, key=lambda item: (item.category, item.key, item.value))


def find_unresolved_questions(facts: list[Fact]) -> list[dict[str, Any]]:
    """Find conflicts and missing evidence that need human resolution."""

    questions: list[dict[str, Any]] = []

    def add_value_conflict(
        *,
        question_id: str,
        label: str,
        matching_facts: list[Fact],
    ) -> None:
        values = sorted({fact.value for fact in matching_facts})
        if len(values) <= 1:
            return
        questions.append(
            {
                "id": question_id,
                "kind": QuestionKind.CONFLICT,
                "question": f"Conflicting {label} values found: {', '.join(values)}",
                "sources": [ref.to_dict() for fact in matching_facts for ref in fact.source_refs],
            }
        )

    mcu_facts = [
        fact
        for fact in facts
        if fact.category == "mcu" or fact.key in {"mcu", "board_build.mcu"}
    ]
    variant_facts = [
        fact
        for fact in facts
        if fact.category == "variant" or fact.key in {"variant", "board_build.variant"}
    ]
    add_value_conflict(
        question_id="question.mcu.conflict",
        label="MCU/SoC",
        matching_facts=mcu_facts,
    )
    add_value_conflict(
        question_id="question.variant.conflict",
        label="PlatformIO variant",
        matching_facts=variant_facts,
    )

    conflict_prefixes = (
        "PIN_",
        "LORA_",
        "SPI_",
        "I2C_",
        "UART_",
        "GPS_",
        "GNSS_",
        "DISPLAY_",
        "OLED_",
        "EINK_",
        "PMU_",
        "PMIC_",
        "BAT_",
        "BATTERY_",
        "BLE_",
        "USB_",
        "SERIAL_",
    )
    conflict_names = {
        "SCK",
        "MISO",
        "MOSI",
        "NSS",
        "CS",
        "RESET",
        "BUSY",
        "DIO1",
        "SDA",
        "SCL",
        "RX",
        "TX",
    }
    keyed_conflicts: dict[str, list[Fact]] = {}
    for fact in facts:
        key = fact.key.upper()
        if key.startswith(conflict_prefixes) or key in conflict_names:
            keyed_conflicts.setdefault(key, []).append(fact)
    for key in sorted(keyed_conflicts):
        add_value_conflict(
            question_id=f"question.peripheral.{_slug(key)}.conflict",
            label=f"peripheral mapping {key}",
            matching_facts=keyed_conflicts[key],
        )

    radio_facts = [
        fact
        for fact in facts
        for chip in RADIO_CAPABILITIES
        if chip in _fact_text(fact)
    ]
    radio_chips = sorted(
        {
            chip
            for fact in radio_facts
            for chip in RADIO_CAPABILITIES
            if chip in _fact_text(fact)
        }
    )
    if len(radio_chips) > 1:
        sources = [ref.to_dict() for fact in radio_facts for ref in fact.source_refs]
        questions.append(
            {
                "id": "question.radio.conflict",
                "kind": QuestionKind.CONFLICT,
                "question": f"Conflicting radio chips found: {', '.join(radio_chips)}",
                "sources": sources,
            }
        )
    if not radio_chips:
        questions.append(
            {
                "id": "question.radio.missing",
                "kind": QuestionKind.MISSING_FACT,
                "question": "No supported LoRa radio chip was identified.",
                "sources": [],
            }
        )
    has_mcu = any(
        fact.category == "mcu" or fact.key in {"mcu", "board_build.mcu"}
        for fact in facts
    )
    has_variant = any(fact.category == "variant" or "variant" in fact.key for fact in facts)
    has_pins = any(
        fact.key.upper().startswith(("PIN_", "LORA_", "SPI_", "I2C_", "UART_"))
        for fact in facts
    )
    has_gnss = any(
        token in _fact_text(fact)
        for fact in facts
        for token in ("GPS", "GNSS", "L76K", "AG3335")
    )
    observed = {
        "mcu": has_mcu,
        "variant": has_variant,
        "pins": has_pins,
        "gnss": has_gnss,
        "display": any(
            token in _fact_text(fact)
            for fact in facts
            for token in ("DISPLAY", "OLED", "SSD1306", "ST7789", "EINK", "GDEW")
        ),
        "power": any(
            token in _fact_text(fact)
            for fact in facts
            for token in ("BAT", "BATTERY", "PMU", "PMIC", "AXP")
        ),
        "local_transport": any(
            token in _fact_text(fact)
            for fact in facts
            for token in ("BLE", "USB", "SERIAL", "UART", "CDC")
        ),
    }
    missing_prompts = {
        "mcu": "No MCU/SoC fact was identified.",
        "variant": "No PlatformIO variant fact was identified.",
        "pins": "No SPI/I2C/UART/GPIO pin mappings were identified.",
        "gnss": "No GNSS/location fact was identified; confirm absence or add source.",
        "display": "No display fact was identified; confirm absence or add source.",
        "power": "No PMIC/battery fact was identified; confirm absence or add source.",
        "local_transport": "No BLE/USB/serial local transport fact was identified.",
    }
    for key in sorted(missing_prompts):
        if not observed[key]:
            questions.append(
                {
                    "id": f"question.{key}.missing",
                    "kind": QuestionKind.MISSING_FACT,
                    "question": missing_prompts[key],
                    "sources": [],
                }
            )
    return questions


def build_zephyr_port_checklist(board_id: str) -> list[dict[str, Any]]:
    """Return review tasks required before claiming Zephyr board support."""

    return [
        {
            "id": "checklist.zephyr_board",
            "title": f"Create or select Zephyr board definition for {board_id}",
            "evidence_required": ["board DTS", "Kconfig.board", "build log"],
            "status": ChecklistStatus.NEEDS_VALIDATION,
        },
        {
            "id": "checklist.app_overlay",
            "title": f"Map {board_id} peripherals to LICHEN app overlays",
            "evidence_required": ["devicetree chosen/alias nodes", "HAL capability review"],
            "status": ChecklistStatus.NEEDS_VALIDATION,
        },
        {
            "id": "checklist.smoke",
            "title": f"Run board-appropriate build and smoke validation for {board_id}",
            "evidence_required": ["Zephyr build", "hardware smoke test where applicable"],
            "status": ChecklistStatus.NEEDS_VALIDATION,
        },
    ]


def build_follow_up_beads(board_id: str, source_project: str) -> list[dict[str, Any]]:
    """Describe follow-up Beads without creating them."""

    return [
        {
            "title": (
                f"Port {source_project} {board_id} facts into a reviewed "
                "Zephyr board checklist"
            ),
            "description": (
                "Use the board intake report to decide Zephyr board/overlay work; "
                "do not claim support until build and smoke evidence exists."
            ),
            "labels": ["zephyr", "board-support", "hal", source_project],
            "blocked_by_hardware_validation": True,
        }
    ]


def build_report(
    *,
    source_project: str,
    board_id: str,
    platformio_ini: Path,
    board_json: Path,
    variant_headers: list[Path],
) -> dict[str, Any]:
    """Build a deterministic intake report from PlatformIO-oriented inputs."""

    facts: list[Fact] = []
    facts.extend(parse_board_json(board_json))
    facts.extend(parse_platformio_ini(platformio_ini, board_id))
    for header in sorted(variant_headers):
        facts.extend(parse_variant_header(header))

    facts = sorted(facts, key=lambda fact: (fact.category, fact.key, fact.value))
    inferences = infer_from_facts(facts)
    return {
        "format_version": FORMAT_VERSION,
        "source_set": {
            "source_project": source_project,
            "board_id": board_id,
            "platformio_ini": platformio_ini.as_posix(),
            "board_json": board_json.as_posix(),
            "variant_headers": [path.as_posix() for path in sorted(variant_headers)],
        },
        "parsed_facts": [fact.to_dict() for fact in facts],
        "inferred_suggestions": [inference.to_dict() for inference in inferences],
        "human_decisions": [],
        "unresolved_questions": find_unresolved_questions(facts),
        "zephyr_port_checklist": build_zephyr_port_checklist(board_id),
        "follow_up_beads": build_follow_up_beads(board_id, source_project),
        "zephyr_support_status": ChecklistStatus.NEEDS_VALIDATION,
    }


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-project", required=True)
    parser.add_argument("--board-id", required=True)
    parser.add_argument("--platformio-ini", type=Path, required=True)
    parser.add_argument("--board-json", type=Path, required=True)
    parser.add_argument("--variant-header", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    report = build_report(
        source_project=args.source_project,
        board_id=args.board_id,
        platformio_ini=args.platformio_ini,
        board_json=args.board_json,
        variant_headers=args.variant_header,
    )
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(text, end="")
    else:
        args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
