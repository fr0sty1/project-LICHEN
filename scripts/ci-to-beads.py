#!/usr/bin/env python3
"""
Parse CI test results and create beads for failures.

Supports:
- twister XML results (Zephyr tests)
- pytest JUnit XML
- cppcheck XML
- clang-tidy output

Usage:
  ./ci-to-beads.py twister twister-out/twister.xml
  ./ci-to-beads.py pytest python/junit.xml
  ./ci-to-beads.py cppcheck cppcheck-results.xml
  ./ci-to-beads.py clang-tidy clang-tidy.log
"""

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def run_bd(args: list[str]) -> tuple[int, str]:
    """Run bd command and return exit code + output."""
    result = subprocess.run(
        ["bd"] + args,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


def bead_exists(title_fragment: str) -> bool:
    """Check if a bead with similar title already exists."""
    code, output = run_bd(["list", "--status", "open"])
    return title_fragment.lower() in output.lower()


def create_bead(title: str, body: str, priority: str = "P3") -> str | None:
    """Create a bead and return its ID."""
    # Truncate title to 80 chars
    if len(title) > 80:
        title = title[:77] + "..."

    # Check for duplicate
    key_words = title.split()[:3]
    if key_words and bead_exists(" ".join(key_words)):
        print(f"  SKIP (exists): {title[:60]}")
        return None

    code, output = run_bd([
        "create", title,
        "--type", "bug",
        "--priority", priority,
        "--body", body
    ])

    if code == 0:
        # Extract bead ID from output
        for line in output.split("\n"):
            if "project-LICHEN-" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("project-LICHEN-"):
                        print(f"  CREATED: {p} - {title[:50]}")
                        return p
    else:
        print(f"  FAILED: {title[:50]} - {output[:100]}")
    return None


def parse_twister(xml_path: str) -> list[dict]:
    """Parse twister XML results."""
    findings = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for testsuite in root.findall(".//testsuite"):
        suite_name = testsuite.get("name", "unknown")

        for testcase in testsuite.findall("testcase"):
            test_name = testcase.get("name", "unknown")

            # Check for failures
            failure = testcase.find("failure")
            if failure is not None:
                findings.append({
                    "title": f"Zephyr test failure: {suite_name}/{test_name}",
                    "body": f"Test: {suite_name}::{test_name}\n\n{failure.text or failure.get('message', 'No details')}",
                    "priority": "P2",
                    "file": f"lichen/tests/{suite_name}",
                })

            # Check for errors
            error = testcase.find("error")
            if error is not None:
                findings.append({
                    "title": f"Zephyr test error: {suite_name}/{test_name}",
                    "body": f"Test: {suite_name}::{test_name}\n\n{error.text or error.get('message', 'No details')}",
                    "priority": "P2",
                    "file": f"lichen/tests/{suite_name}",
                })

    return findings


def parse_pytest(xml_path: str) -> list[dict]:
    """Parse pytest JUnit XML results."""
    findings = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for testcase in root.findall(".//testcase"):
        classname = testcase.get("classname", "")
        name = testcase.get("name", "unknown")

        failure = testcase.find("failure")
        if failure is not None:
            findings.append({
                "title": f"Python test failure: {name}",
                "body": f"Test: {classname}::{name}\n\n```\n{failure.text[:2000] if failure.text else 'No traceback'}\n```",
                "priority": "P2",
                "file": classname.replace(".", "/") + ".py",
            })

        error = testcase.find("error")
        if error is not None:
            findings.append({
                "title": f"Python test error: {name}",
                "body": f"Test: {classname}::{name}\n\n```\n{error.text[:2000] if error.text else 'No traceback'}\n```",
                "priority": "P1",  # Errors are more severe
                "file": classname.replace(".", "/") + ".py",
            })

    return findings


def parse_cppcheck(xml_path: str) -> list[dict]:
    """Parse cppcheck XML results."""
    findings = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for error in root.findall(".//error"):
        error_id = error.get("id", "unknown")
        severity = error.get("severity", "style")
        msg = error.get("msg", "No message")

        # Get location
        location = error.find("location")
        file_path = location.get("file", "unknown") if location is not None else "unknown"
        line = location.get("line", "?") if location is not None else "?"

        # Map severity to priority
        priority_map = {
            "error": "P1",
            "warning": "P2",
            "style": "P3",
            "performance": "P3",
            "portability": "P3",
            "information": "P4",
        }
        priority = priority_map.get(severity, "P3")

        findings.append({
            "title": f"cppcheck {severity}: {error_id} in {Path(file_path).name}",
            "body": f"File: {file_path}:{line}\nSeverity: {severity}\nID: {error_id}\n\n{msg}",
            "priority": priority,
            "file": file_path,
        })

    return findings


def parse_clang_tidy(log_path: str) -> list[dict]:
    """Parse clang-tidy text output."""
    findings = []

    with open(log_path) as f:
        content = f.read()

    # Parse lines like: /path/file.c:123:45: warning: message [check-name]
    import re
    pattern = r"([^:\s]+):(\d+):(\d+): (warning|error): (.+?) \[([^\]]+)\]"

    for match in re.finditer(pattern, content):
        file_path, line, col, severity, msg, check = match.groups()

        priority = "P1" if severity == "error" else "P2"

        findings.append({
            "title": f"clang-tidy {check} in {Path(file_path).name}:{line}",
            "body": f"File: {file_path}:{line}:{col}\nCheck: {check}\n\n{msg}",
            "priority": priority,
            "file": file_path,
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Create beads from CI results")
    parser.add_argument("format", choices=["twister", "pytest", "cppcheck", "clang-tidy"])
    parser.add_argument("path", help="Path to results file")
    parser.add_argument("--dry-run", action="store_true", help="Don't create beads, just print")
    parser.add_argument("--max", type=int, default=50, help="Max beads to create")
    args = parser.parse_args()

    if not Path(args.path).exists():
        print(f"File not found: {args.path}")
        sys.exit(1)

    # Parse results
    parsers = {
        "twister": parse_twister,
        "pytest": parse_pytest,
        "cppcheck": parse_cppcheck,
        "clang-tidy": parse_clang_tidy,
    }

    findings = parsers[args.format](args.path)
    print(f"Found {len(findings)} issues in {args.path}")

    if args.dry_run:
        for f in findings[:args.max]:
            print(f"  [{f['priority']}] {f['title'][:60]}")
        return

    # Create beads
    created = 0
    for f in findings[:args.max]:
        bead_id = create_bead(f["title"], f["body"], f["priority"])
        if bead_id:
            created += 1

    print(f"\nCreated {created} beads from {len(findings)} findings")


if __name__ == "__main__":
    main()
