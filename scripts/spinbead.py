#!/usr/bin/env python3
"""
Spinbead: Process beads in waves with batched codereview via litellm.

Claims each bead as actor ``spinbead`` *before* any file I/O so other
agents (same OS user included) see it leave ``bd ready``. Failed claims
are skipped. Failed fixes with no edits are unclaimed. Once a file is
mutated, the claim is kept (close, or leave in_progress).

Usage:
    ./spinbead.py                    # Process all ready beads
    ./spinbead.py --max-waves 3      # Limit wave iterations
    ./spinbead.py --dry-run          # Show plan without executing
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import httpx

LITELLM_URL = os.environ.get("LITELLM_URL", "http://heft:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_KEY", "sk-litellm-local")
MODEL = os.environ.get("LITELLM_MODEL", "ox-alpha")
MAX_CONCURRENT = int(os.environ.get("SPINBEAD_CONCURRENCY", "8"))
WAVE_CAP = int(os.environ.get("SPINBEAD_WAVE_CAP", "20"))
# Distinct from the human git user so `bd update --claim` is not
# idempotent across Grok/OpenCode sessions on this machine.
ACTOR = os.environ.get("SPINBEAD_ACTOR", "spinbead")
READY_LIMIT = 200


@dataclass
class Bead:
    id: str
    priority: int
    title: str
    tags: list[str] = field(default_factory=list)


@dataclass
class Edit:
    file: str
    search: str
    replace: str


@dataclass
class FixResult:
    bead_id: str
    files_modified: list[str]
    closed: bool
    edits_applied: int = 0
    notes: str = ""


@dataclass
class Finding:
    severity: str
    file: str
    line: int | None
    issue: str
    fix: str = ""


async def llm_call(client: httpx.AsyncClient, prompt: str, system: str = "") -> str:
    """Single LLM call to litellm."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = await client.post(
        f"{LITELLM_URL}/chat/completions",
        headers={"Authorization": f"Bearer {LITELLM_KEY}"},
        json={"model": MODEL, "messages": messages, "temperature": 0},
        timeout=300,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def extract_json(text: str) -> dict | list | None:
    """Extract JSON from LLM response."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    for pattern in [r"(\{[\s\S]*\})", r"(\[[\s\S]*\])"]:
        match = re.search(pattern, text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
    return None


def run_bd(args: list[str], *, write: bool = False) -> subprocess.CompletedProcess:
    """Run a bd command. Write ops pass --actor so claims are not shared."""
    cmd = ["bd"]
    if write:
        cmd += ["--actor", ACTOR]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=True)


def _bd_payload(proc: subprocess.CompletedProcess) -> dict | list | None:
    text = (proc.stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _unwrap_issue(payload: dict | list | None) -> dict | None:
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0]
    if isinstance(payload, dict):
        return payload
    return None


def claim_accepted(proc: subprocess.CompletedProcess, actor: str = ACTOR) -> bool:
    """True iff this actor now holds an in_progress claim."""
    if proc.returncode != 0:
        return False
    issue = _unwrap_issue(_bd_payload(proc))
    if not issue:
        return False
    if issue.get("status") != "in_progress":
        return False
    assignee = issue.get("assignee") or ""
    if assignee and assignee != actor:
        return False
    return True


def claim_bead(bead_id: str) -> bool:
    """Atomically claim bead as ACTOR. False if someone else holds it."""
    proc = run_bd(["update", bead_id, "--claim", "--json"], write=True)
    if not claim_accepted(proc):
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        print(f"      ⏭️  Claim failed: {err[-1] if err else 'not claimable'}")
        return False
    return True


def unclaim_bead(bead_id: str, reason: str) -> None:
    proc = run_bd(["unclaim", bead_id, "--reason", reason, "--json"], write=True)
    if proc.returncode != 0:
        print(f"      ⚠️  unclaim {bead_id} failed: {(proc.stderr or '').strip()[:80]}")


def beads_from_ready_json(payload: list) -> list[Bead]:
    beads: list[Bead] = []
    for item in payload:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        issue_type = str(item.get("issue_type") or item.get("type") or "")
        labels = [str(x) for x in (item.get("labels") or [])]
        if issue_type:
            labels.append(issue_type)
        beads.append(
            Bead(
                id=str(item["id"]),
                priority=int(item.get("priority", 2)),
                title=str(item.get("title") or ""),
                tags=labels,
            )
        )
    return beads


def parse_beads(output: str) -> list[Bead]:
    """Parse human ``bd ready`` lines. Fallback if JSON is unavailable."""
    beads = []
    for line in output.strip().split("\n"):
        match = re.match(r"[○◐●✓❄]\s+(\S+)\s+[●○]\s+P(\d)\s+(.*)", line)
        if match:
            rest = match.group(3)
            tags = re.findall(r"\[(\w+)\]", rest)
            title = re.sub(r"\[\w+\]\s*", "", rest).strip()
            beads.append(
                Bead(
                    id=match.group(1),
                    priority=int(match.group(2)),
                    title=title,
                    tags=tags,
                )
            )
    return beads


def is_actionable(bead: Bead) -> bool:
    return "epic" not in bead.tags and bead.priority <= 3


def load_ready(limit: int = READY_LIMIT) -> list[Bead]:
    """Fresh ``bd ready`` snapshot. Call once per wave, not once per run."""
    proc = run_bd(["ready", "--json", "--exclude-type", "epic", "-n", str(limit)])
    if proc.returncode != 0:
        print(f"   ❌ bd ready failed: {(proc.stderr or '').strip()[:200]}")
        return [b for b in parse_beads(proc.stdout + proc.stderr) if is_actionable(b)]

    payload = _bd_payload(proc)
    if not isinstance(payload, list):
        return [b for b in parse_beads(proc.stdout) if is_actionable(b)]
    return [b for b in beads_from_ready_json(payload) if is_actionable(b)]


def apply_edit(edit: Edit) -> bool:
    """Apply a search/replace edit to a file."""
    try:
        path = Path(edit.file)
        if not path.exists():
            print(f"      ⚠️  File not found: {edit.file}")
            return False

        content = path.read_text()
        if edit.search not in content:
            print(f"      ⚠️  Search text not found in {edit.file}")
            return False

        new_content = content.replace(edit.search, edit.replace, 1)
        path.write_text(new_content)
        return True
    except OSError as e:
        print(f"      ❌ Edit failed: {e}")
        return False


def release_if_clean(bead_id: str, edits_applied: int, reason: str) -> None:
    """Unclaim only when we have not mutated the tree."""
    if edits_applied == 0:
        unclaim_bead(bead_id, reason)


async def fix_bead(client: httpx.AsyncClient, bead: Bead, sem: asyncio.Semaphore) -> FixResult:
    """Fix a single already-claimed bead."""
    async with sem:
        print(f"   🔧 [{bead.id}] {bead.title[:60]}")
        progress = {"edits": 0}
        try:
            return await _fix_claimed_bead(client, bead, progress)
        except Exception as exc:
            release_if_clean(bead.id, progress["edits"], f"exception: {exc}")
            raise


async def _fix_claimed_bead(
    client: httpx.AsyncClient, bead: Bead, progress: dict[str, int]
) -> FixResult:
    show = run_bd(["show", bead.id])
    details = show.stdout + show.stderr

    file_patterns = re.findall(r"[\w/]+\.\w{1,4}", details)
    files_content = {}
    for fp in set(file_patterns):
        try:
            p = Path(fp)
            if p.exists() and p.stat().st_size < 50000:
                files_content[fp] = p.read_text()
        except OSError:
            pass

    files_context = "\n\n".join(
        f"=== {f} ===\n```\n{c[:4000]}\n```"
        for f, c in list(files_content.items())[:3]
    )

    prompt = f"""Fix this issue. Return JSON with exact search/replace edits.

BEAD: {bead.id}
TITLE: {bead.title}
PRIORITY: P{bead.priority}

DETAILS:
{details[:3000]}

RELEVANT FILES:
{files_context if files_context else "(no files found - search the codebase)"}

Return JSON:
{{
  "can_fix": true/false,
  "reason": "why or why not",
  "edits": [
    {{"file": "path/to/file.py", "search": "exact old code", "replace": "exact new code"}}
  ]
}}

RULES:
- "search" must be EXACT text from the file (copy-paste, preserve whitespace)
- Keep edits minimal - only what's needed to fix the issue
- If you can't fix it (need more context, unclear, etc), set can_fix=false
"""

    response = await llm_call(client, prompt)
    result = extract_json(response)

    if not result:
        release_if_clean(bead.id, 0, "Failed to parse LLM response")
        return FixResult(bead.id, [], False, notes="Failed to parse LLM response")

    if not result.get("can_fix"):
        reason = result.get("reason", "unknown")
        print(f"      ⏭️  Cannot fix: {reason[:50]}")
        release_if_clean(bead.id, 0, f"Cannot fix: {reason[:120]}")
        return FixResult(bead.id, [], False, notes=str(reason))

    edits = result.get("edits", [])
    files_modified: set[str] = set()
    edits_applied = 0

    for e in edits:
        if not all(k in e for k in ("file", "search", "replace")):
            continue
        edit = Edit(file=e["file"], search=e["search"], replace=e["replace"])
        if apply_edit(edit):
            files_modified.add(edit.file)
            edits_applied += 1
            progress["edits"] = edits_applied
            print(f"      ✅ Edited {edit.file}")

    if edits_applied == 0:
        release_if_clean(bead.id, 0, "No edits applied")
        return FixResult(bead.id, [], False, notes="No edits applied")

    close = run_bd(
        ["close", bead.id, "--reason", f"spinbead applied {edits_applied} edit(s)"],
        write=True,
    )
    if close.returncode != 0:
        # Files are already changed: keep the claim so nobody else redoes it.
        print(f"      ⚠️  close failed, keeping claim: {(close.stderr or '').strip()[:80]}")
        return FixResult(
            bead_id=bead.id,
            files_modified=list(files_modified),
            closed=False,
            edits_applied=edits_applied,
            notes="close failed; left in_progress",
        )
    print(f"      ✓ Closed {bead.id}")

    return FixResult(
        bead_id=bead.id,
        files_modified=list(files_modified),
        closed=True,
        edits_applied=edits_applied,
    )


async def review_file(client: httpx.AsyncClient, filepath: str, sem: asyncio.Semaphore) -> list[Finding]:
    """Review a file from 3 perspectives."""
    async with sem:
        print(f"   🔍 {filepath}")

        try:
            content = Path(filepath).read_text()
        except OSError:
            return []

        prompt = f"""Review from 3 perspectives: CORRECTNESS, SECURITY, EDGE-CASES.

FILE: {filepath}
```
{content[:12000]}
```

Return JSON array of findings (empty if clean):
[
  {{"severity": "P0|P1|P2", "line": 123, "issue": "one line description", "fix": "suggestion"}}
]

P0 = crash/data-loss/security
P1 = bug/incorrect-behavior
P2 = code-smell/risk

Skip style nits. Only real issues.
"""

        response = await llm_call(client, prompt)
        result = extract_json(response)

        if not result or not isinstance(result, list):
            return []

        findings = []
        for f in result:
            if isinstance(f, dict) and f.get("severity") in ("P0", "P1", "P2"):
                findings.append(Finding(
                    severity=f["severity"],
                    file=filepath,
                    line=f.get("line"),
                    issue=f.get("issue", ""),
                    fix=f.get("fix", ""),
                ))
        return findings


def file_beads(findings: list[Finding]) -> list[str]:
    """File new beads for findings. Returns list of created IDs."""
    new_ids = []
    for f in findings:
        if f.severity not in ("P0", "P1"):
            continue

        priority = 0 if f.severity == "P0" else 1
        title = f"{f.file}:{f.line or '?'} {f.issue[:80]}"

        created = run_bd(
            [
                "create",
                "--json",
                "-p", str(priority),
                "-t", "bug",
                "-l", "codereview,spinbead",
                title,
            ],
            write=True,
        )
        if created.returncode != 0:
            print(f"   ⚠️  create failed: {(created.stderr or '').strip()[:80]}")
            continue

        issue = _unwrap_issue(_bd_payload(created))
        new_id = (issue or {}).get("id")
        if new_id:
            new_ids.append(str(new_id))
            print(f"   📝 Filed P{priority}: {title[:60]}")

    return new_ids


def claim_wave(candidates: list[Bead]) -> list[Bead]:
    """Claim up to WAVE_CAP beads as spinbead before any LLM work."""
    claimed: list[Bead] = []
    for bead in candidates:
        if len(claimed) >= WAVE_CAP:
            break
        if not claim_bead(bead.id):
            continue
        claimed.append(bead)
    return claimed


async def spinbead(max_waves: int = 10, dry_run: bool = False) -> dict:
    """Main orchestration loop."""
    print(f"🎯 Spinbead (model: {MODEL}, concurrency: {MAX_CONCURRENT})")
    print(f"   litellm: {LITELLM_URL}")
    print(f"   actor: {ACTOR}\n")

    print("📋 PHASE 1: Inventory")
    beads = load_ready(READY_LIMIT)
    print(f"   {len(beads)} actionable beads (excluding epics)")

    if not beads:
        print("\n✅ No beads to process")
        return {"waves": 0, "closed": 0, "reviewed": 0}

    by_priority: dict[int, list[Bead]] = {}
    for b in beads:
        by_priority.setdefault(b.priority, []).append(b)

    for p in sorted(by_priority.keys()):
        print(f"   P{p}: {len(by_priority[p])}")

    if dry_run:
        print("\n📊 Dry run complete (no claims)")
        return {"waves": 0, "closed": 0, "reviewed": 0, "dry_run": True}

    print("\n⚡ PHASE 2: Waves")
    all_modified: set[str] = set()
    total_closed = 0
    wave_num = 0
    files: list[str] = []
    new_beads: list[str] = []

    async with httpx.AsyncClient() as client:
        for priority in [0, 1, 2, 3]:
            fresh = [b for b in load_ready(READY_LIMIT) if b.priority == priority]
            if not fresh:
                continue

            wave_num += 1
            if wave_num > max_waves:
                print(f"\n⚠️  Max waves ({max_waves}) reached")
                break

            print(f"\n🌊 Wave {wave_num}: claiming from {len(fresh)} P{priority} beads")
            claimed = claim_wave(fresh)
            print(f"   claimed {len(claimed)} as {ACTOR}")
            if not claimed:
                continue

            sem = asyncio.Semaphore(MAX_CONCURRENT)
            tasks = [fix_bead(client, b, sem) for b in claimed]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, FixResult):
                    if r.closed:
                        total_closed += 1
                    all_modified.update(r.files_modified)
                elif isinstance(r, Exception):
                    print(f"   ❌ {r}")

        print(f"\n🔬 PHASE 3: Review ({len(all_modified)} files)")

        source_exts = {".py", ".rs", ".c", ".h", ".ts", ".js", ".go"}
        files = [f for f in all_modified if Path(f).suffix in source_exts]

        all_findings: list[Finding] = []
        if files:
            sem = asyncio.Semaphore(MAX_CONCURRENT)
            tasks = [review_file(client, f, sem) for f in files]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, list):
                    all_findings.extend(r)

        p0p1 = [f for f in all_findings if f.severity in ("P0", "P1")]
        print(f"   {len(all_findings)} findings ({len(p0p1)} P0/P1)")

        print("\n🔄 PHASE 4: Converge")
        new_beads = file_beads(p0p1)

        if not new_beads:
            print("   ✅ Converged")
        else:
            print(f"   {len(new_beads)} new beads filed - run again")

    return {
        "waves": wave_num,
        "closed": total_closed,
        "reviewed": len(files),
        "new_beads": len(new_beads),
    }


def main():
    global MODEL, MAX_CONCURRENT

    parser = argparse.ArgumentParser(description="Process beads in waves via litellm")
    parser.add_argument("--max-waves", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--model", "-m", default=MODEL)
    parser.add_argument("--concurrency", "-c", type=int, default=MAX_CONCURRENT)
    args = parser.parse_args()

    MODEL = args.model
    MAX_CONCURRENT = args.concurrency

    result = asyncio.run(spinbead(args.max_waves, args.dry_run))
    print(f"\n📊 {json.dumps(result)}")


if __name__ == "__main__":
    main()
