# Context-Aware Code Review Prompt

Use this template for batch code review after wave-based fixes.

---

## Prompt Template

```
You are reviewing changes to `{file_path}`.

## Context

These changes were made to address:
{bead_summaries}

## The Diff

```diff
{diff}
```

## Surrounding Code (for reference)

```{lang}
{surrounding_context}
```

## Your Task

Identify DEFECTS - code that will produce wrong behavior in production.

DO NOT flag:
- Style preferences ("I would have written it differently")
- Naming opinions ("this variable name is unclear")
- Missing features not in scope ("this could also handle X")
- Patterns that look unusual but work correctly
- Anything explained by the bead context above
- Hypothetical concerns without concrete failure scenarios

DO flag:
- Logic errors (wrong result for valid input)
- Boundary errors (off-by-one, overflow, underflow)
- Resource leaks (memory, file handles, locks)
- Security vulnerabilities (injection, overflow, auth bypass)
- Undefined behavior (null deref, use-after-free, data races)
- Spec violations (behavior contradicts documented requirements)

## Output Format

If you find defects, output JSON:

```json
{
  "findings": [
    {
      "line": 142,
      "severity": "P1",
      "confidence": "HIGH",
      "category": "boundary-error",
      "summary": "Off-by-one in loop termination causes last element to be skipped",
      "failure_scenario": "Input array of length N processes only N-1 elements",
      "suggested_fix": "Change `< len - 1` to `< len`"
    }
  ]
}
```

If no defects meet the bar, output:

```json
{
  "findings": [],
  "note": "Changes look correct for stated intent. No defects found."
}
```

## Severity Definitions

- **P0**: Security vulnerability, data loss, or crash in normal operation
- **P1**: Wrong behavior that users will encounter
- **P2**: Wrong behavior in edge cases
- **P3**: Code smell that could become a bug later

## Confidence Definitions

- **HIGH**: You can describe exact inputs that trigger the bug
- **MEDIUM**: You believe there's a bug but can't construct a concrete case
- **LOW**: Something feels off but you're not sure

Only P0-P2 with HIGH confidence become beads. Everything else is discarded.

## Anti-Bikeshed Check

Before submitting each finding, ask yourself:
"If I posted this as a PR comment, would the author say 'good catch' or 'that's intentional'?"

If the latter is plausible, don't submit it.

Saying "no issues found" is a valid and respectable output. It means the code is good. Do not manufacture concerns to appear thorough.
```

---

## Variables

| Variable | Source |
|----------|--------|
| `{file_path}` | The file being reviewed |
| `{bead_summaries}` | 1-2 sentence summary of each bead that touched this file |
| `{diff}` | Unified diff of all changes to this file in this round |
| `{lang}` | Language for syntax highlighting (c, rust, python) |
| `{surrounding_context}` | 50-100 lines around the changed regions |

---

## Example Bead Summary Format

```
- bd-l1qw.1.4.3: Implement frame CRC validation per spec 4.1.2
- bd-l1qw.1.5.1: Add sender ID extraction for 10-byte extended format
- bd-85z6: Fix off-by-one in signature truncation (was 47 bytes, spec requires 48)
```

---

## Post-Review Filtering

After collecting all findings across all files:

```python
def filter_findings(findings: list, previous_round_findings: set) -> list:
    dominated = []
    for f in findings:
        dominated_dominated = f["severity"] in ["P0", "P1", "P2"] \
            and f["confidence"] == "HIGH" \
            and f["id"] not in previous_round_findings  # not a repeat
        if keep:
            accepted.append(f)
    return accepted
```

Discard:
- P3 (too minor)
- MEDIUM/LOW confidence (not concrete enough)  
- Repeats from previous round (it's an opinion, not a bug)

---

## Convergence Criteria

The review loop terminates when ANY of:

1. `filter_findings()` returns empty list
2. Same findings appear in consecutive rounds (opinion, not bug - close as wontfix)
3. 3 rounds completed on same file set (diminishing returns)

Do NOT chase "zero raw findings." Chase "zero actionable defects."
