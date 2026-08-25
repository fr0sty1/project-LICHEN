# Finding Verification Prompt

Use this to adversarially verify findings before they become beads.

---

## Prompt Template

```
A code reviewer flagged the following potential defect:

## The Finding

**File:** `{file_path}`
**Line:** {line}
**Severity:** {severity}
**Category:** {category}
**Summary:** {summary}
**Claimed failure scenario:** {failure_scenario}

## The Code

```{lang}
{code_with_context}
```

## Bead Context (why this code exists)

{bead_summaries}

## Your Task

Try to REFUTE this finding. You succeed if you can show:

1. **The scenario is impossible** - The claimed inputs cannot occur due to upstream validation, type system, or invariants
2. **The behavior is intentional** - The code does what the spec requires, even if surprising
3. **The concern is mitigated elsewhere** - Another part of the system handles this case
4. **The failure scenario is wrong** - The described inputs would not produce the described output

Be adversarial. Assume the code author knew what they were doing. Look for reasons the finding is WRONG, not reasons it might be right.

## Output Format

```json
{
  "verdict": "CONFIRMED" | "REFUTED" | "UNCERTAIN",
  "reasoning": "One paragraph explaining your conclusion",
  "evidence": "Specific code/spec reference that supports your verdict"
}
```

## Verdict Definitions

- **CONFIRMED**: You tried to refute it and failed. The bug is real.
- **REFUTED**: You found a concrete reason the finding is wrong.
- **UNCERTAIN**: You can't confirm or refute. Needs human judgment.

## Examples

**REFUTED example:**
```json
{
  "verdict": "REFUTED",
  "reasoning": "The reviewer claims `len - 1` causes off-by-one, but this loop processes pairs of elements, so `len - 1` is correct to avoid reading past the array on the second element of each pair.",
  "evidence": "Line 145: `process(arr[i], arr[i+1])` - the `i+1` access requires stopping one early."
}
```

**CONFIRMED example:**
```json
{
  "verdict": "CONFIRMED",
  "reasoning": "The loop iterates `i < len - 1` but accesses only `arr[i]`, not `arr[i+1]`. The last element is genuinely skipped.",
  "evidence": "Line 145 only accesses `arr[i]`. No pair processing. The `- 1` is a bug."
}
```

**UNCERTAIN example:**
```json
{
  "verdict": "UNCERTAIN",
  "reasoning": "Whether this is a bug depends on whether the spec requires processing all elements or allows skipping the last one for alignment. I cannot determine spec intent from the code.",
  "evidence": "Spec section 4.1.2 is ambiguous on trailing element handling."
}
```

Only CONFIRMED findings become beads. REFUTED are discarded. UNCERTAIN are flagged for human review.
```

---

## Integration with Batch Review

```
PHASE 3 - BATCH CODEREVIEW:
  3a. Run context-aware review → raw_findings[]
  3b. Filter: keep only P0-P2 + HIGH confidence
  3c. For each remaining finding:
        Run verify-finding prompt
        If REFUTED → discard
        If UNCERTAIN → tag for human review
        If CONFIRMED → create bead
  3d. Return: {new_beads[], needs_human[]}
```

This adds one agent call per finding but eliminates 50-80% of false positives before they enter the bead queue.

---

## When to Skip Verification

Skip verification (auto-confirm) for:
- P0 security vulnerabilities (too important to risk false negative)
- Findings with attached reproduction (already concrete)
- Findings that reference specific test vector failures

The verification step is for "smells wrong" findings, not "demonstrably broken" findings.
