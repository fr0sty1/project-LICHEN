---
name: wave-fix
description: Fix beads in priority waves with batched codereview and adversarial verification
model: opus
whenToUse: When processing many beads efficiently with deduped review - say "wave-fix" or "/wave-fix"
---

```javascript
export const meta = {
  name: 'wave-fix',
  description: 'Fix beads in waves, batch codereview, verify findings adversarially',
  phases: [
    { title: 'Inventory', detail: 'Load ready beads, build file graph' },
    { title: 'Waves', detail: 'Fix beads by priority, collect modified files' },
    { title: 'Review', detail: 'Batch codereview on unique files' },
    { title: 'Verify', detail: 'Adversarially challenge findings' },
    { title: 'Converge', detail: 'File confirmed issues, loop if needed' },
  ],
}

const ACTOR = 'claude-wave'
const MAX_PER_WAVE = 15
const MAX_ROUNDS = 3

const FIX_SCHEMA = {
  type: 'object',
  properties: {
    bead_id: { type: 'string' },
    success: { type: 'boolean' },
    files_modified: { type: 'array', items: { type: 'string' } },
    notes: { type: 'string' }
  },
  required: ['bead_id', 'success', 'files_modified']
}

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { enum: ['P0', 'P1', 'P2'] },
          confidence: { enum: ['HIGH', 'MEDIUM', 'LOW'] },
          line: { type: 'integer' },
          issue: { type: 'string' },
          failure_scenario: { type: 'string' }
        },
        required: ['severity', 'confidence', 'issue']
      }
    }
  },
  required: ['file', 'findings']
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { enum: ['CONFIRMED', 'REFUTED', 'UNCERTAIN'] },
    reasoning: { type: 'string' }
  },
  required: ['verdict', 'reasoning']
}

// ─────────────────────────────────────────────────────────────
// Phase 1: Inventory
// ─────────────────────────────────────────────────────────────
phase('Inventory')
log('Loading ready beads...')

const inventory = await agent(`
Run: bd ready --json -n 200 --exclude-type epic

Parse the JSON output and return a structured inventory.
Group beads by priority (0-3). Skip P4 and epics.
For each bead, note any file paths mentioned in the title.

Return JSON with this structure - no markdown, just the JSON object.
`, { 
  schema: {
    type: 'object',
    properties: {
      total: { type: 'integer' },
      by_priority: {
        type: 'object',
        properties: {
          p0: { type: 'array', items: { type: 'string' } },
          p1: { type: 'array', items: { type: 'string' } },
          p2: { type: 'array', items: { type: 'string' } },
          p3: { type: 'array', items: { type: 'string' } }
        }
      }
    },
    required: ['total', 'by_priority']
  }
})

if (!inventory || inventory.total === 0) {
  log('No actionable beads found')
  return { status: 'empty', waves: 0, closed: 0 }
}

log(`Found ${inventory.total} beads: P0=${(inventory.by_priority.p0||[]).length}, P1=${(inventory.by_priority.p1||[]).length}, P2=${(inventory.by_priority.p2||[]).length}, P3=${(inventory.by_priority.p3||[]).length}`)

// ─────────────────────────────────────────────────────────────
// Phase 2: Waves
// ─────────────────────────────────────────────────────────────
phase('Waves')

const allModified = new Set()
let totalClosed = 0
let waveNum = 0

for (const priority of ['p0', 'p1', 'p2', 'p3']) {
  const beadIds = inventory.by_priority[priority] || []
  if (beadIds.length === 0) continue
  
  // Take up to MAX_PER_WAVE beads
  const wave = beadIds.slice(0, MAX_PER_WAVE)
  waveNum++
  
  log(`Wave ${waveNum}: ${wave.length} ${priority.toUpperCase()} beads`)
  
  // Fix beads in parallel
  const results = await parallel(wave.map(beadId => () => 
    agent(`
You are fixing bead ${beadId}.

1. Run: bd update ${beadId} --claim --actor ${ACTOR}
   If claim fails (already claimed), return {bead_id: "${beadId}", success: false, files_modified: [], notes: "already claimed"}

2. Run: bd show ${beadId}
   Read the issue details.

3. Find and read the relevant file(s) mentioned in the issue.

4. Make the minimal fix. Use the Edit tool.

5. If fix succeeded, run: bd close ${beadId} --reason "Fixed by wave-fix"
   Return {bead_id: "${beadId}", success: true, files_modified: ["path/to/file.py"], notes: "brief description"}

6. If you cannot fix it, run: bd unclaim ${beadId} --reason "Could not fix: <reason>"
   Return {bead_id: "${beadId}", success: false, files_modified: [], notes: "reason"}

Do NOT run codereview. Just fix and report.
`, { schema: FIX_SCHEMA, label: `fix:${beadId}`, phase: 'Waves' })
  ))
  
  // Collect results
  for (const r of results) {
    if (r && r.success) {
      totalClosed++
      r.files_modified.forEach(f => allModified.add(f))
    }
  }
  
  log(`Wave ${waveNum} complete: ${results.filter(r => r?.success).length} fixed`)
}

if (allModified.size === 0) {
  log('No files modified, skipping review')
  return { status: 'done', waves: waveNum, closed: totalClosed, reviewed: 0 }
}

// ─────────────────────────────────────────────────────────────
// Phase 3: Batch Review
// ─────────────────────────────────────────────────────────────
phase('Review')

const filesToReview = [...allModified].filter(f => 
  f.endsWith('.py') || f.endsWith('.rs') || f.endsWith('.c') || 
  f.endsWith('.h') || f.endsWith('.ts') || f.endsWith('.js')
)

log(`Reviewing ${filesToReview.length} modified files`)

const allFindings = []

if (filesToReview.length > 0) {
  const reviews = await parallel(filesToReview.map(filepath => () =>
    agent(`
Review ${filepath} from 3 perspectives: CORRECTNESS, SECURITY, EDGE-CASES.

Read the file, then identify DEFECTS - code that will produce wrong behavior.

DO NOT flag: style preferences, naming opinions, hypotheticals without concrete failure scenarios.
DO flag: logic errors, boundary errors, resource leaks, security vulnerabilities, spec violations.

Return findings array. Empty array if the code is clean.
Saying "no issues" is valid - do not manufacture concerns.
`, { schema: REVIEW_SCHEMA, label: `review:${filepath}`, phase: 'Review' })
  ))
  
  for (const r of reviews) {
    if (r && r.findings) {
      // Filter to HIGH confidence only
      const highConf = r.findings.filter(f => f.confidence === 'HIGH')
      highConf.forEach(f => allFindings.push({ ...f, file: r.file }))
    }
  }
}

log(`Found ${allFindings.length} HIGH-confidence findings`)

if (allFindings.length === 0) {
  log('No findings to verify')
  return { status: 'converged', waves: waveNum, closed: totalClosed, reviewed: filesToReview.length, findings: 0 }
}

// ─────────────────────────────────────────────────────────────
// Phase 4: Adversarial Verification
// ─────────────────────────────────────────────────────────────
phase('Verify')

log(`Verifying ${allFindings.length} findings...`)

const verified = await parallel(allFindings.map(finding => () =>
  agent(`
A code reviewer flagged this potential defect:

File: ${finding.file}
Line: ${finding.line || '?'}
Severity: ${finding.severity}
Issue: ${finding.issue}
Failure scenario: ${finding.failure_scenario || 'not specified'}

Your task: Try to REFUTE this finding.

1. Read the file
2. Look for reasons the finding is WRONG:
   - The scenario is impossible (upstream validation prevents it)
   - The behavior is intentional (spec requires it)
   - Another part of the system handles this
   - The failure scenario is incorrect

Be adversarial. Assume the code author knew what they were doing.

Return verdict: CONFIRMED (bug is real), REFUTED (finding is wrong), or UNCERTAIN (needs human).
`, { schema: VERIFY_SCHEMA, label: `verify:${finding.file}:${finding.line}`, phase: 'Verify' })
))

const confirmed = []
const uncertain = []
let refuted = 0

for (let i = 0; i < verified.length; i++) {
  const v = verified[i]
  if (!v) continue
  if (v.verdict === 'CONFIRMED') {
    confirmed.push({ ...allFindings[i], reasoning: v.reasoning })
  } else if (v.verdict === 'UNCERTAIN') {
    uncertain.push({ ...allFindings[i], reasoning: v.reasoning })
  } else {
    refuted++
  }
}

log(`Verification: ${confirmed.length} confirmed, ${refuted} refuted, ${uncertain.length} uncertain`)

// ─────────────────────────────────────────────────────────────
// Phase 5: Converge
// ─────────────────────────────────────────────────────────────
phase('Converge')

// File beads for confirmed findings
const newBeadIds = []
for (const finding of confirmed) {
  const result = await agent(`
Create a bead for this confirmed finding:

File: ${finding.file}
Line: ${finding.line || '?'}
Severity: ${finding.severity}
Issue: ${finding.issue}

Run: bd create --json -p ${finding.severity === 'P0' ? 0 : 1} -t bug -l codereview,wave-fix "${finding.file}:${finding.line || '?'} ${finding.issue.slice(0, 60)}"

Return the new bead ID from the JSON output.
`, { schema: { type: 'object', properties: { bead_id: { type: 'string' } }, required: ['bead_id'] }, label: 'file-bead', phase: 'Converge' })
  
  if (result && result.bead_id) {
    newBeadIds.push(result.bead_id)
  }
}

if (uncertain.length > 0) {
  log(`⚠️ ${uncertain.length} findings need human review:`)
  for (const u of uncertain.slice(0, 5)) {
    log(`  - ${u.file}:${u.line || '?'} ${u.issue.slice(0, 50)}`)
  }
}

if (newBeadIds.length === 0) {
  log('✅ Converged - no new issues')
} else {
  log(`Filed ${newBeadIds.length} new beads - run again to process them`)
}

return {
  status: newBeadIds.length === 0 ? 'converged' : 'continue',
  waves: waveNum,
  closed: totalClosed,
  reviewed: filesToReview.length,
  findings_confirmed: confirmed.length,
  findings_refuted: refuted,
  findings_uncertain: uncertain.length,
  new_beads: newBeadIds
}
```
