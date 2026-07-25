---
name: spec-executor
description: Execute spec implementation beads with dependency-aware orchestration
model: opus
whenToUse: When working through the 1,767 spec implementation beads under project-LICHEN-worker6-l1qw
---

```javascript
export const meta = {
  name: 'spec-executor',
  description: 'Execute spec implementation beads across all chapters',
  phases: [
    { title: 'Discover', detail: 'Load bead graph, identify ready work' },
    { title: 'Vectors', detail: 'Generate test vectors for unblocked chapters' },
    { title: 'Implement', detail: 'Run per-language implementation tasks' },
    { title: 'Validate', detail: 'Cross-validation gates' },
    { title: 'Report', detail: 'Final progress summary' },
  ],
}

const MASTER_EPIC = 'project-LICHEN-worker6-l1qw'
const MAX_FAILURES = 3

// Track failures per bead (resets each run)
const failures = new Map()

// Helper: parse bd output
function parseBeadList(output) {
  const lines = output.trim().split('\n').filter(l => l.includes('project-LICHEN'))
  return lines.map(l => {
    const match = l.match(/(project-LICHEN-[\w.-]+)/)
    return match ? match[1] : null
  }).filter(Boolean)
}

// ─────────────────────────────────────────────────────────────
// Phase 1: Discover
// ─────────────────────────────────────────────────────────────
phase('Discover')

const discovery = await agent(`
You are analyzing the spec implementation bead structure to find ready work.

Master epic: ${MASTER_EPIC}

Run these commands:
1. bd show ${MASTER_EPIC} — see the chapter/thruline structure
2. bd search "l1qw" --limit 100 — sample the beads

Categorize beads by their title patterns:
- "Vectors: X" → vector tasks (should run first)
- "Python: X" / "Rust: X" / "Zephyr: X" → implementation tasks
- "Cross-validate: X" → cross-validation tasks (run after impls)

A bead is READY if:
- Status is "open" (not closed, not in_progress)
- For impl tasks: no blocking vector task, OR vector task is closed
- For cross-val tasks: all impl tasks in same parent epic are closed

Return counts and lists of ready bead IDs by category.
Focus on the first 3-4 chapters for this run.
`, {
  label: 'discover',
  schema: {
    type: 'object',
    properties: {
      vectorsReady: { 
        type: 'array', 
        items: { type: 'string' },
        description: 'Bead IDs for ready vector tasks'
      },
      implsReady: { 
        type: 'array', 
        items: { type: 'string' },
        description: 'Bead IDs for ready implementation tasks'
      },
      crossValReady: { 
        type: 'array', 
        items: { type: 'string' },
        description: 'Bead IDs for ready cross-validation tasks'
      },
      summary: {
        type: 'object',
        properties: {
          totalScanned: { type: 'number' },
          alreadyClosed: { type: 'number' },
          readyCount: { type: 'number' },
        }
      }
    },
    required: ['vectorsReady', 'implsReady', 'crossValReady', 'summary']
  }
})

if (!discovery) {
  log('Discovery failed, aborting')
  return { error: 'discovery failed' }
}

log(`Found: ${discovery.vectorsReady.length} vectors, ${discovery.implsReady.length} impls, ${discovery.crossValReady.length} cross-val ready`)

// ─────────────────────────────────────────────────────────────
// Phase 2: Vectors
// ─────────────────────────────────────────────────────────────
phase('Vectors')

const vectorLimit = Math.min(discovery.vectorsReady.length, 5)
let vectorsClosed = 0

if (vectorLimit > 0) {
  log(`Processing ${vectorLimit} vector tasks`)
  
  const vectorResults = await parallel(
    discovery.vectorsReady.slice(0, vectorLimit).map(beadId => async () => {
      return await agent(`
Work on test vector bead: ${beadId}

Steps:
1. Claim it: bd update ${beadId} --claim
2. Read description: bd show ${beadId}
3. Check existing vectors in test/vectors/
4. Create or complete the required JSON test vectors
5. Validate JSON is well-formed
6. If complete, close: bd close ${beadId} --reason "Test vectors created"

If you cannot complete (missing info, blocked), do NOT close. Explain why.
`, {
        label: 'vec:' + beadId.split('.').pop(),
        phase: 'Vectors',
        schema: {
          type: 'object',
          properties: {
            beadId: { type: 'string' },
            success: { type: 'boolean' },
            filesCreated: { type: 'array', items: { type: 'string' } },
            reason: { type: 'string' },
          },
          required: ['beadId', 'success']
        }
      })
    })
  )
  
  vectorsClosed = vectorResults.filter(r => r?.success).length
  log(`Vectors: ${vectorsClosed}/${vectorLimit} completed`)
}

// ─────────────────────────────────────────────────────────────
// Phase 3: Implement
// ─────────────────────────────────────────────────────────────
phase('Implement')

const implLimit = Math.min(discovery.implsReady.length, 8)
let implsClosed = 0

if (implLimit > 0) {
  log(`Processing ${implLimit} implementation tasks`)
  
  const implResults = await parallel(
    discovery.implsReady.slice(0, implLimit).map(beadId => async () => {
      const failCount = failures.get(beadId) || 0
      if (failCount >= MAX_FAILURES) {
        return { beadId, success: false, reason: 'max failures reached, escalate' }
      }
      
      const result = await agent(`
Implement bead: ${beadId}

Steps:
1. Claim: bd update ${beadId} --claim
2. Read description: bd show ${beadId}
3. Find relevant source files (Python in python/src/, Rust in rust/, Zephyr in lichen/)
4. Implement the feature per the description
5. Run relevant tests (pytest, cargo test, or twister)
6. If tests pass, close: bd close ${beadId} --reason "Implemented and tested"

If blocked or tests fail, do NOT close. Explain the issue.
`, {
        label: 'impl:' + beadId.split('.').pop(),
        phase: 'Implement',
        schema: {
          type: 'object',
          properties: {
            beadId: { type: 'string' },
            success: { type: 'boolean' },
            filesChanged: { type: 'array', items: { type: 'string' } },
            testsPassed: { type: 'boolean' },
            reason: { type: 'string' },
          },
          required: ['beadId', 'success']
        }
      })
      
      if (result && !result.success) {
        failures.set(beadId, failCount + 1)
      }
      return result
    })
  )
  
  implsClosed = implResults.filter(r => r?.success).length
  const escalations = implResults.filter(r => r?.reason?.includes('escalate'))
  
  log(`Implement: ${implsClosed}/${implLimit} completed`)
  if (escalations.length > 0) {
    log(`ESCALATE: ${escalations.map(e => e.beadId).join(', ')}`)
  }
}

// ─────────────────────────────────────────────────────────────
// Phase 4: Validate
// ─────────────────────────────────────────────────────────────
phase('Validate')

const crossValLimit = Math.min(discovery.crossValReady.length, 3)
let crossValClosed = 0

if (crossValLimit > 0) {
  log(`Processing ${crossValLimit} cross-validation tasks`)
  
  const crossValResults = await parallel(
    discovery.crossValReady.slice(0, crossValLimit).map(beadId => async () => {
      return await agent(`
Cross-validate bead: ${beadId}

Steps:
1. Claim: bd update ${beadId} --claim
2. Read description: bd show ${beadId}
3. Find the relevant test vectors
4. Run vectors through Python, Rust, AND Zephyr implementations
5. Compare outputs byte-for-byte where applicable
6. If all match, close: bd close ${beadId} --reason "Cross-validation passed"

If divergences found:
- Document the specific differences
- File a bug bead for each divergence
- Do NOT close this bead
`, {
        label: 'xval:' + beadId.split('.').pop(),
        phase: 'Validate',
        schema: {
          type: 'object',
          properties: {
            beadId: { type: 'string' },
            success: { type: 'boolean' },
            divergences: { type: 'array', items: { type: 'string' } },
            bugsField: { type: 'array', items: { type: 'string' } },
          },
          required: ['beadId', 'success']
        }
      })
    })
  )
  
  crossValClosed = crossValResults.filter(r => r?.success).length
  log(`Cross-validation: ${crossValClosed}/${crossValLimit} passed`)
}

// ─────────────────────────────────────────────────────────────
// Phase 5: Report
// ─────────────────────────────────────────────────────────────
phase('Report')

const report = await agent(`
Generate progress report for spec executor run.

Run: bd search "l1qw" --limit 200 and count by status.

Report:
- Beads closed this run: vectors=${vectorsClosed}, impls=${implsClosed}, crossval=${crossValClosed}
- Total closed vs total open under ${MASTER_EPIC}
- Any beads that need escalation (repeated failures)
- Recommended next steps
`, {
  label: 'report',
  schema: {
    type: 'object',
    properties: {
      thisRun: {
        type: 'object',
        properties: {
          vectorsClosed: { type: 'number' },
          implsClosed: { type: 'number' },
          crossValClosed: { type: 'number' },
        }
      },
      overall: {
        type: 'object',
        properties: {
          totalBeads: { type: 'number' },
          closed: { type: 'number' },
          open: { type: 'number' },
          percentComplete: { type: 'number' },
        }
      },
      escalations: { type: 'array', items: { type: 'string' } },
      nextSteps: { type: 'array', items: { type: 'string' } },
    },
    required: ['thisRun', 'overall']
  }
})

if (report) {
  log(`Run complete: ${report.thisRun.vectorsClosed + report.thisRun.implsClosed + report.thisRun.crossValClosed} beads closed`)
  log(`Overall: ${report.overall.percentComplete}% complete (${report.overall.closed}/${report.overall.totalBeads})`)
}

return {
  thisRun: {
    vectorsClosed,
    implsClosed,
    crossValClosed,
    total: vectorsClosed + implsClosed + crossValClosed,
  },
  overall: report?.overall,
  escalations: Array.from(failures.entries()).filter(([k, v]) => v >= MAX_FAILURES).map(([k]) => k),
  nextSteps: report?.nextSteps,
}
```
