# Spec Executor Workflow

Draft design for automated execution of the 1,767 spec implementation beads.

## Problem

Standard `bd ready → claim → work → close` loop doesn't handle:
- Dependencies (vectors before impls, impls before cross-validation)
- Parallelization (chapters can run in parallel, tasks within chapter have ordering)
- Thruline gates (cross-chapter validation)
- Escalation (stop burning tokens on stuck work)
- Progress tracking (where are we, what's blocked)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SPEC EXECUTOR                           │
├─────────────────────────────────────────────────────────────┤
│  Phase 1: Discover    - Load bead graph, compute DAG       │
│  Phase 2: Vectors     - Generate test vectors (unblocks)   │
│  Phase 3: Implement   - Per-language tasks in parallel     │
│  Phase 4: Validate    - Cross-validation gates             │
│  Phase 5: Thrulines   - Cross-chapter verification         │
├─────────────────────────────────────────────────────────────┤
│  Escalation: 3 failures on same bead → pause + surface     │
│  Budget: configurable token cap per phase                  │
└─────────────────────────────────────────────────────────────┘
```

## Dependency Rules

Within each chapter epic, execution order is:

1. **Vectors first** — `Vectors: X test vectors` tasks
2. **Implementations** — `Python: X`, `Rust: X`, `Zephyr: X` (parallel)
3. **Cross-validation** — `Cross-validate: X parity` (blocks on all impls)

Sub-epics follow same pattern recursively.

Thrulines run after all referenced chapters reach implementation phase.

## Workflow Script

```javascript
export const meta = {
  name: 'spec-executor',
  description: 'Execute spec implementation beads across all chapters',
  phases: [
    { title: 'Discover', detail: 'Load bead graph, identify ready work' },
    { title: 'Vectors', detail: 'Generate test vectors for unblocked chapters' },
    { title: 'Implement', detail: 'Run per-language implementation tasks' },
    { title: 'Validate', detail: 'Cross-validation gates' },
    { title: 'Thrulines', detail: 'Cross-chapter verification' },
  ],
}

const MASTER_EPIC = 'project-LICHEN-worker6-l1qw'
const MAX_FAILURES = 3
const CHAPTERS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] // .1 through .10
const THRULINES = [11, 12, 13, 14] // .11 through .14

// Track failures per bead
const failures = new Map()

// ─────────────────────────────────────────────────────────────
// Phase 1: Discover
// ─────────────────────────────────────────────────────────────
phase('Discover')

const discovery = await agent(`
  Analyze the bead structure under ${MASTER_EPIC}.
  
  For each chapter epic (.1 through .10), identify:
  1. Vector tasks (title contains "Vectors:")
  2. Implementation tasks (title contains "Python:" or "Rust:" or "Zephyr:")
  3. Cross-validation tasks (title contains "Cross-validate:")
  4. Current status (open/in_progress/closed)
  
  Return a structured summary of what's ready to work on.
  A task is ready if:
  - It's open (not closed, not in_progress)
  - Its parent epic is not closed
  - For impl tasks: corresponding vector task is closed OR doesn't exist
  - For cross-val tasks: all impl tasks in same epic are closed
  
  Use: bd show ${MASTER_EPIC} and bd search commands.
`, {
  label: 'discover',
  schema: {
    type: 'object',
    properties: {
      chapters: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            vectorsReady: { type: 'array', items: { type: 'string' } },
            implsReady: { type: 'array', items: { type: 'string' } },
            crossValReady: { type: 'array', items: { type: 'string' } },
            blocked: { type: 'array', items: { type: 'string' } },
          }
        }
      },
      thrulines: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            ready: { type: 'boolean' },
            blockedBy: { type: 'array', items: { type: 'string' } },
          }
        }
      },
      summary: {
        type: 'object',
        properties: {
          totalBeads: { type: 'number' },
          closed: { type: 'number' },
          ready: { type: 'number' },
          blocked: { type: 'number' },
        }
      }
    },
    required: ['chapters', 'summary']
  }
})

log(`Discovered: ${discovery.summary.totalBeads} beads, ${discovery.summary.ready} ready, ${discovery.summary.closed} closed`)

// ─────────────────────────────────────────────────────────────
// Phase 2: Vectors
// ─────────────────────────────────────────────────────────────
phase('Vectors')

const allVectorTasks = discovery.chapters.flatMap(ch => 
  ch.vectorsReady.map(id => ({ id, chapter: ch.name }))
)

if (allVectorTasks.length > 0) {
  log(`Processing ${allVectorTasks.length} vector tasks`)
  
  const vectorResults = await parallel(
    allVectorTasks.slice(0, 10).map(task => async () => {
      const result = await agent(`
        Work on bead ${task.id} (test vectors for ${task.chapter}).
        
        1. Claim: bd update ${task.id} --claim
        2. Read the bead description for requirements
        3. Check existing vectors in test/vectors/
        4. Create or complete the required test vectors
        5. Ensure vectors are valid JSON with proper schema
        6. Close: bd close ${task.id} --reason "Vectors created/completed"
        
        If you cannot complete the work, explain why and do NOT close the bead.
      `, {
        label: `vectors:${task.id}`,
        phase: 'Vectors',
        schema: {
          type: 'object',
          properties: {
            beadId: { type: 'string' },
            success: { type: 'boolean' },
            vectorsCreated: { type: 'array', items: { type: 'string' } },
            error: { type: 'string' },
          },
          required: ['beadId', 'success']
        }
      })
      return result
    })
  )
  
  const succeeded = vectorResults.filter(r => r?.success).length
  const failed = vectorResults.filter(r => r && !r.success).length
  log(`Vectors: ${succeeded} succeeded, ${failed} failed`)
}

// ─────────────────────────────────────────────────────────────
// Phase 3: Implement
// ─────────────────────────────────────────────────────────────
phase('Implement')

// Group impl tasks by chapter for parallel execution
const implByChapter = {}
for (const ch of discovery.chapters) {
  if (ch.implsReady.length > 0) {
    implByChapter[ch.id] = ch.implsReady
  }
}

// Run chapters in parallel, tasks within chapter in parallel
const chapterResults = await parallel(
  Object.entries(implByChapter).slice(0, 5).map(([chapterId, tasks]) => async () => {
    const results = await parallel(
      tasks.slice(0, 5).map(taskId => async () => {
        // Check failure count
        const failCount = failures.get(taskId) || 0
        if (failCount >= MAX_FAILURES) {
          log(`Skipping ${taskId}: ${failCount} prior failures`)
          return { beadId: taskId, success: false, error: 'max failures reached' }
        }
        
        const result = await agent(`
          Implement bead ${taskId}.
          
          1. Claim: bd update ${taskId} --claim
          2. Read the bead description for requirements
          3. Find the relevant source files
          4. Implement the feature/fix
          5. Run tests to verify
          6. If tests pass, close: bd close ${taskId} --reason "Implemented and tested"
          
          If you cannot complete, explain why and do NOT close.
        `, {
          label: `impl:${taskId}`,
          phase: 'Implement',
          schema: {
            type: 'object',
            properties: {
              beadId: { type: 'string' },
              success: { type: 'boolean' },
              filesChanged: { type: 'array', items: { type: 'string' } },
              testsRun: { type: 'boolean' },
              error: { type: 'string' },
            },
            required: ['beadId', 'success']
          }
        })
        
        if (!result?.success) {
          failures.set(taskId, failCount + 1)
        }
        return result
      })
    )
    return { chapterId, results }
  })
)

// Summarize implementation results
let implSucceeded = 0, implFailed = 0
for (const ch of chapterResults.filter(Boolean)) {
  for (const r of ch.results.filter(Boolean)) {
    if (r.success) implSucceeded++
    else implFailed++
  }
}
log(`Implement: ${implSucceeded} succeeded, ${implFailed} failed`)

// ─────────────────────────────────────────────────────────────
// Phase 4: Validate (Cross-validation)
// ─────────────────────────────────────────────────────────────
phase('Validate')

// Re-discover to find newly ready cross-val tasks
const postImplDiscovery = await agent(`
  Check which cross-validation tasks are now ready under ${MASTER_EPIC}.
  A cross-val task is ready if all impl tasks in the same epic are closed.
  
  Return list of ready cross-val bead IDs.
`, {
  label: 'discover-crossval',
  schema: {
    type: 'object',
    properties: {
      ready: { type: 'array', items: { type: 'string' } },
    },
    required: ['ready']
  }
})

if (postImplDiscovery.ready.length > 0) {
  log(`Running ${postImplDiscovery.ready.length} cross-validation tasks`)
  
  const crossValResults = await parallel(
    postImplDiscovery.ready.slice(0, 5).map(taskId => async () => {
      return await agent(`
        Run cross-validation for bead ${taskId}.
        
        1. Claim the bead
        2. Run the same test vectors through Python, Rust, and Zephyr
        3. Compare outputs for parity
        4. Document any divergences
        5. If all match, close the bead
        6. If divergences found, file bugs and do NOT close
      `, {
        label: `crossval:${taskId}`,
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
  
  const cvSucceeded = crossValResults.filter(r => r?.success).length
  log(`Cross-validation: ${cvSucceeded}/${postImplDiscovery.ready.length} passed`)
}

// ─────────────────────────────────────────────────────────────
// Phase 5: Thrulines
// ─────────────────────────────────────────────────────────────
phase('Thrulines')

// Check if any thrulines are ready (all referenced chapters have closed impl tasks)
const thrulineStatus = await agent(`
  Check thruline readiness under ${MASTER_EPIC}.
  
  Thrulines (.11 through .14) are ready when their referenced chapters have
  sufficient implementation progress (>80% impl tasks closed).
  
  Return which thrulines are ready and their sub-tasks.
`, {
  label: 'discover-thrulines',
  schema: {
    type: 'object',
    properties: {
      ready: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            tasks: { type: 'array', items: { type: 'string' } },
          }
        }
      },
      notReady: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            blockedBy: { type: 'string' },
          }
        }
      },
    },
    required: ['ready', 'notReady']
  }
})

if (thrulineStatus.ready.length > 0) {
  log(`Running ${thrulineStatus.ready.length} ready thrulines`)
  
  // Run ready thrulines
  await parallel(
    thrulineStatus.ready.map(thruline => async () => {
      return await agent(`
        Execute thruline ${thruline.id}: ${thruline.name}
        
        This is a cross-chapter verification. Work through the sub-tasks:
        ${thruline.tasks.join(', ')}
        
        For each task:
        1. Claim it
        2. Verify the cross-impl behavior
        3. Close if passing, file bugs if not
      `, {
        label: `thruline:${thruline.id}`,
        phase: 'Thrulines',
      })
    })
  )
} else {
  log(`No thrulines ready. Blocked: ${thrulineStatus.notReady.map(t => t.name).join(', ')}`)
}

// ─────────────────────────────────────────────────────────────
// Final Summary
// ─────────────────────────────────────────────────────────────
const finalSummary = await agent(`
  Generate final progress report for ${MASTER_EPIC}.
  
  Count:
  - Total beads
  - Closed beads
  - In-progress beads
  - Open beads
  - Per-chapter breakdown
  
  List any beads that hit max failures (escalation needed).
`, {
  label: 'final-summary',
  schema: {
    type: 'object',
    properties: {
      total: { type: 'number' },
      closed: { type: 'number' },
      inProgress: { type: 'number' },
      open: { type: 'number' },
      escalations: { type: 'array', items: { type: 'string' } },
      chapterProgress: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            percent: { type: 'number' },
          }
        }
      }
    },
    required: ['total', 'closed', 'open']
  }
})

log(`Final: ${finalSummary.closed}/${finalSummary.total} closed (${Math.round(100*finalSummary.closed/finalSummary.total)}%)`)

if (finalSummary.escalations.length > 0) {
  log(`ESCALATIONS NEEDED: ${finalSummary.escalations.join(', ')}`)
}

return {
  summary: finalSummary,
  failures: Object.fromEntries(failures),
}
```

## Invocation

```bash
# Run one iteration (vectors + some impls)
claude --workflow spec-executor

# Run with token budget
claude --workflow spec-executor +500k

# Run specific chapter only
claude --workflow spec-executor --args '{"chapters": [3]}'
```

## Iteration Strategy

Don't try to close all 1,767 beads in one run. Instead:

1. **Run 1:** Vectors phase for all chapters (~100 beads)
2. **Run 2-5:** Implementation phase, 2-3 chapters per run (~300 beads/run)
3. **Run 6-7:** Cross-validation gates
4. **Run 8:** Thrulines
5. **Ongoing:** Re-run on open beads until convergence

Each run should be ~500k-1M tokens. Total estimate: 5-10M tokens for full spec.

## Monitoring

Watch `/workflows` during execution. Key signals:
- Agent stuck in loop → likely blocked on missing vector
- Same bead failing repeatedly → escalation, needs human
- Cross-val failing → implementations diverged, need investigation

## Open Questions

1. **Commit strategy** — commit per bead? per chapter? per phase?
2. **Test execution** — run full test suite or just affected tests?
3. **Worktree isolation** — each impl agent in its own worktree to avoid conflicts?
4. **Human checkpoints** — pause for review after each phase?
