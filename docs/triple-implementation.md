# Triple Implementation: Python, Rust, Zephyr

## TL;DR

LICHEN maintains three co-equal implementations: Python, Rust, and Zephyr (C). This is not redundancy — it's a forcing function for specification quality. When implementations disagree, the spec decides. The spec can't hide behind "read the code."

---

## The Problem with One Implementation

Single-implementation projects drift toward "the code is the spec":

1. Ambiguous spec clause? Check what the code does.
2. Edge case undefined? Whatever the code does is "correct."
3. Bug or feature? Who knows — it's been there for years.

The implementation becomes the oracle. The spec rots into documentation. New implementations must bug-for-bug match the original.

---

## The Three Implementations

| Language | Role | Strengths |
|----------|------|-----------|
| **Python** | Simulator, test oracle, rapid prototyping | Readable, fast iteration, runs the network simulator |
| **Rust** | Gateway, high-performance nodes, no-std embedded | Memory safety, performance, catches C-like bugs at compile time |
| **Zephyr (C)** | Resource-constrained nodes, real hardware | Runs on 32KB RAM, direct hardware access, production firmware |

Each implementation is written independently. They share:
- The spec (normative)
- Test vectors (normative)
- Nothing else

### Python: The Thinking Language

Python is where ideas become concrete first. Its value:

**Readability as specification check.** If you can't express the algorithm clearly in Python, the spec is too convoluted. Python code should read like pseudocode. When it doesn't, simplify the spec.

**Dynamic typing surfaces ambiguity.** Python doesn't force you to decide "is this an int or a float?" up front. When you find yourself adding type checks, that's a sign the spec didn't nail down the types.

**Rapid iteration.** Change a line, run it, see results. No compile step. The feedback loop is seconds, not minutes. This matters for exploring edge cases.

**The simulator runs Python.** The network simulator that tests multi-node behavior is Python. The "ground truth" for protocol interactions lives here.

```python
# Python: intent is clear, details are implicit
def compress_ipv6(addr, context):
    if addr.startswith(context.prefix):
        return elide_prefix(addr, context)
    return addr  # uncompressed
```

### Rust: The Pedantic Language

Rust forces you to answer questions Python let you ignore:

**Ownership and lifetimes.** Who owns this buffer? How long does it live? When is it freed? Python's GC hides this. Rust makes you decide. This surfaces spec gaps like "who deallocates the reassembly buffer?"

**Error handling is explicit.** Every fallible operation returns `Result<T, E>`. You can't forget to handle errors — the compiler won't let you. This finds spec clauses that forgot to define error behavior.

**No null.** `Option<T>` forces you to handle the "not present" case. Spec clauses that assume "this field is always present" get challenged.

**No-std compatibility.** Rust can run without a standard library, without an allocator, on bare metal. If the algorithm requires heap allocation, you discover it here. That might mean the spec is too expensive for constrained nodes.

```rust
// Rust: every question answered explicitly
fn compress_ipv6(addr: &Ipv6Addr, context: &Context) -> Result<Compressed, Error> {
    if addr.segments()[..4] == context.prefix {
        Ok(Compressed::Elided(elide_prefix(addr, context)?))
    } else {
        Ok(Compressed::Full(*addr))
    }
}
```

### Zephyr (C): The Honest Language

C doesn't protect you. That's the point:

**Manual memory management.** Every malloc needs a free. Every buffer needs a size. There's no safety net. If the spec assumes infinite memory, C will teach you otherwise.

**Fixed-size buffers.** You can't just `vec.push()`. You allocate a fixed buffer and check bounds. This forces the spec to define maximum sizes. "Up to 64 entries" becomes a real constraint.

**No exceptions.** Error handling is return codes, checked manually. Every function signature asks: "what errors can this return?" If the spec doesn't say, you have to decide.

**Real hardware constraints.** 32KB RAM. 256KB flash. 64MHz CPU. If your algorithm doesn't fit, you simplify the spec — not buy a bigger chip.

**Interrupt-driven I/O.** Packets arrive in ISRs. You can't block. You can't allocate. The spec's "wait for response" becomes "register callback, return immediately, handle response later."

```c
// C: nothing is free, everything is explicit
int compress_ipv6(const uint8_t *addr, const context_t *ctx, 
                  uint8_t *out, size_t out_len, size_t *written) {
    if (memcmp(addr, ctx->prefix, 8) == 0) {
        if (out_len < ELIDED_SIZE) return -ENOBUFS;
        *written = elide_prefix(addr, ctx, out);
        return 0;
    }
    if (out_len < 16) return -ENOBUFS;
    memcpy(out, addr, 16);
    *written = 16;
    return 0;
}
```

### The Triad Forces Completeness

| Question | Python's Answer | Rust's Answer | C's Answer |
|----------|-----------------|---------------|------------|
| Who owns this buffer? | GC handles it | Explicit ownership | Explicit malloc/free |
| What if allocation fails? | Exception | Result::Err | Return -ENOMEM |
| What's the max size? | Unbounded list | Vec (heap) or array | Fixed buffer, compile-time |
| What if the field is missing? | None / KeyError | Option::None | NULL pointer or sentinel |
| How do we handle async? | asyncio / await | tokio / async-await | Callbacks, work queues |

A spec that works in all three languages has answered all these questions. A spec that only works in Python has hidden them.

---

## How Disagreement Surfaces Bugs

When Python and Rust produce different outputs for the same input:

1. **Check the spec.** Does it define this case?
2. **If yes:** One implementation is wrong. Fix it.
3. **If no:** The spec is incomplete. Fix it, then fix implementations.

Neither implementation "wins" by default. The spec is the arbiter.

### Real Example: RPL DAO Transit E-flag

```
Python:  E-flag set when path cost increases
Rust:    E-flag set on any path change
Zephyr:  E-flag never set (stub implementation)
```

Spec check: "E-flag MUST be set when the path error metric increases."

Result:
- Rust was wrong (any change ≠ increase)
- Zephyr was wrong (stub)
- Python was right
- Spec was clear — no spec fix needed

Without three implementations, Rust's bug ships. Users discover it in production when interoperating with other RPL stacks.

---

## Test Vectors: The Shared Ground Truth

Implementations don't test against each other. They test against shared vectors:

```
test/vectors/
├── schc-compression.json    # Input packets → compressed output
├── rpl-dao.json             # DAO messages, expected parsing
├── oscore-encrypt.json      # Plaintext → ciphertext (known keys)
├── ccp16-desync.json        # CCP state machine transitions
└── ...
```

Each vector file contains:
- Inputs (hex, structured data)
- Expected outputs
- Edge cases with rationale

A passing test suite means: "This implementation matches the spec's intent as encoded in vectors."

### Vector-Driven Development

1. Write spec clause
2. Write test vector encoding that clause
3. Implement in Python (fast iteration)
4. Implement in Rust (catches different bugs)
5. Implement in Zephyr (resource constraints force simplification)
6. All three pass the same vectors

If you can't write a vector for a spec clause, the clause is too vague.

---

## What Each Language Catches

### Python Catches
- Spec ambiguities (you hit them first while prototyping)
- Algorithm correctness (easy to debug, print, inspect)
- Protocol state machine bugs (simulator visualizes them)

### Rust Catches
- Memory bugs (use-after-free, buffer overflows)
- Concurrency bugs (data races, deadlocks)
- Type confusion (the compiler is strict)
- Integer overflow (explicit wrapping required)

### Zephyr (C) Catches
- Resource exhaustion (runs on real constrained hardware)
- Alignment issues (packed structs, DMA)
- Timing bugs (real interrupts, real radio timing)
- Code size issues (won't fit in flash? simplify the spec)

Bugs that escape all three are genuinely rare.

---

## The Cost

Yes, it's 3x the implementation work. But:

| Cost | Mitigation |
|------|------------|
| 3x code | Shared test vectors mean you're not writing 3x tests |
| 3x maintenance | Spec changes are discovered in one impl, fixed in all |
| 3x debugging | Bugs are usually in one impl, comparison finds them fast |
| Coordination overhead | Beads track per-language tasks under shared epics |

And the return:

| Benefit | Value |
|---------|-------|
| Spec quality | Forces precision; ambiguity breaks implementations |
| Bug detection | Two implementations finding the same bug = spec bug |
| Confidence | "Works in 3 languages" > "works in 1 language" |
| Interoperability | Real protocol stacks will vary; you've already tested that |

---

## When Implementations Should Differ

Not everything is identical. Language-appropriate idioms are fine:

| Aspect | Python | Rust | Zephyr |
|--------|--------|------|--------|
| Error handling | Exceptions | Result<T, E> | Return codes |
| Memory | GC | Ownership | Static allocation |
| Async | asyncio | tokio | Zephyr work queues |
| Logging | logging module | tracing | printk / LOG_* |

The **protocol behavior** must match. The **implementation idiom** should be native to each language.

---

## Anti-Patterns

### "Port" Mentality
Wrong: "Port the Python to Rust line by line."
Right: "Implement the spec in idiomatic Rust."

Ports inherit bugs. Fresh implementations find spec bugs.

### Reference Implementation
Wrong: "Python is the reference. Match its bugs."
Right: "Test vectors are the reference. Match them."

### Skipping Languages
Wrong: "Zephyr is hard. We'll do it later."
Right: "Zephyr constraints inform spec simplification. Do it now."

The third implementation always finds bugs the first two missed.

---

## Why Not Separate Language-Specialist Agents?

You might think: "Use a Python expert agent for Python, a Rust expert for Rust, a C expert for C." This is wrong. Here's why.

### The Spec Is the Skill, Not the Syntax

The hard part of implementing LICHEN isn't "how do I write a for-loop in Rust." It's:

- What does the spec mean by "SHOULD retry with exponential backoff"?
- When the DAO says "path lifetime," does that include the initial hop?
- Is this field big-endian or little-endian?

A "Rust specialist" agent doesn't know LICHEN. A generalist agent that has read the spec and implemented it in Python *does* know LICHEN. When that same agent implements in Rust, it carries the understanding forward.

### Cross-Language Context Prevents Bugs

When one agent implements all three languages:

```
Agent thinks: "In Python I did X because the spec says Y. 
              In Rust, I need to do X differently because of ownership,
              but the *meaning* must stay the same."
```

When separate agents implement each language:

```
Python agent: "I'll do X."
Rust agent: "I'll do Z, seems right."
C agent: "I'll do W, the spec is unclear."
```

Three agents, three interpretations, no shared understanding. The bugs aren't caught until integration — too late.

### The Agent Must Feel the Friction

When a single agent implements in C after Python, it experiences:

- "This was easy in Python but hard in C. Why?"
- "I need to preallocate a buffer. What's the max size? Spec doesn't say."
- "Python raised an exception here. What return code should C use?"

These questions surface spec gaps. The agent notices them *because* it just did the easy version. A C-only agent doesn't know it's hard — it's always hard.

### Specialist Agents Fragment Knowledge

If PyAgent implements Python, RustAgent implements Rust, and CAgent implements C:

- Who notices when behaviors diverge?
- Who decides which interpretation is correct?
- Who updates the spec when a gap is found?

You'd need a fourth "coordinator" agent to reconcile disagreements. That coordinator would need to understand all three languages *and* the spec. At that point, just use one generalist agent.

### Empirical Evidence from This Run

Our agents work on beads like:

```
epic: CCP-8 Channel Hopping
├── task: Python implementation
├── task: Rust implementation  
├── task: Zephyr implementation
└── task: Test vectors
```

The same agent often claims multiple child tasks. When it does:

- It implements Python first (fast feedback)
- It ports understanding to Rust (catches ownership issues)
- It implements C last (catches resource constraints)
- It notices when its implementations disagree

When different agents claim each task:

- More coordination overhead
- More "I assumed X" / "I assumed Y" conflicts
- Codereview catches bugs instead of the agent itself

**One agent, three languages** > **three agents, one language each**

### The Real Specialist Knowledge

What would actually help is **domain specialists**, not language specialists:

| Useful Specialist | Why |
|-------------------|-----|
| Crypto agent | OSCORE, EDHOC, Schnorr — get the subtle bits right |
| Compression agent | SCHC rules, bit packing, context matching |
| Routing agent | RPL, DAO, DIO, DODAG — complex state machines |

These specialists know *what* to implement. The language is just *how*. An agent that deeply understands SCHC can implement it in any language. An agent that deeply understands Rust but not SCHC will write beautiful wrong code.

### Summary: Language Is Incidental

The goal is correct protocol implementation. Language is incidental.

- Spec knowledge transfers across languages
- Implementation friction surfaces spec gaps
- Cross-language context catches divergence early
- One agent seeing all three languages > three agents seeing one

Don't fragment by language. Fragment by protocol domain if you must fragment at all.

---

## Practical Workflow

1. **Spec change proposed** → Write vector first
2. **Vector written** → Implement in Python (fastest feedback)
3. **Python passes** → Implement in Rust (catches memory/type bugs)
4. **Rust passes** → Implement in Zephyr (catches resource bugs)
5. **All pass** → Spec change is complete

If any implementation struggles:
- Is the spec too complex? Simplify.
- Is the vector wrong? Fix it.
- Is the implementation wrong? Fix it.

Never: "Ship it, the other impls can catch up later."

---

## Effect on AI Code Generation

Triple implementation changes how AI agents write code — for the better.

### Forces Spec-First Thinking

With one implementation, the agent's instinct is:
```
"Find similar code in the codebase → adapt it"
```

With three implementations, the agent must:
```
"Read the spec → understand the requirement → implement idiomatically"
```

The agent can't copy-paste Python into Rust. It has to understand what the code *does*, then express it in a different language. This forces comprehension over pattern matching.

### Cross-Validation Catches Agent Mistakes

When an agent implements a feature wrong:
- **Single impl:** Bug ships. Discovered in production.
- **Triple impl:** Second implementation disagrees. Bug caught immediately.

The agent gets fast feedback: "Your Rust doesn't match your Python. One is wrong." This is better than "tests pass, ship it" followed by silent corruption.

### Test Vectors Anchor Correctness

Agents love to write code that "looks right" but doesn't actually work. Test vectors force:

1. Agent writes code
2. Vector test fails
3. Agent must actually fix the bug

No amount of confident-sounding explanation survives a failing vector. The agent can't argue with `expected: 0x4A, got: 0x4B`.

### Prevents "Implementation as Oracle"

Without vectors, agents do this:
```python
def test_encrypt():
    result = encrypt(data, key)
    assert result == encrypt(data, key)  # Tautology!
```

With cross-implementation vectors:
```python
def test_encrypt():
    result = encrypt(data, key)
    assert result == KNOWN_VECTOR_OUTPUT  # External oracle
```

The agent can't use its own code as the test oracle. It must match an independent source of truth.

### Idiom Diversity Improves Understanding

An agent that implements the same algorithm in:
- Python (high-level, GC, exceptions)
- Rust (ownership, Result types, no-std)
- C (manual memory, return codes, fixed buffers)

...actually understands the algorithm. It's not just shuffling syntax. Each language forces different design decisions, and the agent must reason about them.

### Empirical Observation

During this multi-agent run:
- Agents frequently caught their own mistakes when the second/third impl diverged
- Codereview passes found "works in Python, wrong in Rust" bugs
- Spec ambiguities surfaced when agents asked "which behavior is correct?"

The three-language constraint turned sloppy generation into rigorous implementation.

---

## Summary

Three implementations is not 3x the work for 1x the result. It's:

- **1x spec work** (shared, must be precise)
- **1x vector work** (shared, normative)
- **3x impl work** (but each finds different bugs)
- **>3x confidence** (interop tested by construction)

The spec becomes load-bearing. "Read the code" stops being an acceptable answer. Protocol bugs surface before production.

When Python, Rust, and Zephyr all pass the same vectors, you're shipping a protocol — not just a program.
