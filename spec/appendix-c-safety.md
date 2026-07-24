<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# C Code Safety Policy

This document defines mandatory safety requirements for all C code in LICHEN.
C is used for the Zephyr firmware — the attack surface includes frame parsing,
cryptographic operations, and radio driver interaction.

## Compiler Hardening (Mandatory)

### Basic Flags

All C code MUST be compiled with these flags:

```cmake
# CMake: add to top-level CMakeLists.txt
add_compile_options(
    -Wall -Wextra -Werror
    -Wformat=2 -Wformat-security
    -Wshadow
    -Wconversion -Wsign-conversion
    -Wno-unused-parameter  # Zephyr callbacks often have unused params
    -fstack-protector-strong
)

# For native_sim builds only (not cross-compiled firmware)
if(CONFIG_BOARD_NATIVE_SIM OR CONFIG_BOARD_NATIVE_POSIX)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()
```

| Flag | Purpose |
|------|---------|
| `-Wall -Wextra -Werror` | All warnings as errors |
| `-Wformat=2 -Wformat-security` | Format string vulnerabilities |
| `-Wshadow` | Variable shadowing bugs |
| `-Wconversion -Wsign-conversion` | Implicit conversion bugs |
| `-fstack-protector-strong` | Stack buffer overflow detection |

### Advanced Hardening (Clang 18+)

When toolchain supports it, enable these advanced protections:

```cmake
# Control Flow Integrity - prevents ROP/JOP attacks
add_compile_options(-fsanitize=cfi -fvisibility=hidden)
add_link_options(-fsanitize=cfi)

# Bounds safety (Apple/LLVM extension)
add_compile_options(-fbounds-safety)

# Safe stack - separate stack for return addresses
add_compile_options(-fsanitize=safe-stack)
```

| Flag | Purpose |
|------|---------|
| `-fsanitize=cfi` | Control Flow Integrity — blocks ROP/JOP exploits |
| `-fbounds-safety` | Compile-time bounds checking (Clang 18+) |
| `-fsanitize=safe-stack` | Isolate return addresses from buffer overflows |

### Pointer Annotations (Mandatory for New Code)

All new code MUST use bounds annotations where applicable:

```c
// __counted_by - Clang 18+ flexible array member bounds
struct packet {
    uint16_t len;
    uint8_t data[] __counted_by(len);
};

// Nullability annotations
void process(_Nonnull const uint8_t *buf, size_t len);
_Nullable struct peer *find_peer(uint64_t id);

// GCC/Clang nonnull attribute (older compilers)
void send(const uint8_t *buf, size_t len) __attribute__((nonnull(1)));

// Buffer size annotations (function contracts)
void copy_frame(
    uint8_t *dest __attribute__((pass_object_size(0))),
    const uint8_t *src,
    size_t n
);
```

| Annotation | Purpose |
|------------|---------|
| `__counted_by(n)` | Bounds-check flexible array members at compile time |
| `_Nonnull` / `_Nullable` | Document and check null pointer contracts |
| `__attribute__((nonnull))` | Compiler warning on null arguments |
| `__attribute__((returns_nonnull))` | Promise non-null return value |
| `pass_object_size` | Enable `__builtin_object_size` bounds checks |

### Future: Hardware Memory Safety

When targeting capable hardware:

| Hardware | Technique | Status |
|----------|-----------|--------|
| ARM Cortex-A (v8.5+) | MTE (Memory Tagging Extension) | Use `-fsanitize=memtag` |
| ARM Morello | CHERI capabilities | Experimental |
| Intel (12th gen+) | CET shadow stack | Use `-fcf-protection=full` |

These are not yet applicable to Cortex-M (our primary target) but should be
enabled when LICHEN runs on Linux/application processors (border routers).

## Zephyr Safety Config (Mandatory)

All firmware builds MUST enable in prj.conf:

```ini
# Stack protection
CONFIG_STACK_CANARIES=y
CONFIG_STACK_SENTINEL=y

# Assertions (disable only in release with explicit justification)
CONFIG_ASSERT=y
CONFIG_ASSERT_VERBOSE=y

# Thread stack analysis (CI and debug builds)
CONFIG_THREAD_ANALYZER=y
CONFIG_THREAD_ANALYZER_USE_PRINTK=y
CONFIG_THREAD_ANALYZER_AUTO=n

# Heap validation (debug builds)
CONFIG_SYS_HEAP_VALIDATE=y
```

## Sanitizers (Mandatory for native_sim)

All tests run on native_sim MUST use AddressSanitizer and UndefinedBehaviorSanitizer:

```ini
# In test prj.conf or overlay
CONFIG_ASAN=y
CONFIG_UBSAN=y
```

Or via CMake for standalone tests:
```cmake
target_compile_options(${target} PRIVATE -fsanitize=address,undefined)
target_link_options(${target} PRIVATE -fsanitize=address,undefined)
```

ASan catches:
- Buffer overflows (stack, heap, global)
- Use-after-free
- Double-free
- Memory leaks

UBSan catches:
- Signed integer overflow
- Null pointer dereference
- Misaligned access
- Shift overflow

## Static Analysis (Mandatory in CI)

All C code MUST pass clang-tidy with this configuration:

```yaml
# .clang-tidy
Checks: >
  -*,
  bugprone-*,
  cert-*,
  clang-analyzer-*,
  misc-*,
  modernize-*,
  performance-*,
  readability-*,
  -readability-magic-numbers,
  -cert-dcl37-c,
  -cert-dcl51-cpp,
  -bugprone-easily-swappable-parameters
WarningsAsErrors: '*'
```

Run in CI:
```bash
clang-tidy --config-file=.clang-tidy lichen/subsys/lichen/**/*.c
```

### cppcheck (Mandatory)

cppcheck is the secondary static analyzer, complementary to clang-tidy. It
catches classes that clang-tidy misses: uninitialized variables, buffer
overflows, null pointer dereferences, and style issues.

Run in CI with curated suppressions for vendored code and Zephyr macro
noise:
```bash
cppcheck --error-exitcode=1 --enable=warning,style,performance \
  --suppress=missingIncludeSystem --inline-suppr \
  --suppressions-list=lichen/.cppcheck-suppressions lichen/
```

Suppressions are documented in `lichen/.cppcheck-suppressions`. Each entry
includes a rationale. Correctness classes (uninitvar, comparePointers,
syntaxError outside known files) always fail the build.

### Coverity Scan (Weekly)

Coverity Scan provides deeper static analysis than clang-tidy. It is free for
open-source projects and runs weekly via `.github/workflows/coverity.yml`.

**Setup (required once per fork):**

1. Register at https://scan.coverity.com/ using the GitHub repo URL
2. Add repository secrets in GitHub (Settings > Secrets > Actions):
   - `COVERITY_SCAN_TOKEN`: From Coverity project settings
   - `COVERITY_SCAN_EMAIL`: Email registered with Coverity

The workflow submits builds weekly and on manual trigger. Results are available
on the Coverity Scan dashboard (not inline in CI).

**Limitations:**
- Coverity Scan does not provide synchronous CI results (no fail-fast on defects)
- Review the dashboard manually after each weekly scan
- New high-severity issues should be addressed before release

## Fuzzing (Mandatory for Parsers)

All code that parses untrusted input MUST be fuzz-tested:

| Component | Input | Fuzzer |
|-----------|-------|--------|
| `frame.c` | Raw LoRa packets | AFL++/libFuzzer |
| `schnorr48.c` | Signatures | libFuzzer |
| `schc.c` | Compressed headers | AFL++ |

Fuzzing harness example:
```c
// fuzz_frame.c
#include "lichen/link/frame.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct lichen_frame frame;
    lichen_frame_parse(data, size, &frame);  // Must not crash
    return 0;
}
```

Build and run:
```bash
clang -fsanitize=fuzzer,address fuzz_frame.c -o fuzz_frame
./fuzz_frame corpus/
```

## Coding Rules (CERT C Subset)

Follow these CERT C rules. Violations are bugs.

### Memory Safety

| Rule | Summary |
|------|---------|
| ARR30-C | Do not form out-of-bounds pointers |
| ARR38-C | Guarantee array indices are within bounds |
| MEM30-C | Do not access freed memory |
| MEM35-C | Allocate sufficient memory for an object |
| STR31-C | Guarantee storage for strings has space for terminator |

### Integer Safety

| Rule | Summary |
|------|---------|
| INT30-C | Ensure unsigned operations do not wrap |
| INT32-C | Ensure signed operations do not overflow |
| INT33-C | Ensure division/remainder do not divide by zero |

### String Safety

**Never use these functions:**
- `strcpy`, `strcat`, `sprintf`, `gets`

**Always use these instead:**
- `strncpy` or `strlcpy` (if available)
- `strncat` or `strlcat`
- `snprintf`
- `fgets`

**Always check return values:**
```c
// WRONG
snprintf(buf, sizeof(buf), "%s", input);

// RIGHT
int ret = snprintf(buf, sizeof(buf), "%s", input);
if (ret < 0 || (size_t)ret >= sizeof(buf)) {
    // Handle truncation or error
}
```

### Buffer Size Rules

**Always pass explicit sizes:**
```c
// WRONG
void process(uint8_t *buf) { ... }

// RIGHT
void process(uint8_t *buf, size_t buf_len) { ... }
```

**Use sizeof on arrays, not pointers:**
```c
uint8_t buf[64];
memset(buf, 0, sizeof(buf));  // OK: sizeof(array) = 64

void func(uint8_t *buf) {
    memset(buf, 0, sizeof(buf));  // BUG: sizeof(pointer) = 8
}
```

## Cross-Validation (Mandatory)

All protocol logic in C MUST have equivalent tests that run against Python
and Rust implementations using shared test vectors.

Test vectors live in `spec/test-vectors/` as JSON:
```json
{
  "name": "frame_parse_minimal",
  "input_hex": "...",
  "expected": { "version": 1, "flags": 0, ... }
}
```

Each implementation loads the same vectors:
- Python: `pytest` with `@pytest.mark.parametrize`
- Rust: `#[test_case]` macro
- C: `ZTEST_F` with vector loader

A test that passes in one implementation but fails in another is a spec
violation — fix the code, not the test.

---

[Index](README.md)
