#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
#
# C static analysis: cppcheck + clang-tidy
# Usage: ./scripts/lint-c.sh [files...]
#        ./scripts/lint-c.sh           # lint all C files
#        ./scripts/lint-c.sh --staged  # lint staged files only (for pre-commit)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LICHEN_DIR="$PROJECT_ROOT/lichen"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Collect files to lint
if [[ "$1" == "--staged" ]]; then
    FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(c|h)$' | grep '^lichen/' || true)
    if [[ -z "$FILES" ]]; then
        echo -e "${GREEN}No staged C files to lint${NC}"
        exit 0
    fi
elif [[ $# -gt 0 ]]; then
    FILES="$*"
else
    FILES=$(find "$LICHEN_DIR/subsys" "$LICHEN_DIR/lib" "$LICHEN_DIR/drivers" -name '*.c' 2>/dev/null || true)
fi

if [[ -z "$FILES" ]]; then
    echo -e "${YELLOW}No C files found${NC}"
    exit 0
fi

ERRORS=0

# Run cppcheck
echo -e "${YELLOW}Running cppcheck...${NC}"
if command -v cppcheck &>/dev/null; then
    if ! cppcheck --enable=warning,style,performance,portability \
        --error-exitcode=1 \
        --inline-suppr \
        --suppress=missingIncludeSystem \
        --suppress=unmatchedSuppression \
        --suppress=syntaxError \
        --std=c11 \
        -I "$LICHEN_DIR/include" \
        -I "$LICHEN_DIR/subsys/lichen" \
        $FILES 2>&1; then
        ERRORS=$((ERRORS + 1))
    fi
    echo -e "${GREEN}cppcheck: done${NC}"
else
    echo -e "${RED}cppcheck not installed (brew install cppcheck)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Run clang-tidy
echo -e "${YELLOW}Running clang-tidy...${NC}"
if command -v clang-tidy &>/dev/null; then
    for f in $FILES; do
        if [[ "$f" == *.c ]]; then
            if ! clang-tidy "$f" \
                --config-file="$LICHEN_DIR/.clang-tidy" \
                -p /dev/null \
                -- -I "$LICHEN_DIR/include" -I "$LICHEN_DIR/subsys/lichen" -std=c11 2>&1; then
                ERRORS=$((ERRORS + 1))
            fi
        fi
    done
    echo -e "${GREEN}clang-tidy: done${NC}"
else
    echo -e "${RED}clang-tidy not installed (brew install llvm)${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}Lint failed with $ERRORS error(s)${NC}"
    exit 1
fi

echo -e "${GREEN}All C lint checks passed${NC}"
