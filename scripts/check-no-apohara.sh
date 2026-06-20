#!/usr/bin/env bash
# scripts/check-no-apohara.sh — AC11 hardening (R11).
#
# THEMIS must NOT depend on any other `apohara_*` crate. This script
# greps the workspace (excluding this script itself + the legacy
# `.archive/` dir + vendored fixtures) and exits 1 if any
# `use apohara_` import, `apohara_` Cargo path-dep, or `apohara-*`
# binary name is found.
#
# Installed automatically by scripts/install-pre-commit.sh; runs in
# the pre-commit hook before every commit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Patterns we ban:
#   - use apohara_xxx::...
#   - use apohara::...
#   - apohara_xxx = ... (in Cargo.toml, but only in path/git
#     deps, since the workspace itself is themis_* and the
#     apohara- branding appears in the apohara-themis repo
#     name; this catches cross-crate pollution)
# We allow:
#   - The repo's own name (apohara-themis, apohara-dev, etc.)
#     appearing in URLs, .claude/, .gitignore, etc.
#   - The legacy `.archive/pre-themis/` (pre-hackathon dev snapshot)

VIOLATIONS=0

# 1. Rust source: any `use apohara_` import
#    Allow-list (C-17 / C-02 + C-10): the two upstream crates
#    `apohara_agentguard` and `apohara_sealchain_core` are
#    legitimate workspace deps. Any other `use apohara_*` is
#    rejected. The allow-list matches both `use` statements and
#    fully-qualified `apohara_xxx::yyy` paths.
echo "Checking Rust source for 'use apohara_' imports (allow-list: agentguard, sealchain-core)..."
FORBIDDEN_IMPORTS=$(grep -rEn '(use[[:space:]]+apohara)|(apohara[_a-zA-Z0-9]*[[:space:]]*::)' crates/ \
    --exclude-dir=.omc \
    --exclude-dir=target \
    --exclude-dir=.venv \
    --exclude-dir=node_modules 2>/dev/null \
    | grep -Ev 'apohara_(agentguard|sealchain_core)' \
    || true)
if [ -n "$FORBIDDEN_IMPORTS" ]; then
    echo "$FORBIDDEN_IMPORTS" >&2
    echo "✗ Found non-allow-listed apohara_ imports in Rust source" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo "  ✓ no non-allow-listed apohara_ imports in crates/"
fi

# 2. Cargo.toml path/git dependencies on apohara-*
#    Allow-list (C-17 / C-02 + C-10): the workspace is allowed
#    to depend on TWO specific apohara-* path crates that are
#    hard requirements of the spec:
#      - apohara-agentguard      (C-02 / G15,G18,G33) — seccomp+Landlock sandbox
#      - apohara-sealchain-core  (C-10 / G30)         — C2PA seal wrapper
#    Every OTHER `apohara-*` path/git dep is rejected. This
#    keeps the dependency surface minimal while honoring the
#    two non-negotiable upstream crates.
echo "Checking Cargo.toml for apohara- path dependencies (allow-list: agentguard, sealchain-core)..."
FORBIDDEN_DEPS=$(grep -rEn 'apohara-?[a-zA-Z0-9_-]*\s*=\s*\{' crates/ 2>/dev/null \
    | grep -Ev 'apohara-(agentguard|sealchain-core)\s*=' \
    || true)
if [ -n "$FORBIDDEN_DEPS" ]; then
    echo "$FORBIDDEN_DEPS" >&2
    echo "✗ Found non-allow-listed apohara-* path deps in Cargo.toml" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo "  ✓ no non-allow-listed apohara-* path deps"
fi

# 3. Binary names matching apohara-*
echo "Checking for apohara-* binaries in workspace Cargo.toml..."
if grep -rEn 'name\s*=\s*"apohara-' crates/ 2>/dev/null; then
    echo "✗ Found apohara-* binary name" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo "  ✓ no apohara-* binary names"
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo
    echo "AC11 violation: $VIOLATIONS check(s) failed"
    exit 1
fi

echo
echo "✓ AC11 clean: no apohara_* imports, path deps, or binary names"
exit 0
