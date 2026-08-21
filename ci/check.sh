#!/usr/bin/env bash
# Every gate CI enforces, runnable locally. Keep the two in lockstep: a gate that only exists in CI
# gets discovered late, and a gate that only exists here gets bypassed.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "── hygiene ──";  bash ci/hygiene.sh
echo "── fmt ──";      cargo fmt --all --check
echo "── clippy ──";   cargo clippy --workspace --all-targets -- -D warnings
echo "── schemas ──";  cargo xtask check
echo "── test ──";     cargo test --workspace
echo "── coverage ──"; cargo llvm-cov --workspace --fail-under-lines 85 --summary-only
echo "all gates passed"
