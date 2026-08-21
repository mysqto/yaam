#!/usr/bin/env bash
# Every gate CI enforces, runnable locally. Keep the two in lockstep: a gate that only exists in CI
# gets discovered late, and a gate that only exists here gets bypassed.
set -euo pipefail
cd "$(dirname "$0")/.."

# `yaam-bench` is compiled by fmt, clippy and test — so it cannot rot — but it is never run: it has
# no tests, and its one entry point is a `--release` binary that takes minutes and writes a few
# hundred megabytes. It is excluded from coverage because it is measurement code, not library code:
# counting a few hundred never-executed lines against the workspace figure would move the number
# without telling anyone anything about the library.
echo "── hygiene ──";  bash ci/hygiene.sh
echo "── fmt ──";      cargo fmt --all --check
echo "── clippy ──";   cargo clippy --workspace --all-targets -- -D warnings
echo "── test ──";     cargo test --workspace
echo "── coverage ──"; cargo llvm-cov --workspace --exclude yaam-bench \
                         --fail-under-lines 85 --summary-only
echo "all gates passed"
