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
# Again with every feature on, because `crash-points` gates code the run above cannot see: the crash
# test is `required-features` and its checkpoints compile out. Without this, the instrumentation
# would be lint-checked by nobody until it had already rotted.
echo "── features ──"; cargo clippy --workspace --all-targets --all-features -- -D warnings
echo "── schemas ──";  cargo xtask check
echo "── test ──";     cargo test --workspace
# The crash tests kill a real service at each durability window and then wait on a restarted one's
# own maintenance timer, which takes minutes. They are `#[ignore]`d out of the run above and named
# here instead — gated rather than optional, because an untested crash window is the one that costs
# a record.
#
# `--features crash-points` builds the checkpoints into the binaries this test spawns; they are
# compiled out of everything else, this run included. The test target declares the feature in
# `required-features`, so dropping the flag fails the build rather than quietly running a test that
# can no longer stop a process in a window.
echo "── crash ──";    cargo test -p yaam-cli --features crash-points \
                         --test crash_injection -- --ignored
echo "── coverage ──"; cargo llvm-cov --workspace --exclude yaam-bench \
                         --fail-under-lines 85 --summary-only
echo "all gates passed"
