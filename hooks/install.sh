#!/usr/bin/env bash
# Installs the pre-commit guard into a repository that keeps a memory store's backup.
#
# The hook itself comes from `yaam guard-commit --print-hook`, so there is one copy of the script and
# it is the one the binary was built with.
#
# Idempotent, and it never overwrites a hook it did not write: a pre-commit that is already this
# script is left alone, and one that is anything else gets the generated hook beside it and a printed
# merge instead. Silently replacing somebody's hook would remove a check to add one.
set -euo pipefail

REPO="$PWD"
STORE=""
KEYSTORE=""
YAAM="${YAAM:-yaam}"

usage() {
  cat <<'USAGE'
usage: hooks/install.sh [--repo DIR] [--store PATH] [--key-store PATH] [--yaam PATH]

  --repo DIR        the repository to install into                   (default $PWD)
  --store PATH      the memory root inside it, recorded as yaam.root (default: not set)
  --key-store PATH  a relocated key store, recorded as yaam.keystore (default: not set)
  --yaam PATH       the yaam executable to wire                      (default yaam on PATH)

Keep the store in a subdirectory of the repository. Everything beside it is then outside the
memory root and none of the guard's business; a store at the top level leaves no such place, and
the guard refuses every file there that no backup manifest classifies.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)      REPO="$2"; shift 2 ;;
    --store)     STORE="$2"; shift 2 ;;
    --key-store) KEYSTORE="$2"; shift 2 ;;
    --yaam)      YAAM="$2"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *)           echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v "$YAAM" >/dev/null 2>&1 || [ -x "$YAAM" ] || {
  echo "yaam not found: $YAAM — build it, or pass --yaam" >&2
  exit 1
}
git -C "$REPO" rev-parse --show-toplevel >/dev/null 2>&1 || {
  echo "$REPO is not a git repository" >&2
  exit 1
}

# `core.hooksPath` wins where it is set, and `--git-path` does not know about it. Asking both is what
# makes this work in a worktree and in a repository that has moved its hooks.
hooks="$(git -C "$REPO" config --get core.hooksPath || :)"
if [ -z "$hooks" ]; then
  hooks="$(git -C "$REPO" rev-parse --path-format=absolute --git-path hooks)"
elif [ "${hooks#/}" = "$hooks" ]; then
  hooks="$(git -C "$REPO" rev-parse --show-toplevel)/$hooks"
fi

# Recorded in the repository rather than left to the environment: a hook run from an editor or a
# desktop client inherits almost none of a shell's.
if [ -n "$STORE" ]; then
  git -C "$REPO" config --local yaam.root "$STORE"
  echo "→ git config yaam.root $STORE"
fi
if [ -n "$KEYSTORE" ]; then
  git -C "$REPO" config --local yaam.keystore "$KEYSTORE"
  echo "→ git config yaam.keystore $KEYSTORE"
fi

mkdir -p "$hooks"
target="$hooks/pre-commit"
generated="$("$YAAM" guard-commit --print-hook)"

if [ -f "$target" ]; then
  if [ "$(cat "$target")" = "$generated" ]; then
    chmod +x "$target"
    echo "→ $target is already this hook; nothing to do"
    exit 0
  fi
  aside="$hooks/pre-commit.guard-commit"
  printf '%s\n' "$generated" > "$aside"
  chmod +x "$aside"
  echo "→ kept existing $target"
  echo "→ wrote $aside"
  cat <<MERGE

$target already exists, so it was left alone. Call the guard from it — as the last thing it does,
so its own checks still run, and without swallowing the exit code:

  "$aside" || exit \$?

MERGE
else
  printf '%s\n' "$generated" > "$target"
  chmod +x "$target"
  echo "→ wrote $target"
fi

cat <<NEXT

Verify it refuses something, with no commit at risk:

  $YAAM --root ${STORE:-<store>} guard-commit --path ${STORE:-<store>}/keystore/anything

Expect exit 8 and a refusal naming the key store and the manifest's reason for excluding it. The
codes are the interface — 8 excluded, 4 unclassified, 3 no store, 1 could not tell — and all of
them block the commit.
NEXT
