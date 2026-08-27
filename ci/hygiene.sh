#!/usr/bin/env bash
# Fails if domain- or employer-specific vocabulary leaks into the repo.
# This repo is published as a general-purpose library; keeping it neutral is a hard requirement,
# so it is a build gate rather than a review note.
set -uo pipefail

# Extend as needed. Case-insensitive, word-boundary matched where sensible.
DENY=(
  'wego' 'bamboohr' 'sprinklr' 'wenrix' 'openclaw' 'hermes'
  'payment_ref' 'booking_ref' 'partner_ref'
  '@wego' 'PAY-[0-9]' 'p9zy63u53v' 'WFVQZ'
)

status=0
for term in "${DENY[@]}"; do
  # Exclude this script and the git directory from its own scan.
  if hits=$(grep -rInE --binary-files=without-match \
        --exclude-dir=.git --exclude-dir=target --exclude=hygiene.sh \
        -- "$term" . 2>/dev/null); then
    echo "::error::denied term '$term' found:"
    echo "$hits" | head -20
    status=1
  fi
done

# A commit message is published exactly as widely as a file is, and nothing above looked at one. What
# prompted this: a draft message in a sibling repository named a deployment hostname, and the only
# thing between it and a public repository was somebody reading the draft.
#
# The scope is what this checkout is *adding*, and each fallback exists for a checkout the one above
# it cannot describe:
#
#   1. The message in flight, when there is one. That is the draft case, and a draft is a working
#      file: a hit is fixable by editing it, which is the whole difference from history.
#   2. Every commit on top of the branch this one tracks — or, with no upstream configured, on top of
#      the remote's default branch. Those are the commits a push would publish.
#   3. With neither — a detached CI checkout, a shallow clone with no remote refs — `HEAD` alone.
#      That is the commit under test, and it is the one thing such a checkout can be sure of.
#
# Never the whole history, and that is the point of the bound rather than an economy. History is
# immutable and already cloned: a term in a message from months ago cannot be fixed by anyone reading
# this failure, so scanning it would leave the gate permanently red and therefore ignored. A fresh
# clone reaches step 2, finds nothing above its upstream, and passes — which is the property that
# keeps this gate worth having.
#
# Message text only (`%B`). An author or committer identity is not part of the message, cannot be
# corrected once pushed, and would fail this gate on an email address rather than on a leak.
message_scope=()
if git rev-parse --git-dir >/dev/null 2>&1; then
  if upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null); then
    message_scope=("$upstream..HEAD")
  else
    for base in origin/HEAD origin/main origin/master; do
      if git rev-parse --verify --quiet "$base" >/dev/null 2>&1; then
        message_scope=("$base..HEAD")
        break
      fi
    done
    # Bounded at one commit, not at a window: a window would re-read history that this checkout did
    # not write, which is the false positive the whole scope avoids.
    [ "${#message_scope[@]}" -gt 0 ] || message_scope=(-1 HEAD)
  fi

  drafts=()
  for draft in COMMIT_EDITMSG MERGE_MSG SQUASH_MSG; do
    path="$(git rev-parse --git-path "$draft")"
    [ -f "$path" ] && drafts+=("$path")
  done

  # `--max-count` caps a wildly diverged branch rather than the history it would reach: the commits
  # nearest the tip are the ones a push publishes first.
  scanned=0
  for sha in $(git log --max-count=100 --format=%H "${message_scope[@]}" 2>/dev/null); do
    scanned=$((scanned + 1))
    message="$(git log -1 --format=%B "$sha")"
    for term in "${DENY[@]}"; do
      if hits=$(printf '%s\n' "$message" | grep -inE -- "$term"); then
        echo "::error::denied term '$term' in the message of commit $sha:"
        echo "$hits" | head -5
        status=1
      fi
    done
  done
  for path in ${drafts+"${drafts[@]}"}; do
    for term in "${DENY[@]}"; do
      if hits=$(grep -inE --binary-files=without-match -- "$term" "$path"); then
        echo "::error::denied term '$term' in the message being composed ($path):"
        echo "$hits" | head -5
        status=1
      fi
    done
  done
  echo "hygiene: scanned $scanned commit message(s) (${message_scope[*]}) and ${#drafts[@]} in flight"
else
  echo "hygiene: not a git checkout — commit messages not scanned"
fi

if [ "$status" -eq 0 ]; then
  echo "hygiene: clean — no domain-specific terms found"
fi
exit "$status"
