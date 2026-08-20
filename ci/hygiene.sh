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

if [ "$status" -eq 0 ]; then
  echo "hygiene: clean — no domain-specific terms found"
fi
exit "$status"
