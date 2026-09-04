# Invariants

Anything landing in this repo must hold these. CI enforces what can be mechanically enforced; the
rest is on review.

## 1. Generic by construction

This repo is domain-neutral and must stay that way. It carries **no** organisation names, employer
names, internal hostnames, team names, ticket prefixes, chat channel or user IDs, colleague names, or
domain vocabulary borrowed from any specific company's systems.

Entity kinds, attribute keys and redaction policies are **configuration** (`spec/`), never hardcoded
domain terms. Examples in docs and tests use neutral vocabulary: `order_ref`, `ticket`,
`pull_request`, `deploy`, `chat_user`. CI fails the build on a denylist of leaked terms.

## 2. The index is derived, always

Nothing may be indexed that is not present in the Markdown tree (or a local cold manifest). Every
column must be reproducible by `yaam reindex`. This is what makes the store portable, and it is easy
to break silently — a round-trip test guards it.

## 3. No claimed guarantee without a mechanism

A filesystem rename cannot join a SQLite transaction. Do not write "atomic" where the mechanism
delivers *recoverability*. Every partial failure needs a defined winner and a sweeper that converges.

## 4. Crypto invariants are types, not comments

- A nonce is constructible only from a CSPRNG; re-sealing takes a fresh key *and* nonce.
- Associated data is recomputed from record identity, never read from the stored blob.
- A record's key is derived from *all* subject shares, so an any-one-suffices misbuild cannot decrypt.
- A record names **at most one** subject, so one erasure reaches one body. Refused in
  `ActionRecord::validate` and again once a deployment's resolver has answered — never in one caller.
- Changing a record's subject set re-encrypts under a fresh key. Never re-wrap the old one.

## 5. Idempotency is per-hop

Every write path is keyed and safe to replay: unique record ids, compound keys on fan-out targets,
recomputed counters rather than incremented ones.

## 6. Tests and docs are part of the change

- Line coverage ≥ 85%, enforced in CI.
- `cargo clippy --all-targets -- -D warnings` clean.
- Every public item documented. Comments explain *why*, briefly — no restating the code.

## Running the gates

```sh
ci/check.sh      # hygiene, fmt, clippy, tests, coverage — the same set CI runs
```

CI runs the same set on every push and pull request (`.github/workflows/ci.yml`). Keep the two in
lockstep: a gate that exists only in CI is discovered late, and one that exists only locally is
bypassed.
