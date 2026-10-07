# AGENTS.md

Guidance for coding agents working in this repository.

## Purpose and architecture

certdrift inspects, checks and compares X.509 certificates, as a Node.js library and CLI,
producing structured JSON instead of OpenSSL's human-oriented text.
`src/` is the core and never touches disk or network. `src/tls/` acquires certificates over TLS.
`bin/` is the CLI. Node.js >= 24, ESM, plain JavaScript type-checked through JSDoc with `tsc`.

## Invariants

`test/invariants.test.js` is the source of truth: it fails when an invariant is broken.
Read it; do not restate it.

## Commands

- `npm run check` — type check, then tests. CI runs exactly this; it must pass.
- `npm test` — tests only.

The full list is `scripts` in `package.json`.

## Tests

- Test files end in `.test.js`. `npm test` runs only that pattern, so a test file named
  otherwise is silently skipped.
- Validate any JSON output with `validatorFor(name)` from `test/helpers/schema.js`, not with a
  new Ajv setup.
- `npm run fixtures` regenerates `test/fixtures/` with new keys, and most validity dates are
  relative to the day it runs. Never depend on a fixture's exact bytes or fingerprints, or on
  the current time: pin `at` and assert on properties every regeneration keeps.

## Changes

Work only on what the issue asks. Short branch → pull request → CI green on Node 24 and 26 →
squash merge into `main`. The PR title follows Conventional Commits and becomes the squash
commit. Everything in this repository is written in English.

## Contract changes

A change to the JSON output updates the schema in `schema/`, its examples and its tests in the
same change. Never change the contract's shape or its `contract` number without the
maintainer's approval.

## Dependencies

No production dependencies. A new devDependency needs a justification in its issue.

## Definition of done

Every acceptance criterion of the issue being worked is met, and `npm run check` passes.