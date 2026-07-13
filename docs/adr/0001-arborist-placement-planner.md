# ADR-0001: Use npm Arborist as Oath's placement planner

**Status:** Accepted
**Date:** 2026-07-12
**Deciders:** Oath maintainers

## Context

Oath's resolver produces a dependency graph without npm's physical placement
decisions. Its linker then hoists the most-referenced version. A preserved
Express comparison proved this differs from npm 11: both installs succeeded,
but npm produced 7,139 normalized entries and Oath produced 6,964, including
different root versions of semver, lru-cache, argparse, and cliui.

Oath must match npm's package contract while retaining stronger assessment,
integrity, approval, atomicity, and sandbox boundaries.

## Decision

Pin the reference npm major and use its `@npmcli/arborist` implementation to run
`reify({ dryRun: true, ignoreScripts: true })`. Serialize exact package
locations and dependency edges into a versioned `PlacementPlan`. Non-dry reify
is forbidden: Oath fetches and verifies every planned artifact, scans it, stores
it in the Oath CAS, then its transactional linker materializes the exact planned
locations.

The legacy Rust resolver remains only as a canary during migration and for
comparing semantic graphs. It stops determining production placement once the
Arborist path passes required fixtures.

## Options considered

1. Reimplement npm's hoisting algorithm in Rust: rejected because npm behavior
   changes and the 100-project gate already falsified the approximation.
2. Delegate to `npm install`: rejected because npm would own extraction and
   linking, weakening Oath's pre-link policy boundary.
3. Arborist planning plus Oath enforcement: accepted because it reuses npm's
   semantics while preserving Oath's security wedge.

## Consequences

- Oath distributions must bundle a pinned Arborist runtime or locate the one
  shipped with the pinned npm reference. Runtime identity is recorded in plans.
- Placement-plan schema changes require compatibility fixtures.
- npm upgrades enter a canary lane before changing the production planner.
- GA remains blocked until the full 100-project lane passes this path.
