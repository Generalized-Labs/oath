# ADR-0002: Separate compatibility and native-security release runners

**Status:** Accepted  
**Date:** 2026-07-12
**Amended:** 2026-07-14

## Context

The real-project parity lane needs high disk capacity and executes untrusted
repository content only with lifecycle scripts disabled. Native sandbox evidence
needs specific host kernels and Windows security APIs. Combining these workloads
on standard 14 GB runners caused disk exhaustion and allowed compile-only or
skipped checks to look like security evidence.

## Decision

Oath has two independent release programs:

1. Compatibility runs 250 pinned, npm-11.12.1-eligible projects in 20 shards on
   the approved Blacksmith `blacksmith-16vcpu-ubuntu-2404` runner pool. npm and
   Oath trees are materialized sequentially. A final aggregation job requires
   250 unique exact comparisons at the pinned commit and immutable lock
   artifact. Each compressed lock is checked in, digest-verified before use,
   shared by npm and Oath, and materialized through `npm install`. npm's output
   lock may differ only through the paired `devOptional: true` to `dev: true`
   normalization; every changed path is evidence, and every other mutation
   fails. Installed package paths and contents remain exact.
2. Native security runs on Ubuntu 22.04, Ubuntu 24.04, macOS 15, Windows Server
   2022, and Windows Server 2025. Strict Linux mode runs only when the launcher
   verifies its required namespaces, seccomp, Landlock, resource, filesystem,
   and network controls on the native kernel. macOS proves its deprecated
   Seatbelt launcher still enforces default-deny file contents, scoped writes,
   network denial, child inheritance, environment stripping, and resource
   limits. Ubuntu 22.04 must prove fail-closed behavior when the full contract
   is unavailable. Missing controls never trigger a compatibility fallback.
   Capability reports are checksummed, attested through GitHub OIDC, and
   retained with the test output.

Moving repository HEAD is never a release input. Candidate refresh and npm
eligibility preflight happen in a separate canary process.

## Consequences

- A missing large-runner pool leaves compatibility jobs queued instead of
  silently falling back to insufficient storage.
- Cross-compilation is useful developer feedback but cannot satisfy native
  security gates.
- The checked-in pinned corpus becomes release-critical evidence and requires
  review when commits or lock artifacts change. Regenerating a lock from a
  package manifest during an evidence run is forbidden because registry state
  can change without a source commit changing.
- The corpus execution boundary includes Blacksmith as an approved third-party
  runner provider; job permissions and credentials remain minimized.

## Release gate

- 10,000/10,000 generated stress executions, explicitly labeled as repetitions.
- All 100 reviewed independent behavioral workflows pass on the OS matrix.
- 250/250 pinned real projects, 25 in each required category.
- Zero successful Linux, macOS, or Windows adversarial escapes.
- No skipped/unavailable native controls.
- Checksummed and attested capability reports for every native matrix entry.
