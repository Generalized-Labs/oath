# ADR-0002: Separate compatibility and native-security release runners

**Status:** Accepted  
**Date:** 2026-07-12

## Context

The real-project parity lane needs high disk capacity and executes untrusted
repository content only with lifecycle scripts disabled. Native sandbox evidence
needs specific host kernels and Windows security APIs. Combining these workloads
on standard 14 GB runners caused disk exhaustion and allowed compile-only or
skipped checks to look like security evidence.

## Decision

Oath has two independent release programs:

1. Compatibility runs 100 pinned, npm-11.12.1-eligible projects in 20 shards on
   the approved Blacksmith `blacksmith-16vcpu-ubuntu-2404` runner pool. npm and
   Oath trees are materialized sequentially. A final aggregation job requires
   100 unique exact comparisons at the pinned commit and lock hash.
2. Native security runs on Ubuntu 22.04, Ubuntu 24.04, Windows Server 2022, and
   Windows Server 2025. Strict Linux mode runs only when the launcher verifies
   its required namespaces, seccomp, Landlock, resource, filesystem, and
   network controls on the native kernel. Ubuntu 22.04 must prove fail-closed
   behavior when the full contract is unavailable. Missing controls never
   trigger a compatibility fallback. Capability reports are checksummed,
   attested through GitHub OIDC, and retained with the test output.

Moving repository HEAD is never a release input. Candidate refresh and npm
eligibility preflight happen in a separate canary process.

## Consequences

- A missing large-runner pool leaves compatibility jobs queued instead of
  silently falling back to insufficient storage.
- Cross-compilation is useful developer feedback but cannot satisfy native
  security gates.
- The checked-in pinned corpus becomes release-critical evidence and requires
  review when commits or lock hashes change.
- The corpus execution boundary includes Blacksmith as an approved third-party
  runner provider; job permissions and credentials remain minimized.

## Release gate

- 500/500 generated stress executions, explicitly labeled as repetitions.
- Every reviewed independent behavioral fixture passes on the OS matrix.
- 100/100 pinned real projects, ten in each required category.
- Zero successful Linux or Windows adversarial escapes.
- No skipped/unavailable native controls.
- Checksummed and attested capability reports for every native matrix entry.
