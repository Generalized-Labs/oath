# v0.2.0 release readiness

Audit date: 2026-07-14

## Decision

Oath `v0.2.0` is a **developer preview**. The CLI and the documented npm
workflow slices are eligible for a preview tag only after the exact candidate
commit passes the manually dispatched `release-evidence-gate`. The release
workflow checks that exact-commit result before it builds or publishes assets
and derives prerelease status from the signed evidence manifest.

Oath is **not GA**. The hosted registry is a business-beta control plane for
isolated design-partner deployments with an operator. Detection quality,
service SLOs, code signing, external review, operational drills, and commercial
adoption have not met the complete GA contract.

## Repository governance

Oath currently has one active maintainer. Protected `master` therefore requires
pull requests with zero human approvals during this phase; requiring an
independent approval would deadlock every maintainer-authored change. The
repository still enforces all 19 required cross-platform checks, strict branch
freshness, verified commit signatures, linear history, conversation resolution,
administrator enforcement, and force-push/deletion blocking. Independent
approval becomes mandatory when a second active Oath maintainer is onboarded
and remains a GA governance gate.

## Audited full-evidence baseline

The corrected install-evidence contract first passed in run
[`29320179154`](https://github.com/Generalized-Labs/oath/actions/runs/29320179154)
at commit `aafc55c7403bc859b68ec6785de29bb2f28802ae`. All 54 jobs
passed. The downloaded manifest checksum and GitHub OIDC/SLSA provenance both
verified, and the manifest remained explicit that GA is not ready. This is a
historical audited baseline for that exact commit; it must not be relabeled as
evidence for later source.

| Gate | Result |
| --- | ---: |
| Rust format and warning-fatal Clippy | Pass |
| Rust workspace tests, including live PostgreSQL | Pass |
| Declared Rust 1.94 MSRV check | Pass |
| Rust and website dependency audits | Pass |
| Independent npm behaviors | 30 / 30 platform results across 10 behavior IDs |
| Generated stress executions | 500 / 500 |
| Pinned real-project trees | 100 / 100 |
| Local registry reliability smoke | Pass |
| Public stable-release README smoke | Pass |

The independent behavior hashes and current AI ecosystem run are checked in
under `compat-results/`. The complete manually dispatched CI run repeats the
cross-platform, native-containment, registry, audit, reliability, 500-fixture,
and 100-project gates for the exact release commit.

## Current source validation

- The reviewed behavior contract is expanded to ten workflows; a local macOS
  run matched 10/10 against npm 11.12.1 with zero tree differences.
- `ExecAssessment v3`, `PublishAssessment v2`, and `RegistryVerdict v1` have
  published schemas/types, stable decisions, digests, expiry, limitations, and
  Ed25519 signatures. Exec v2 and publish v1 remain explicitly selectable.
- The live PostgreSQL test passes server-owned assessment, retained evidence,
  SPDX SBOM, registry-observation provenance, private verdict authorization,
  step-up approval enforcement, atomic outbox delivery, download accounting,
  revocation rollback, OSV quarantine output, and Merkle proof verification.
- Every later candidate still requires a manually dispatched full-evidence run
  and signed manifest bound to its exact commit before the developer-preview
  tag. This document intentionally does not maintain a mutable latest-run
  pointer.
- The real-project corpus now commits and digest-verifies 100 compressed npm
  lockfiles. Evidence runs no longer regenerate dependency resolution from
  mutable registry state, and npm and Oath consume the same pinned bytes through
  the ordinary `npm install` path. Paired `devOptional: true` to `dev: true`
  normalization is recorded path by path; every other lock mutation is a hard
  failure.

## Honest measured limits

- The current installer sample does not support a speed claim. Oath measured
  slower than npm and Bun for both cold and warm installs; see
  [`BENCHMARKS.md`](../BENCHMARKS.md).
- The last published scanner corpus baseline measured 57.5% malware recall and
  0.6% false positives on the older v0.1.6 engine. It has not been rerun on the
  exact current source and does not meet the GA detection targets; see
  [`scanner-threat-model.md`](scanner-threat-model.md).
- The current source independently extracts and scans the exact staged tarball,
  signs a server `RegistryVerdict v1`, retains publisher claims separately, and
  prevents approval of a server-denied artifact. It becomes release proof only
  through the exact candidate's cross-platform run and signed manifest.
- Core stage, approval, rejection, and revocation mutations enqueue audit intent
  in the same PostgreSQL transaction. An idempotent worker appends signed log
  entries with retry. Full process-kill, restore, key-rotation, and regional
  failover drills remain operator gates.

## Required tag sequence

1. Merge the reviewed candidate to `master`.
2. Manually dispatch `.github/workflows/ci.yml` on the exact master commit.
3. Require every job in `release-evidence-gate` to pass without exceptions.
4. Create `v0.2.0` on that exact commit.
5. Let `.github/workflows/release.yml` revalidate version, changelog, MSRV,
   tests, dependency audits, website, exact-commit evidence, platform builds,
   checksums, and provenance before publishing the GitHub release.

Do not bypass or relabel a failed gate. A failure returns the candidate to
development; it is not a documentation exception.
