# v0.2.0 release readiness

Audit date: 2026-07-14

## Decision

Oath `v0.2.0` is a **developer-preview release candidate**. The CLI and the
documented npm workflow slices are ready to tag only after the exact candidate
commit passes the manually dispatched `release-evidence-gate`. The release
workflow checks that exact-commit result before it builds or publishes assets.

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

## Last signed candidate evidence

The table below describes commit `8e49d586040be3582262d3405a80dcf5d37e1507`
and run `29292367523`. It must not be relabeled as evidence for later source.

| Gate | Result |
| --- | ---: |
| Rust format and warning-fatal Clippy | Pass |
| Rust workspace tests, including live PostgreSQL | 161 / 161 |
| Declared Rust 1.94 MSRV check | Pass |
| RustSec audit | 0 advisories or warnings across 421 locked dependencies |
| Website audit | 0 npm vulnerabilities |
| Independent npm behaviors | 3 / 3 exact tree matches |
| AI ecosystem cases | 4 / 4 |
| Generated stress executions | 500 / 500 in the latest full evidence baseline |
| Pinned real-project trees | 100 / 100 in the latest full evidence baseline |
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
- These are local source checks. The exact post-merge CI run remains required
  before the developer-preview tag.
- The real-project corpus now commits and digest-verifies 100 compressed npm
  lockfiles. Evidence runs no longer regenerate dependency resolution from
  mutable registry state; npm and Oath consume the same pinned bytes and lock
  mutation is a hard failure.

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
  prevents approval of a server-denied artifact. The new path still requires
  the exact-commit cross-platform release run before it becomes release proof.
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
