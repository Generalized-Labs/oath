# v0.2.3 release readiness

Audit date: 2026-07-15

## Decision

Oath `v0.2.3` is a **developer preview**. The CLI and the documented npm
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
repository still enforces its configured cross-platform checks, strict branch
freshness, verified commit signatures, linear history, conversation resolution,
administrator enforcement, and force-push/deletion blocking. Independent
approval becomes mandatory when a second active Oath maintainer is onboarded
and remains a GA governance gate.

## Audited full-evidence baseline

Exact-master run
[`29403483148`](https://github.com/Generalized-Labs/oath/actions/runs/29403483148)
passed all 60 jobs and `release-evidence-gate` at commit
`49f98e650ae3b5066463e585a8843189eb00ccfc`. The downloaded summaries
independently aggregate to 100 reviewed workflow IDs on each supported CI OS,
250 pinned projects, and 10,000 generated comparisons. This is the audited
implementation baseline for that exact commit; the release-bump commit must
pass the complete manually dispatched gate again before it can be tagged.

| Gate | Result |
| --- | ---: |
| Rust format and warning-fatal Clippy | Pass |
| Rust workspace tests, including live PostgreSQL | Pass |
| Declared Rust 1.94 MSRV check | Pass |
| Rust and website dependency audits | Pass |
| Independently reviewed npm workflows | 100 / 100 on Linux, macOS, and Windows |
| Generated stress executions | 10,000 / 10,000; 2,000 per execution mode |
| Pinned real-project trees | 250 / 250 |
| Signed JavaScript, Python, and Go agent-contract verification | Pass |
| PostgreSQL, OCI-container, and registry reliability checks | Pass |
| Native Linux and Windows containment checks | Pass |
| Public stable-release README smoke | Pass |
| Exact-commit release evidence gate | Pass |

The generated artifacts contain 2,000 comparisons each for clean, warm,
offline, repeat, and interrupted modes, all classified as compared and all
equivalent. The complete manually dispatched CI run repeats the cross-platform,
native-containment, registry, audit, reliability, 10,000-execution, and
250-project gates for the exact release commit.

## Current source validation

- The reviewed behavior contract contains 100 workflow IDs. Exact-master
  artifacts matched 100/100 against npm 11.12.1 on Linux, macOS, and Windows
  with zero tree differences.
- `ExecAssessment v3`, `PublishAssessment v2`, and `RegistryVerdict v1` have
  published schemas/types, stable decisions, digests, expiry, limitations, and
  Ed25519 signatures. JavaScript, Python, and Go verifiers accept the signed
  fixtures and reject mutations. Exec v2 and publish v1 remain selectable.
- The registry ships as a rootless OCI image and cloud-neutral Kubernetes base
  over managed PostgreSQL and S3, R2, GCS, or Azure object storage. This is a
  portable deployment contract, not a production-service SLO result.
- The live PostgreSQL test passes server-owned assessment, retained evidence,
  SPDX SBOM, registry-observation provenance, private verdict authorization,
  step-up approval enforcement, atomic outbox delivery, download accounting,
  revocation rollback, OSV quarantine output, and Merkle proof verification.
- Every later candidate still requires a manually dispatched full-evidence run
  and signed manifest bound to its exact commit before the developer-preview
  tag. This document intentionally does not maintain a mutable latest-run
  pointer.
- The signed `v0.2.0` tag points to commit
  `6147df33b5beee7a9a1c39e9cbb3173226490310`, whose exact evidence run
  [`29324736660`](https://github.com/Generalized-Labs/oath/actions/runs/29324736660)
  passed all 54 jobs. Release run
  [`29349917900`](https://github.com/Generalized-Labs/oath/actions/runs/29349917900)
  then failed only while linking the Linux x86-64 and ARM64 assets because the
  cross images lacked target `libseccomp`. No `v0.2.0` GitHub release or assets
  were published. The tag is not moved or deleted.
- The `v0.2.1` release corrected the Linux cross-image `libseccomp` packaging
  failure. `v0.2.2` added portable registry deployment, cross-language signed
  contract verification, immutable release assembly, and expanded npm parity.
  `v0.2.3` derives measured gate state from the evidence instead of retaining
  stale hard-coded open labels.
- The real-project corpus now commits and digest-verifies 250 compressed npm
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
- Native macOS containment signing/notarization and an external sandbox escape
  review remain open. Unsupported requested containment must continue to fail
  closed unless policy explicitly permits degraded execution.

## Required tag sequence

1. Merge the reviewed candidate to `master`.
2. Manually dispatch `.github/workflows/ci.yml` on the exact master commit.
3. Require every job in `release-evidence-gate` to pass without exceptions.
4. Create signed tag `v0.2.3` on that exact commit.
5. Let `.github/workflows/release.yml` revalidate version, changelog, MSRV,
   tests, dependency audits, website, exact-commit evidence, platform builds,
   checksums, and provenance before publishing the GitHub release.

Do not bypass or relabel a failed gate. A failure returns the candidate to
development; it is not a documentation exception.
