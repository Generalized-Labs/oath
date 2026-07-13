# v0.2.0 release readiness

Audit date: 2026-07-13

## Decision

Oath `v0.2.0` is a **developer-preview release candidate**. The CLI and the
documented npm workflow slices are ready to tag only after the exact candidate
commit passes the manually dispatched `release-evidence-gate`. The release
workflow checks that exact-commit result before it builds or publishes assets.

Oath is **not GA**. The hosted registry is a business-beta control plane for
isolated design-partner deployments with an operator. Detection quality,
service SLOs, code signing, external review, operational drills, and commercial
adoption have not met the complete GA contract.

## Verified candidate evidence

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

## Honest measured limits

- The current installer sample does not support a speed claim. Oath measured
  slower than npm and Bun for both cold and warm installs; see
  [`BENCHMARKS.md`](../BENCHMARKS.md).
- The last published scanner corpus baseline measured 57.5% malware recall and
  0.6% false positives on the older v0.1.6 engine. It has not been rerun on the
  exact v0.2.0 candidate and does not meet the GA detection targets; see
  [`scanner-threat-model.md`](scanner-threat-model.md).
- Registry assessment evidence is supplied by the publisher. The hosted service
  does not yet independently reproduce and attest that assessment.
- Registry mutations and transparency-event appends are separate transactions.
  Full process-kill, restore, key-rotation, and regional-failover drills remain
  operator gates.

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
