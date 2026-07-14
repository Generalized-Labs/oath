# GA evidence contract

GA requires a reviewed independent behavioral contract, 10,000 generated stress
executions, and 250 named real projects. The stress and project targets are
enforced by `scripts/compat-scale.mjs`; independent behavior IDs live in
`tests/compat/behavioral-contract.json`. Changing any denominator requires a
reviewed contract change. A manifest is not a passing result. GA is green only
when every independent behavior and stress artifact passes (or records a
reviewed security divergence), and all real-project runs include commit SHA,
npm version, Oath version, platform, duration, graph/layout comparison, and
logs/checksums.

## Current evidence snapshot (2026-07-14)

- The post-placement-contract stress run executed 500 generated cases: 500 were
  equivalent and zero failed. These are repetitions of three independent
  behavioral templates (`basic`, `alias`, and `workspace`) across clean, warm,
  offline, repeat, and interrupted-recovery modes. They prove deterministic
  stress behavior; they do not count as 500 independent npm features.
- Independent behavioral coverage and generated stress coverage are separate
  release artifacts and public metrics. The current independent behavioral
  baseline is 3/3; GA requires the workflow contract in this document, not a
  generated-case count by itself.
- The source contract now contains ten reviewed behavior IDs. A local macOS run
  on this candidate matched all 10/10 against npm 11.12.1, including peers,
  optionals, overrides, scoped packages, dist-tags, nested placement, aliases,
  workspaces, production dependencies, and development dependencies. This is
  useful pre-merge evidence, but it does not replace the signed cross-platform
  CI artifact and therefore does not change the public 3/3 baseline above.
- The pinned corpus now has 100/100 exact npm/Oath tree equivalents. The
  aggregate contains zero failures. Repositories rejected by reference npm or
  requiring another package manager are not eligible for the locked corpus and
  never count as passes.
- Corpus manifest version 2 stores the exact compressed npm lockfile for each
  project. The harness verifies the decompressed digest, supplies identical
  bytes to npm and Oath, uses lock-preserving `npm ci` for the frozen reference,
  and rejects lock mutation. Generated fixtures separately retain ordinary
  `npm install` differential coverage. This replaced the earlier
  hash-only design after exact-master run `29310661010` correctly blocked on
  Express and Ant Design lock drift caused by mutable registry resolution even
  though both npm/Oath trees were identical.
- Exact-master run `29314277600` then exposed a second reproducibility flaw:
  replaying Snowpack's frozen lock with `npm install` under a fresh cache changed
  six `devOptional` flags to `dev`, despite an identical 46,695-entry dependency
  tree. The run correctly failed. The corrected harness uses `npm ci`; the exact
  Snowpack lock and tree passed locally, but a complete exact-commit CI run is
  still required before release.
- Next.js HEAD was replaced by the npm-eligible
  `NextJSTemplates/play-nextjs` commit
  `f0a5c55ef1d6198c41ac6354595adadc4c41b924`, which passed exact comparison.
- The installer benchmark does not support a speed claim: Oath was slower than
  npm and Bun on both cold and warm runs. See
  `compat-results/benchmarks/installers.json` for versions and methodology.
- Native Linux enforcement passed on Ubuntu 24.04 with Landlock/seccomp active,
  and Ubuntu 22.04 proved strict mode fails closed when the required Landlock
  ABI is unavailable. Native Windows AppContainer, restricted-token, ACL, Job
  Object, environment, filesystem, and network-denial checks passed on Windows
  Server 2022 and 2025 in PRs 16 and 17.
- Final v0.2 release-candidate evidence run
  [`29292367523`](https://github.com/Generalized-Labs/oath/actions/runs/29292367523)
  passed all 53 jobs at commit
  `8e49d586040be3582262d3405a80dcf5d37e1507`. It published
  GitHub OIDC attestations for the Linux and Windows capability reports. Ubuntu
  24.04 reported the strict Landlock/seccomp backend active; Ubuntu 22.04
  reported an explicit fail-closed degradation; Windows Server 2022 and 2025
  reported the AppContainer/Job Object backend active.

Scheduled and manually dispatched CI produce release evidence. Pull-request CI
runs the independent behavioral baseline and native enforcement checks. Public
metrics must report evidence class, independent-behavior denominator, generated
stress denominator, failures, confidence intervals, and skipped projects;
skipped or network-failed runs never count as passes.

Successful full-evidence runs now produce `ga-evidence-manifest.json`. The
manifest hashes every input summary, binds them to the exact commit and run,
lists every still-open external GA gate, receives a GitHub OIDC artifact
attestation, and is attached to the corresponding release. This document is a
human index; the signed manifest is the release claim source of truth.
