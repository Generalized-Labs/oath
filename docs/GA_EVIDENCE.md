# GA evidence contract

GA requires a reviewed independent behavioral contract, 500 generated stress
executions, and 100 named real projects. The stress and project targets are
enforced by `scripts/compat-scale.mjs`; independent behavior IDs live in
`tests/compat/behavioral-contract.json`. Changing any denominator requires a
reviewed contract change. A manifest is not a passing result. GA is green only
when every independent behavior and stress artifact passes (or records a
reviewed security divergence), and all real-project runs include commit SHA,
npm version, Oath version, platform, duration, graph/layout comparison, and
logs/checksums.

## Current evidence snapshot (2026-07-13)

- The post-placement-contract stress run executed 500 generated cases: 500 were
  equivalent and zero failed. These are repetitions of three independent
  behavioral templates (`basic`, `alias`, and `workspace`) across clean, warm,
  offline, repeat, and interrupted-recovery modes. They prove deterministic
  stress behavior; they do not count as 500 independent npm features.
- Independent behavioral coverage and generated stress coverage are separate
  release artifacts and public metrics. The current independent behavioral
  baseline is 3/3; GA requires the workflow contract in this document, not a
  generated-case count by itself.
- Ten unique real projects currently have exact npm/Oath tree equivalence. The
  100-project gate is not complete. Repositories rejected by reference npm or
  requiring another package manager are reported but never counted as passes.
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
- Pull-request capability reports are checksummed but deliberately not attested.
  A scheduled or manually dispatched release-evidence run must still publish
  GitHub OIDC attestations for Linux and Windows before a release is promoted.

Scheduled and manually dispatched CI produce release evidence. Pull-request CI
runs the independent behavioral baseline and native enforcement checks. Public
metrics must report evidence class, independent-behavior denominator, generated
stress denominator, failures, confidence intervals, and skipped projects;
skipped or network-failed runs never count as passes.
