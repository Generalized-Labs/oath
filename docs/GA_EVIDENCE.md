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
- The pinned corpus now has 100/100 exact npm/Oath tree equivalents. The
  aggregate contains zero failures. Repositories rejected by reference npm or
  requiring another package manager are not eligible for the locked corpus and
  never count as passes.
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
- Manual release-evidence run
  [`29240267897`](https://github.com/Generalized-Labs/oath/actions/runs/29240267897)
  passed at commit `ad9071e10ae6c02412e8a7d3263793c9b60a7915`. It published
  GitHub OIDC attestations for the Linux and Windows capability reports. Ubuntu
  24.04 reported the strict Landlock/seccomp backend active; Ubuntu 22.04
  reported an explicit fail-closed degradation; Windows Server 2022 and 2025
  reported the AppContainer/Job Object backend active.

Scheduled and manually dispatched CI produce release evidence. Pull-request CI
runs the independent behavioral baseline and native enforcement checks. Public
metrics must report evidence class, independent-behavior denominator, generated
stress denominator, failures, confidence intervals, and skipped projects;
skipped or network-failed runs never count as passes.
