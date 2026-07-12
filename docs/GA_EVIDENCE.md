# GA evidence contract

GA requires 500 differential fixtures and 100 named real projects. The targets
are enforced by `scripts/compat-scale.mjs`; changing the counts requires a
reviewed contract change. A manifest is not a passing result. GA is green only
when all fixture shard artifacts exist, every result is equivalent or records a
reviewed security divergence, and all real-project runs include commit SHA,
npm version, Oath version, platform, duration, graph/layout comparison, and
logs/checksums.

## Current evidence snapshot (2026-07-12)

- The post-placement-contract differential run executed all 500 fixtures: 500
  were equivalent and zero failed. The modes were clean 102/102, warm 101/101,
  offline 99/99, repeat 99/99, and interrupted recovery 99/99.
- Ten unique real projects currently have exact npm/Oath tree equivalence. The
  100-project gate is not complete. Repositories rejected by reference npm or
  requiring another package manager are reported but never counted as passes.
- Next.js HEAD was replaced by the npm-eligible
  `NextJSTemplates/play-nextjs` commit
  `f0a5c55ef1d6198c41ac6354595adadc4c41b924`, which passed exact comparison.
- The installer benchmark does not support a speed claim: Oath was slower than
  npm and Bun on both cold and warm runs. See
  `compat-results/benchmarks/installers.json` for versions and methodology.
- Linux and Windows enforcement are release gates. Cross-compilation is not a
  substitute for running the adversarial suite on a Linux kernel and the Job
  Object/AppContainer smoke on a native Windows runner.

Scheduled CI produces evidence artifacts. Pull-request CI runs the three smoke
fixtures and validates the full corpus manifest. Public metrics must report the
denominator, failures, confidence intervals, and skipped projects; skipped or
network-failed runs never count as passes.
