# General availability gate tracker

No row is complete because a feature exists in source. Completion requires the
linked evidence on the exact release commit and, where applicable, the full
observation window or external approval.

| Gate | Current state | Required evidence |
| --- | --- | --- |
| 100 independent npm workflows | In progress: 10 source IDs; local macOS 10/10 | Signed Linux/macOS/Windows reports, reviewed IDs, zero unexplained differences |
| 10,000 generated executions | Open: last signed baseline 500/500 | Exact-commit manifest across clean/warm/offline/repeat/interrupted modes |
| 250 pinned projects | Open: last signed baseline 100/100 | Commit-pinned eligible corpus, exclusions, logs, tree/lock/exit comparisons |
| Detection quality | Failing last published baseline | Frozen malware plus private family/time holdout, benign corpus, secret/exfiltration suite, confidence intervals |
| Native containment | Partial | Zero escapes/leaks/writes/connections/bypasses on every supported OS and external corpus |
| Performance | Open; current sample loses | Reproducible p50/p95 cold/warm/install/assessment/exec results on declared hardware |
| Registry durability | Source foundation implemented | Managed HA deployment, KMS, CDN, quotas/rate limits, restore/failover/key drills |
| Transparency | Partial | Compact consistency proofs, Rekor-compatible bundles, external/customer witnesses, split-view drill |
| Service objectives | Open | 60 consecutive production days meeting `SERVICE_LEVEL_OBJECTIVES.md` |
| Independent security | Open | Architecture review, penetration test, and sandbox escape review with no unresolved high/critical findings |
| Legal/compliance | Open | Approved and effective documents listed in `LEGAL_READINESS.md` |
| Customer validation | Open | 50 accepted partners, required active teams/tenants/publishers, retention/conversion/margin metrics, ten verified replacements |

The GA evidence generator always emits `ga_gate.ready: false` until a reviewed
gate evaluator can consume every technical, operational, security, legal, and
commercial artifact. A missed gate moves the release date; it does not change
the denominator or threshold.
