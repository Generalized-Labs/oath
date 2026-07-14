# General availability gate tracker

No row is complete because a feature exists in source. Completion requires the
linked evidence on the exact release commit and, where applicable, the full
observation window or external approval.

| Gate | Current state | Required evidence |
| --- | --- | --- |
| 100 independent npm workflows | Infrastructure ready: 100 explicit command/state cases from 10 reviewed base fixtures; independent review open | Signed Linux/macOS/Windows reports, external review of every ID, zero unexplained differences |
| 10,000 generated executions | Infrastructure ready; last signed baseline 500/500 | Exact-commit 10,000-result manifest across clean/warm/offline/repeat/interrupted modes |
| 250 pinned projects | Refresh ready: 100 retained pins plus 498-candidate pool; last signed baseline 100/100 | Reviewed 250-project manifest and exact-commit tree/lock/exit results |
| Detection quality | Gate implemented; historical quality still failing | Qualifying frozen malware/private holdout/benign/exfiltration run with corpus digests, exclusions, and confidence intervals |
| Native containment | Fail-closed selection implemented; native evidence partial | Zero escapes/leaks/writes/connections/bypasses on every supported OS and external corpus |
| Performance | Open; current sample loses | Reproducible p50/p95 cold/warm/install/assessment/exec results on declared hardware |
| Registry durability | PostgreSQL/object storage, atomic stage quotas, and distributed request windows implemented | Managed HA deployment, KMS, CDN, restore/failover/key drills |
| Transparency | Compact inclusion/consistency proofs and signed checkpoints implemented | Rekor-compatible bundles, external/customer witnesses, split-view drill |
| Service objectives | Machine validator ready; observation window open | 60 consecutive production days meeting `SERVICE_LEVEL_OBJECTIVES.md` |
| Independent security | Checksum-locked audit input bundle ready; reviews open | Architecture review, penetration test, and sandbox escape review with no unresolved high/critical findings |
| Legal/compliance | Open | Approved and effective documents listed in `LEGAL_READINESS.md` |
| Customer validation | Open | 50 accepted partners, required active teams/tenants/publishers, retention/conversion/margin metrics, ten verified replacements |

The GA evidence generator always emits `ga_gate.ready: false` until a reviewed
gate evaluator can consume every technical, operational, security, legal, and
commercial artifact. A missed gate moves the release date; it does not change
the denominator or threshold.
