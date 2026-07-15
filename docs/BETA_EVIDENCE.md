# Production beta evidence

The 60-day beta gate is evaluated from a machine-readable ledger, not a launch
date in prose. Every UTC day needs immutable metric evidence for metadata p95,
tarball and control-plane availability, revocation propagation, and unresolved
high/critical findings. Missing days break the consecutive window.

The ledger also records passed backup restoration, dependency outage, key
compromise, object corruption, process kill, regional failover, split-view,
tenant-isolation, and webhook-replay drills. Backup restoration must demonstrate
RPO at most five minutes and RTO at most 60 minutes. Independent architecture,
penetration, and sandbox reviews must have no open high or critical findings.

Validate a real ledger with:

```sh
node scripts/validate-beta-ledger.mjs beta-ledger.json
```

The validator exits nonzero for underpowered, discontinuous, incomplete, or
failing evidence. Its `--self-test` mode uses generated synthetic dates only to
test validation logic and can never be submitted as beta evidence.
