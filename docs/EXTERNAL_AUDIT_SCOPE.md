# External audit scope

Oath requires three independent reviews against the exact release candidate:
an architecture review, a penetration test, and a sandbox escape review. The
review organization must be independent of implementation and must receive the
source commit, build provenance, supported-platform matrix, threat models,
schemas, registry migrations, runbooks, and reproducible test commands.

## Required attack surfaces

- install resolution, tar extraction, integrity verification, lifecycle scripts,
  transactional linking, cache reuse, and interrupted recovery;
- `oath exec` assessment signing, policy downgrade resistance, secret handling,
  Linux and Windows native containment, and unsupported-platform fail closure;
- publisher OIDC, stage-only roles, approval step-up, server reassessment,
  private-package tenant boundaries, quotas, and request limits;
- immutable objects, PostgreSQL mutation/outbox atomicity, revocation rollback,
  stale/offline clients, signed tombstones, and checkpoint split views;
- contract canonicalization, key storage/rotation/compromise, artifact
  provenance, webhook replay, and administrative authorization.

## Deliverables

Each reviewer provides methodology, dates, personnel, exact commit and artifact
digests, environments, exclusions, findings with severity and reproduction,
retest disposition, and a detached signature. GA requires zero unresolved high
or critical findings. A report under NDA may remain private, but Oath publishes
the reviewer, scope, dates, finding counts, exclusions, and report digest.

Run `node scripts/build-audit-bundle.mjs audit-dist` from a clean candidate to
produce checksum-locked review inputs. The generated bundle is preparation, not
proof that an audit occurred.
