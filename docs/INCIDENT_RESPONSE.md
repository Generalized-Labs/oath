# Incident response

1. Page the on-call owner for confirmed unauthorized access, signing-key risk,
   tenant isolation failure, malicious package exposure, or SLO exhaustion.
2. Preserve logs, checkpoints, affected digests, policy/rule versions, database
   transaction IDs, and object versions before remediation.
3. Contain with token revocation, package quarantine, signed tombstones, cache
   invalidation, key rotation, or regional withdrawal as appropriate.
4. Notify affected customers using verified security contacts. Critical active
   exploitation targets initial notice within 24 hours; legal requirements may
   require a shorter deadline.
5. Restore from a tested recovery set, verify object/control-plane consistency,
   publish a new signed checkpoint, and monitor for recurrence.
6. Publish a blameless post-incident report with timeline, impact, evidence,
   corrective actions, and owner/due date unless disclosure would increase harm.

Quarterly exercises cover signing-key compromise, split view, cross-tenant
authorization, object corruption, PostgreSQL loss, dependency outage, process
kill during publish/revoke, and forged/replayed billing webhooks. A checklist is
not evidence: each exercise stores timestamps, commands, outputs, failures, and
recovery validation.
