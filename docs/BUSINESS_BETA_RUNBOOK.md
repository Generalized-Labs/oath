# Business beta runbook

## Entry gates

- All required CI jobs are green on Linux, macOS, and Windows.
- PostgreSQL restore and object-store failover drills passed within 30 days.
- Registry p95 metadata latency is below 250 ms and tarball availability is at
  least 99.9% over a rolling 30-day window.
- Every billed organization has an auditable Stripe event, entitlement, owner,
  and support contact. Webhook signature or replay failures page the operator.
- Compatibility evidence contains 500 fixture results and 100 project results;
  manifests without executed results do not satisfy the gate.

## Operational ownership

The on-call operator owns registry availability, revocation propagation,
transparency checkpoint publication, billing-event reconciliation, and customer
communications. Security incidents involving a published package immediately
freeze its dist-tags, issue a signed tombstone, preserve the artifact, and start
the revocation drill. Billing failures never delete package artifacts or make a
public package private.

## Reliability drills

Run `scripts/reliability-drills.sh` against an isolated environment. It is an
automated smoke for registry tenant/revocation behavior, replica read repair,
unsigned-webhook rejection, and database liveness. It does not perform or
certify the full operator drills below. Record the date, operator, versions,
region, recovery-point objective, recovery-time objective, actual recovery time,
checksums, and linked incident ticket for the complete drill.

Required drills:

1. Restore PostgreSQL into a clean database and compare row counts/checksums.
2. Disable the primary object store and verify replica read plus primary repair.
3. Revoke a release and verify metadata, tarball denial, rollback, tombstone,
   and transparency checkpoint.
4. Kill the registry during stage approval and prove transaction atomicity.
5. Replay and forge Stripe webhooks and prove both are harmless.
6. Expire JWKS keys and invitations and prove authentication fails closed.

## Beta operations

Start with named design partners and explicit package scopes. Publish a weekly
compatibility/security matrix with denominators and failures. Support must have
an organization disable switch, token revocation, invitation revocation,
package quarantine, billing-event lookup, and checkpoint export. Do not call
the service GA while any entry gate is incomplete.
