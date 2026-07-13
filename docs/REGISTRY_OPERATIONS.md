# Registry deployment and operations

The Oath registry in `v0.2.0` is a business-beta control plane. It is suitable
for isolated design-partner deployments with an operator and explicit recovery
procedures. It is not yet a general-availability public registry.

## Runtime contract

Build and start the service with:

```sh
cargo build --release --locked --bin oath-registry
DATABASE_URL=postgresql://... \
OATH_REGISTRY_DATA=/var/lib/oath-registry \
./target/release/oath-registry
```

The process listens on `0.0.0.0:4873`. Put it behind a TLS-terminating reverse
proxy, restrict the admin and metrics routes, and set request-size and rate
limits there.
Do not expose the service directly to the internet.

Required configuration:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL control plane. Startup migrations run automatically and fail closed on ambiguous historical package ownership or visibility. |
| `OATH_REGISTRY_DATA` | Durable signing-key and local-object root. The generated `registry-signing.key` is mode `0600` on Unix and must be backed up securely. |
| `OATH_PUBLIC_URL` | External HTTPS origin used in tarball metadata. It defaults to `http://localhost:4873` for local development and must be set in a deployed beta. |

One-time bootstrap configuration:

| Variable | Purpose |
| --- | --- |
| `OATH_REGISTRY_TOKEN` | Initial organization administrator token. Use a high-entropy secret, bootstrap once, then remove it from the service environment. |
| `OATH_REGISTRY_ORG` | Organization receiving the bootstrap token; defaults to `default`. |

Object storage defaults to the local directory under `OATH_REGISTRY_DATA`.
Production beta deployments should use `OATH_OBJECT_BACKEND=s3`, `r2`, or `gcs`
with `OATH_OBJECT_BUCKET`; R2/S3-compatible endpoints use
`OATH_OBJECT_ENDPOINT`. Provider credentials use the standard environment
variables understood by the object-store SDK. A read-repair replica can be
configured with `OATH_OBJECT_REPLICA_BACKEND`,
`OATH_OBJECT_REPLICA_BUCKET`, `OATH_OBJECT_REPLICA_ENDPOINT`, or
`OATH_OBJECT_REPLICA_ROOT`.

Optional integrations are fail-closed configuration pairs:

| Variables | Behavior |
| --- | --- |
| `OATH_OIDC_ISSUER`, `OATH_OIDC_AUDIENCE` | Enables OIDC discovery and token verification. Both are required together. |
| `OATH_RESEND_API_KEY`, `OATH_EMAIL_FROM`, `OATH_INVITATION_ACCEPT_URL` | Enables invitations. The accept URL must point to an application that obtains an OIDC ID token and POSTs it with `invitation_token` to `/-/oath/invitations/accept`; the registry does not ship that browser UI. |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | Enables checkout and signature-verified, idempotently recorded webhooks. Both are required together. |

`OATH_REGISTRY_MAX_STAGE_REQUEST_BYTES` controls the JSON stage-request limit.
It defaults to 64 MiB and accepts 1 MiB through 1 GiB. Because tarballs are
base64 encoded in the current beta API, usable tarball bytes are lower than the
HTTP limit. Enforce a matching authenticated route limit at the reverse proxy.

## Bootstrap and access

1. Create a dedicated PostgreSQL database and object bucket.
2. Store the signing key, database credentials, object credentials, and
   bootstrap token in the deployment secret manager.
3. Start one registry instance with the bootstrap variables set.
4. Verify `GET /health` and authenticate to `GET /-/oath/admin/summary`.
5. Issue short-lived reader, publisher, or administrator tokens through
   `POST /-/oath/tokens`.
6. Remove `OATH_REGISTRY_TOKEN` from the service environment and restart.

Tokens are organization-scoped. Package names have one immutable owning
organization and one immutable public/private visibility. An administrator in
another organization is not a global superuser. Cross-organization access
requires an explicit package role granted by the owning organization.

Public package metadata and active tarballs are anonymous. Private package
metadata, staged artifacts, and tarballs require an authorized bearer token.
Invalid supplied credentials fail even on public metadata requests.

## Publish and revoke

Publishing is a two-step mutation: a publisher creates a stage, then an
administrator in the owning organization approves or rejects it. Approval is
transactional and an already-decided stage returns a conflict. Artifacts are
content-addressed and immutable. The registry reads `package/package.json` from
the staged npm tarball, bounds manifest extraction, verifies its name and
version against the request, and derives the npm packument from that manifest.
The caller-provided assessment remains evidence supplied by the publisher; the
beta service does not independently reproduce or attest it.

Revocation preserves the artifact and version record, writes a signed tombstone,
and moves affected dist-tags to the highest remaining active semantic version.
If no active version remains, the tag is removed. Test the metadata and tarball
paths after every production revocation and record the transparency checkpoint.

## Observability

- `GET /health` reports process and schema health; it does not prove dependency
  or object-store health.
- `GET /metrics` exposes Prometheus counters for requests, stages, downloads,
  and denied operations.
- `GET /-/oath/transparency/checkpoint` returns the signed current Merkle root.
- Registry events are hash chained in PostgreSQL. Export and monitor them; the
  beta service does not yet publish witnessed consistency proofs.

Alert on elevated 5xx responses, denied-request anomalies, database saturation,
object read failures, replica write failures, stale checkpoints, and failed
billing-webhook verification. Measure metadata and tarball latency separately.

## Backup and recovery

Back up PostgreSQL, the primary and replica object stores, and
`registry-signing.key` as one recovery set. Losing the signing key prevents
continuity of tombstone and checkpoint signatures. Restoring only PostgreSQL or
only objects can produce metadata that references unavailable artifacts.

Run `scripts/reliability-drills.sh` against an isolated database as an automated
smoke, then complete the operator drills in
[`BUSINESS_BETA_RUNBOOK.md`](BUSINESS_BETA_RUNBOOK.md). The script does not by
itself certify restore RPO/RTO, process-kill atomicity, key rotation, or regional
failover.

## Known beta limits

- No built-in TLS, invitation browser UI, SCIM, customer-managed keys, regional
  routing, CDN invalidation controller, or air-gap mirror service.
- The HTTP bind address and port are not yet configurable.
- OIDC membership exchange selects one organization per subject.
- Package mutation and transparency-event append use separate database
  transactions, so the full process-kill atomicity drill remains mandatory.
- Publisher-supplied assessment evidence is stored but is not yet independently
  reproduced, schema-attested, or policy-signed by the hosted service.
- Service SLOs, restore targets, revocation propagation, external security
  review, and design-partner adoption have not yet met the GA gates.

These limits are release blockers for a production-wide npm replacement, not
hidden exceptions. Track them against
[`RELEASE_COMPLETE_PLAN.md`](RELEASE_COMPLETE_PLAN.md).
