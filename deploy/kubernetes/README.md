# Kubernetes deployment base

This Kustomize base is cloud-neutral and deliberately does not create secrets,
public ingress, a database, or an object bucket. Supply those through the
platform's managed services and secret controller.

Before applying the base:

1. Build `deploy/Dockerfile` for the target architectures and replace
   `oath-registry:local` with an immutable image digest.
2. Create `oath-registry-secrets` with a `database-url` key.
3. Create `oath-registry-config` with `public-url`, `object-backend`, and
   `object-bucket` keys. Supported remote backends are `s3`, `r2`, `gcs`, and
   `azure`.
4. Create the `oath-registry-data` persistent-volume claim for the signing key.
   Back it up with PostgreSQL and object storage as one recovery set.
5. Add the provider's workload identity settings and object-store credentials.

Validate the rendered resources before deployment:

```sh
kubectl kustomize deploy/kubernetes/base
kubectl apply --server-side --dry-run=server -k deploy/kubernetes/base
```

The beta signing key is file-backed, so this base intentionally runs one
replica. Do not scale it until every replica mounts the same protected key or a
remote signing provider is configured. TLS and external rate limits belong at
the ingress or service-mesh boundary.
