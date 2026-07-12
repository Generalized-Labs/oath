#!/usr/bin/env bash
set -euo pipefail
: "${OATH_TEST_DATABASE_URL:?set OATH_TEST_DATABASE_URL to an isolated PostgreSQL database}"
: "${OATH_REGISTRY_DATA:?set OATH_REGISTRY_DATA to an isolated directory}"

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cargo test --locked -p oath-registry postgres_api::tests::live_postgres_stage_publish_download_and_revoke
cargo test --locked -p oath-registry object_backend::tests::reads_from_replica_and_repairs_primary
cargo test --locked -p oath-registry billing::tests::rejects_unsigned_webhooks
psql "$OATH_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS registry_events FROM registry_events"
finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"schema_version":1,"started":"%s","finished":"%s","status":"passed"}\n' "$started" "$finished"
