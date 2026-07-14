ALTER TABLE stages
    ADD COLUMN IF NOT EXISTS publisher_assessment JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE stages
    ADD COLUMN IF NOT EXISTS server_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE stages
    ADD COLUMN IF NOT EXISTS sbom JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE stages
    ADD COLUMN IF NOT EXISTS provenance JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions
    ADD COLUMN IF NOT EXISTS publisher_assessment JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions
    ADD COLUMN IF NOT EXISTS server_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions
    ADD COLUMN IF NOT EXISTS sbom JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions
    ADD COLUMN IF NOT EXISTS provenance JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions
    ADD COLUMN IF NOT EXISTS download_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE registry_events
    ADD COLUMN IF NOT EXISTS event_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS registry_events_event_key_unique
    ON registry_events(event_key) WHERE event_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS registry_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    event_json JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    delivered_at BIGINT
);
CREATE INDEX IF NOT EXISTS registry_outbox_pending
    ON registry_outbox(available_at, id) WHERE delivered_at IS NULL;
