CREATE TABLE IF NOT EXISTS organizations (name TEXT PRIMARY KEY, created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, organization TEXT NOT NULL REFERENCES organizations(name), role TEXT NOT NULL, expires_at BIGINT, kind TEXT NOT NULL DEFAULT 'service');
CREATE TABLE IF NOT EXISTS packages (name TEXT PRIMARY KEY, organization TEXT NOT NULL REFERENCES organizations(name), private BOOLEAN NOT NULL, created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS package_roles (name TEXT NOT NULL, organization TEXT NOT NULL, principal_org TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY(name,principal_org));
CREATE TABLE IF NOT EXISTS invitations (token_hash TEXT PRIMARY KEY, organization TEXT NOT NULL REFERENCES organizations(name), email TEXT NOT NULL, role TEXT NOT NULL, expires_at BIGINT NOT NULL, accepted_at BIGINT, revoked_at BIGINT);
CREATE TABLE IF NOT EXISTS organization_members (organization TEXT NOT NULL REFERENCES organizations(name), subject TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY(organization,subject));
CREATE TABLE IF NOT EXISTS stages (id TEXT PRIMARY KEY, organization TEXT NOT NULL REFERENCES organizations(name), name TEXT NOT NULL, version TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL, private BOOLEAN NOT NULL, manifest JSONB NOT NULL DEFAULT '{}'::jsonb, assessment JSONB NOT NULL, created_at BIGINT NOT NULL, decision_reason TEXT, UNIQUE(name,version));
CREATE TABLE IF NOT EXISTS versions (name TEXT NOT NULL, version TEXT NOT NULL, organization TEXT NOT NULL REFERENCES organizations(name), digest TEXT NOT NULL, status TEXT NOT NULL, private BOOLEAN NOT NULL, manifest JSONB NOT NULL DEFAULT '{}'::jsonb, assessment JSONB NOT NULL, published_at BIGINT NOT NULL, PRIMARY KEY(name,version));
CREATE TABLE IF NOT EXISTS dist_tags (name TEXT NOT NULL, tag TEXT NOT NULL, version TEXT NOT NULL, PRIMARY KEY(name,tag));
CREATE TABLE IF NOT EXISTS tombstones (name TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, actor_org TEXT NOT NULL, created_at BIGINT NOT NULL, signature TEXT NOT NULL, public_key TEXT NOT NULL, PRIMARY KEY(name,version));
CREATE TABLE IF NOT EXISTS registry_events (sequence BIGSERIAL PRIMARY KEY, event_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE, signature TEXT NOT NULL, created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS billing_events (provider_event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload JSONB NOT NULL, received_at BIGINT NOT NULL);

ALTER TABLE stages ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE versions ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
    IF EXISTS (
        SELECT name
        FROM (
            SELECT name,organization,private FROM versions
            UNION ALL
            SELECT name,organization,private FROM stages
        ) historical_packages
        GROUP BY name
        HAVING COUNT(DISTINCT organization) > 1 OR COUNT(DISTINCT private) > 1
    ) THEN
        RAISE EXCEPTION 'historical package ownership or visibility is ambiguous; repair conflicting rows before migration';
    END IF;
END $$;

INSERT INTO packages(name,organization,private,created_at)
SELECT DISTINCT ON (name) name,organization,private,published_at
FROM versions
ORDER BY name,published_at
ON CONFLICT (name) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM packages
        JOIN (
            SELECT name,organization,private FROM versions
            UNION ALL
            SELECT name,organization,private FROM stages
        ) historical_packages USING (name)
        WHERE packages.organization <> historical_packages.organization
           OR packages.private <> historical_packages.private
    ) THEN
        RAISE EXCEPTION 'package ownership table conflicts with historical release rows';
    END IF;
END $$;

INSERT INTO packages(name,organization,private,created_at)
SELECT DISTINCT ON (name) name,organization,private,created_at
FROM stages
ORDER BY name,created_at
ON CONFLICT (name) DO NOTHING;
