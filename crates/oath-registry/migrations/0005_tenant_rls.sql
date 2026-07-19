DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oath_api') THEN
        CREATE ROLE oath_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oath_worker') THEN
        CREATE ROLE oath_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION oath_current_organization() RETURNS TEXT
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('oath.organization', true), '')
$$;

CREATE OR REPLACE FUNCTION oath_authenticate_token(candidate_hash TEXT, current_epoch BIGINT)
RETURNS TABLE(organization TEXT, role TEXT, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT tokens.organization, tokens.role, tokens.kind
      FROM tokens
     WHERE token_hash = candidate_hash
       AND (expires_at IS NULL OR expires_at > current_epoch)
$$;
REVOKE ALL ON FUNCTION oath_authenticate_token(TEXT, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oath_authenticate_token(TEXT, BIGINT) TO oath_api, oath_worker;

CREATE OR REPLACE FUNCTION oath_lookup_invitation(candidate_hash TEXT, current_epoch BIGINT)
RETURNS TABLE(organization TEXT, email TEXT, role TEXT, expires_at BIGINT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT invitations.organization, invitations.email, invitations.role, invitations.expires_at
      FROM invitations
     WHERE token_hash = candidate_hash AND accepted_at IS NULL AND revoked_at IS NULL
       AND expires_at > current_epoch
$$;
CREATE OR REPLACE FUNCTION oath_lookup_membership(candidate_subject TEXT)
RETURNS TABLE(organization TEXT, role TEXT)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT organization_members.organization, organization_members.role
      FROM organization_members WHERE subject = candidate_subject ORDER BY created_at LIMIT 1
$$;
REVOKE ALL ON FUNCTION oath_lookup_invitation(TEXT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION oath_lookup_membership(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oath_lookup_invitation(TEXT, BIGINT), oath_lookup_membership(TEXT) TO oath_api, oath_worker;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE package_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE versions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_tenant ON organizations;
CREATE POLICY organizations_tenant ON organizations
    USING (name = oath_current_organization())
    WITH CHECK (name = oath_current_organization());
DROP POLICY IF EXISTS tokens_tenant ON tokens;
CREATE POLICY tokens_tenant ON tokens
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS packages_tenant_or_public ON packages;
CREATE POLICY packages_tenant_or_public ON packages
    USING (organization = oath_current_organization() OR private = false OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=packages.name
          AND package_roles.principal_org=oath_current_organization()))
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS package_roles_tenant ON package_roles;
CREATE POLICY package_roles_tenant ON package_roles
    USING (organization = oath_current_organization() OR principal_org = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS invitations_tenant ON invitations;
CREATE POLICY invitations_tenant ON invitations
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS organization_members_tenant ON organization_members;
CREATE POLICY organization_members_tenant ON organization_members
    USING (organization = oath_current_organization())
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS stages_tenant ON stages;
CREATE POLICY stages_tenant ON stages
    USING (organization = oath_current_organization() OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=stages.name
          AND package_roles.principal_org=oath_current_organization()))
    WITH CHECK (organization = oath_current_organization());
DROP POLICY IF EXISTS versions_tenant_or_public ON versions;
CREATE POLICY versions_tenant_or_public ON versions
    USING (organization = oath_current_organization() OR private = false OR EXISTS (
        SELECT 1 FROM package_roles WHERE package_roles.name=versions.name
          AND package_roles.principal_org=oath_current_organization()))
    WITH CHECK (organization = oath_current_organization());

GRANT USAGE ON SCHEMA public TO oath_api, oath_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO oath_worker;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO oath_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, tokens, packages, package_roles,
    invitations, organization_members, stages, versions, dist_tags, tombstones,
    registry_outbox, registry_rate_limits, billing_events TO oath_api;
GRANT SELECT, INSERT ON registry_events TO oath_api;
GRANT SELECT ON registry_schema_version TO oath_api;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO oath_api;

CREATE TABLE IF NOT EXISTS registry_replication_receipts (
    region TEXT NOT NULL,
    event_key TEXT NOT NULL,
    object_digest TEXT,
    checkpoint_root TEXT,
    observed_at BIGINT NOT NULL,
    source_created_at BIGINT NOT NULL,
    PRIMARY KEY(region, event_key)
);
GRANT SELECT, INSERT, UPDATE ON registry_replication_receipts TO oath_worker;

INSERT INTO registry_schema_version(version, applied_at)
VALUES (5, EXTRACT(EPOCH FROM NOW())::BIGINT)
ON CONFLICT (version) DO NOTHING;
