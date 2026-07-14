use anyhow::{Context, Result};
use serde_json::Value;
use sqlx_core::{query::query, query_scalar::query_scalar, raw_sql::raw_sql, row::Row};
use sqlx_postgres::{PgPool, PgPoolOptions, PgRow};

use crate::{Principal, StageRecord};

#[derive(Clone)]
pub struct PostgresControlPlane {
    pool: PgPool,
}

#[derive(Debug)]
pub struct VersionRecord {
    pub organization: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
}

#[derive(Debug)]
pub struct PackageVersionRecord {
    pub organization: String,
    pub version: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub manifest: Value,
    pub assessment: Value,
    pub server_evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
    pub published_at: i64,
    pub download_count: i64,
}

#[derive(Debug)]
pub struct PackageRecord {
    pub organization: String,
    pub private: bool,
}

#[derive(Debug)]
pub struct VersionBundleRecord {
    pub organization: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub assessment: Value,
    pub server_evidence: Value,
    pub sbom: Value,
    pub provenance: Value,
    pub published_at: i64,
    pub download_count: i64,
    pub tombstone: Option<Value>,
}

#[derive(Debug)]
pub struct InvitationRecord {
    pub organization: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
}

impl PostgresControlPlane {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(20)
            .connect(url)
            .await
            .context("connect PostgreSQL control plane")?;
        let control = Self { pool };
        control.migrate().await?;
        Ok(control)
    }

    async fn migrate(&self) -> Result<()> {
        raw_sql(include_str!("../migrations/0001_registry.sql"))
            .execute(&self.pool)
            .await
            .context("migrate PostgreSQL control plane")?;
        raw_sql(include_str!("../migrations/0002_ga_foundation.sql"))
            .execute(&self.pool)
            .await
            .context("migrate GA foundation schema")?;
        Ok(())
    }

    pub async fn bootstrap_token(&self, organization: &str, hash: &str, role: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        query("INSERT INTO organizations(name,created_at) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING")
            .bind(organization).bind(crate::now() as i64).execute(&mut *tx).await?;
        query("INSERT INTO tokens(token_hash,organization,role,expires_at,kind) VALUES ($1,$2,$3,NULL,'bootstrap') ON CONFLICT (token_hash) DO UPDATE SET organization=EXCLUDED.organization, role=EXCLUDED.role, expires_at=NULL, kind='bootstrap'")
            .bind(hash).bind(organization).bind(role).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn insert_token(
        &self,
        hash: &str,
        organization: &str,
        role: &str,
        expires_at: i64,
        kind: &str,
    ) -> Result<()> {
        query("INSERT INTO tokens(token_hash,organization,role,expires_at,kind) VALUES ($1,$2,$3,$4,$5)")
            .bind(hash).bind(organization).bind(role).bind(expires_at).bind(kind).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn authenticate(&self, hash: &str) -> Result<Option<Principal>> {
        let row = query("SELECT organization,role,kind FROM tokens WHERE token_hash=$1 AND (expires_at IS NULL OR expires_at>$2)")
            .bind(hash).bind(crate::now() as i64).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| Principal {
            organization: row.get("organization"),
            role: row.get("role"),
            kind: row.get("kind"),
        }))
    }

    pub async fn package_role(&self, name: &str, organization: &str) -> Result<Option<String>> {
        Ok(
            query_scalar("SELECT role FROM package_roles WHERE name=$1 AND principal_org=$2")
                .bind(name)
                .bind(organization)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn package(&self, name: &str) -> Result<Option<PackageRecord>> {
        let row = query("SELECT organization,private FROM packages WHERE name=$1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| PackageRecord {
            organization: row.get("organization"),
            private: row.get("private"),
        }))
    }

    pub async fn create_stage(
        &self,
        stage: &StageRecord,
        event_key: &str,
        event: &Value,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        query("INSERT INTO packages(name,organization,private,created_at) VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING")
            .bind(&stage.name).bind(&stage.organization).bind(stage.private).bind(stage.created_at as i64).execute(&mut *tx).await?;
        let package = query("SELECT organization,private FROM packages WHERE name=$1 FOR UPDATE")
            .bind(&stage.name)
            .fetch_one(&mut *tx)
            .await?;
        let owner: String = package.get("organization");
        let private: bool = package.get("private");
        anyhow::ensure!(
            owner == stage.organization,
            "package belongs to another organization"
        );
        anyhow::ensure!(
            private == stage.private,
            "package visibility cannot change between versions"
        );
        query("INSERT INTO stages(id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(&stage.id).bind(&stage.organization).bind(&stage.name).bind(&stage.version)
            .bind(&stage.tag).bind(&stage.digest).bind(&stage.status).bind(stage.private)
            .bind(&stage.manifest).bind(&stage.publisher_assessment).bind(&stage.assessment)
            .bind(&stage.server_evidence).bind(&stage.sbom).bind(&stage.provenance)
            .bind(stage.created_at as i64).execute(&mut *tx).await?;
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn read_stage(&self, id: &str) -> Result<Option<StageRecord>> {
        let row = query("SELECT id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at FROM stages WHERE id=$1")
            .bind(id).fetch_optional(&self.pool).await?;
        Ok(row.map(stage_from_row))
    }

    pub async fn list_stages(&self, organization: &str) -> Result<Vec<StageRecord>> {
        Ok(query("SELECT id,organization,name,version,tag,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,created_at FROM stages WHERE stages.organization=$1 OR EXISTS (SELECT 1 FROM package_roles WHERE package_roles.name=stages.name AND package_roles.principal_org=$1) ORDER BY created_at DESC")
            .bind(organization).fetch_all(&self.pool).await?.into_iter().map(stage_from_row).collect())
    }

    pub async fn decide_stage(
        &self,
        stage: &StageRecord,
        approve: bool,
        reason: Option<&str>,
        event_key: &str,
        event: &Value,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let status: Option<String> =
            query_scalar("SELECT status FROM stages WHERE id=$1 FOR UPDATE")
                .bind(&stage.id)
                .fetch_optional(&mut *tx)
                .await?;
        if status.as_deref() != Some("staged") {
            tx.rollback().await?;
            return Ok(false);
        }
        if approve {
            query("UPDATE stages SET status='approved',decision_reason=$2 WHERE id=$1")
                .bind(&stage.id)
                .bind(reason)
                .execute(&mut *tx)
                .await?;
            query("INSERT INTO versions(name,version,organization,digest,status,private,manifest,publisher_assessment,assessment,server_evidence,sbom,provenance,published_at) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(&stage.name).bind(&stage.version).bind(&stage.organization).bind(&stage.digest)
                .bind(stage.private).bind(&stage.manifest).bind(&stage.publisher_assessment)
                .bind(&stage.assessment).bind(&stage.server_evidence).bind(&stage.sbom)
                .bind(&stage.provenance).bind(crate::now() as i64).execute(&mut *tx).await?;
            query("INSERT INTO dist_tags(name,tag,version) VALUES ($1,$2,$3) ON CONFLICT (name,tag) DO UPDATE SET version=EXCLUDED.version")
                .bind(&stage.name).bind(&stage.tag).bind(&stage.version).execute(&mut *tx).await?;
        } else {
            query("UPDATE stages SET status='rejected',decision_reason=$2 WHERE id=$1")
                .bind(&stage.id)
                .bind(reason)
                .execute(&mut *tx)
                .await?;
        }
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn event_hashes(&self) -> Result<Vec<String>> {
        Ok(
            query_scalar("SELECT event_hash FROM registry_events ORDER BY sequence")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn version(&self, name: &str, version: &str) -> Result<Option<VersionRecord>> {
        let row = query(
            "SELECT organization,digest,status,private FROM versions WHERE name=$1 AND version=$2",
        )
        .bind(name)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| VersionRecord {
            organization: row.get("organization"),
            digest: row.get("digest"),
            status: row.get("status"),
            private: row.get("private"),
        }))
    }

    pub async fn version_bundle(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionBundleRecord>> {
        let row = query("SELECT versions.organization,versions.digest,versions.status,versions.private,versions.assessment,versions.server_evidence,versions.sbom,versions.provenance,versions.published_at,versions.download_count,to_jsonb(tombstones) AS tombstone FROM versions LEFT JOIN tombstones USING (name,version) WHERE versions.name=$1 AND versions.version=$2")
            .bind(name).bind(version).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| VersionBundleRecord {
            organization: row.get("organization"),
            digest: row.get("digest"),
            status: row.get("status"),
            private: row.get("private"),
            assessment: row.get("assessment"),
            server_evidence: row.get("server_evidence"),
            sbom: row.get("sbom"),
            provenance: row.get("provenance"),
            published_at: row.get("published_at"),
            download_count: row.get("download_count"),
            tombstone: row.get("tombstone"),
        }))
    }

    pub async fn public_quarantines(&self) -> Result<Vec<(String, String, String, i64)>> {
        let rows = query("SELECT tombstones.name,tombstones.version,tombstones.reason,tombstones.created_at FROM tombstones JOIN packages USING (name) WHERE tombstones.status='quarantined' AND packages.private=false ORDER BY tombstones.created_at")
            .fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get("name"),
                    row.get("version"),
                    row.get("reason"),
                    row.get("created_at"),
                )
            })
            .collect())
    }

    pub async fn package_versions(&self, name: &str) -> Result<Vec<PackageVersionRecord>> {
        let rows = query("SELECT organization,version,digest,status,private,manifest,assessment,server_evidence,sbom,provenance,published_at,download_count FROM versions WHERE name=$1 AND status='active' ORDER BY published_at")
            .bind(name).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| PackageVersionRecord {
                organization: row.get("organization"),
                version: row.get("version"),
                digest: row.get("digest"),
                status: row.get("status"),
                private: row.get("private"),
                manifest: row.get("manifest"),
                assessment: row.get("assessment"),
                server_evidence: row.get("server_evidence"),
                sbom: row.get("sbom"),
                provenance: row.get("provenance"),
                published_at: row.get("published_at"),
                download_count: row.get("download_count"),
            })
            .collect())
    }

    pub async fn record_download(&self, name: &str, version: &str) -> Result<()> {
        query("UPDATE versions SET download_count=download_count+1 WHERE name=$1 AND version=$2")
            .bind(name)
            .bind(version)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn dist_tags(&self, name: &str) -> Result<Vec<(String, String)>> {
        let rows = query("SELECT tag,version FROM dist_tags WHERE name=$1")
            .bind(name)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("tag"), row.get("version")))
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_version(
        &self,
        name: &str,
        version: &str,
        status: &str,
        reason: &str,
        actor_org: &str,
        created_at: i64,
        signature: &str,
        public_key: &str,
        event_key: &str,
        event: &Value,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let updated = query("UPDATE versions SET status=$3 WHERE name=$1 AND version=$2")
            .bind(name)
            .bind(version)
            .bind(status)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if updated == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        query("INSERT INTO tombstones(name,version,status,reason,actor_org,created_at,signature,public_key) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name,version) DO UPDATE SET status=EXCLUDED.status,reason=EXCLUDED.reason,actor_org=EXCLUDED.actor_org,created_at=EXCLUDED.created_at,signature=EXCLUDED.signature,public_key=EXCLUDED.public_key")
            .bind(name).bind(version).bind(status).bind(reason).bind(actor_org).bind(created_at).bind(signature).bind(public_key).execute(&mut *tx).await?;
        let active: Vec<String> =
            query_scalar("SELECT version FROM versions WHERE name=$1 AND status='active'")
                .bind(name)
                .fetch_all(&mut *tx)
                .await?;
        let rollback = active
            .into_iter()
            .filter_map(|value| {
                value
                    .parse::<node_semver::Version>()
                    .ok()
                    .map(|parsed| (parsed, value))
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, value)| value);
        if let Some(rollback) = rollback {
            query("UPDATE dist_tags SET version=$2 WHERE name=$1 AND version=$3")
                .bind(name)
                .bind(rollback)
                .bind(version)
                .execute(&mut *tx)
                .await?;
        } else {
            query("DELETE FROM dist_tags WHERE name=$1 AND version=$2")
                .bind(name)
                .bind(version)
                .execute(&mut *tx)
                .await?;
        }
        query("INSERT INTO registry_outbox(event_key,event_json,available_at,created_at) VALUES ($1,$2,$3,$3)")
            .bind(event_key).bind(event).bind(crate::now() as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn grant_package_role(
        &self,
        name: &str,
        owner_org: &str,
        principal_org: &str,
        role: &str,
    ) -> Result<()> {
        let package = self.package(name).await?.context("package not found")?;
        anyhow::ensure!(
            package.organization == owner_org,
            "only the package-owning organization may grant roles"
        );
        query("INSERT INTO package_roles(name,organization,principal_org,role) VALUES ($1,$2,$3,$4) ON CONFLICT (name,principal_org) DO UPDATE SET organization=EXCLUDED.organization,role=EXCLUDED.role")
            .bind(name).bind(owner_org).bind(principal_org).bind(role).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_invitation(
        &self,
        token_hash: &str,
        organization: &str,
        email: &str,
        role: &str,
        expires_at: i64,
    ) -> Result<()> {
        query("INSERT INTO invitations(token_hash,organization,email,role,expires_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(token_hash).bind(organization).bind(email).bind(role).bind(expires_at).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn revoke_invitation(&self, token_hash: &str, organization: &str) -> Result<bool> {
        Ok(query("UPDATE invitations SET revoked_at=$3 WHERE token_hash=$1 AND organization=$2 AND accepted_at IS NULL AND revoked_at IS NULL")
            .bind(token_hash).bind(organization).bind(crate::now() as i64).execute(&self.pool).await?.rows_affected() == 1)
    }

    pub async fn accept_invitation(
        &self,
        token_hash: &str,
        subject: &str,
        email: &str,
    ) -> Result<Option<InvitationRecord>> {
        let mut tx = self.pool.begin().await?;
        let row = query("SELECT organization,email,role,expires_at FROM invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>$2 FOR UPDATE")
            .bind(token_hash).bind(crate::now() as i64).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let invitation = InvitationRecord {
            organization: row.get("organization"),
            email: row.get("email"),
            role: row.get("role"),
            expires_at: row.get("expires_at"),
        };
        if !invitation.email.eq_ignore_ascii_case(email) {
            tx.rollback().await?;
            anyhow::bail!("invitation email does not match verified identity");
        }
        query("INSERT INTO organization_members(organization,subject,email,role,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (organization,subject) DO UPDATE SET email=EXCLUDED.email,role=EXCLUDED.role")
            .bind(&invitation.organization).bind(subject).bind(email).bind(&invitation.role).bind(crate::now() as i64).execute(&mut *tx).await?;
        query("UPDATE invitations SET accepted_at=$2 WHERE token_hash=$1")
            .bind(token_hash)
            .bind(crate::now() as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(invitation))
    }

    pub async fn membership(&self, subject: &str) -> Result<Option<(String, String)>> {
        let row = query("SELECT organization,role FROM organization_members WHERE subject=$1 ORDER BY created_at LIMIT 1")
            .bind(subject).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| (row.get("organization"), row.get("role"))))
    }

    pub async fn record_billing_event(
        &self,
        event_id: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<bool> {
        Ok(query("INSERT INTO billing_events(provider_event_id,event_type,payload,received_at) VALUES ($1,$2,$3,$4) ON CONFLICT (provider_event_id) DO NOTHING")
            .bind(event_id).bind(event_type).bind(payload).bind(crate::now() as i64).execute(&self.pool).await?.rows_affected()==1)
    }

    pub async fn pending_outbox(&self, limit: i64) -> Result<Vec<(i64, String, Value)>> {
        let rows = query("SELECT id,event_key,event_json FROM registry_outbox WHERE delivered_at IS NULL AND available_at<=$1 ORDER BY id LIMIT $2")
            .bind(crate::now() as i64).bind(limit).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("id"), row.get("event_key"), row.get("event_json")))
            .collect())
    }

    pub async fn mark_outbox_delivered(&self, id: i64) -> Result<()> {
        query("UPDATE registry_outbox SET delivered_at=$2 WHERE id=$1")
            .bind(id)
            .bind(crate::now() as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn retry_outbox(&self, id: i64) -> Result<()> {
        query("UPDATE registry_outbox SET attempts=attempts+1,available_at=$2 WHERE id=$1")
            .bind(id)
            .bind(crate::now().saturating_add(5) as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn ready(&self) -> Result<()> {
        let value: i32 = query_scalar("SELECT 1").fetch_one(&self.pool).await?;
        anyhow::ensure!(
            value == 1,
            "PostgreSQL readiness query returned an invalid value"
        );
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn stage_from_row(row: PgRow) -> StageRecord {
    StageRecord {
        id: row.get("id"),
        organization: row.get("organization"),
        name: row.get("name"),
        version: row.get("version"),
        tag: row.get("tag"),
        digest: row.get("digest"),
        status: row.get("status"),
        private: row.get("private"),
        manifest: row.get::<Value, _>("manifest"),
        publisher_assessment: row.get::<Value, _>("publisher_assessment"),
        assessment: row.get::<Value, _>("assessment"),
        server_evidence: row.get::<Value, _>("server_evidence"),
        sbom: row.get::<Value, _>("sbom"),
        provenance: row.get::<Value, _>("provenance"),
        created_at: row.get::<i64, _>("created_at") as u64,
    }
}
