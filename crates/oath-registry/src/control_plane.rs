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
    pub version: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub assessment: Value,
    pub published_at: i64,
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
    ) -> Result<()> {
        query("INSERT INTO tokens(token_hash,organization,role,expires_at,kind) VALUES ($1,$2,$3,$4,'short-lived')")
            .bind(hash).bind(organization).bind(role).bind(expires_at).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn authenticate(&self, hash: &str) -> Result<Option<Principal>> {
        let row = query("SELECT organization,role FROM tokens WHERE token_hash=$1 AND (expires_at IS NULL OR expires_at>$2)")
            .bind(hash).bind(crate::now() as i64).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| Principal {
            organization: row.get("organization"),
            role: row.get("role"),
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

    pub async fn create_stage(&self, stage: &StageRecord) -> Result<()> {
        query("INSERT INTO stages(id,organization,name,version,tag,digest,status,private,assessment,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&stage.id).bind(&stage.organization).bind(&stage.name).bind(&stage.version)
            .bind(&stage.tag).bind(&stage.digest).bind(&stage.status).bind(stage.private)
            .bind(&stage.assessment).bind(stage.created_at as i64).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn read_stage(&self, id: &str) -> Result<Option<StageRecord>> {
        let row = query("SELECT id,organization,name,version,tag,digest,status,private,assessment,created_at FROM stages WHERE id=$1")
            .bind(id).fetch_optional(&self.pool).await?;
        Ok(row.map(stage_from_row))
    }

    pub async fn list_stages(&self, organization: &str) -> Result<Vec<StageRecord>> {
        Ok(query("SELECT id,organization,name,version,tag,digest,status,private,assessment,created_at FROM stages WHERE organization=$1 ORDER BY created_at DESC")
            .bind(organization).fetch_all(&self.pool).await?.into_iter().map(stage_from_row).collect())
    }

    pub async fn decide_stage(
        &self,
        stage: &StageRecord,
        approve: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        if approve {
            query("UPDATE stages SET status='approved',decision_reason=$2 WHERE id=$1 AND status='staged'").bind(&stage.id).bind(reason).execute(&mut *tx).await?;
            query("INSERT INTO versions(name,version,organization,digest,status,private,assessment,published_at) VALUES ($1,$2,$3,$4,'active',$5,$6,$7)")
                .bind(&stage.name).bind(&stage.version).bind(&stage.organization).bind(&stage.digest).bind(stage.private).bind(&stage.assessment).bind(crate::now() as i64).execute(&mut *tx).await?;
            query("INSERT INTO dist_tags(name,tag,version) VALUES ($1,$2,$3) ON CONFLICT (name,tag) DO UPDATE SET version=EXCLUDED.version")
                .bind(&stage.name).bind(&stage.tag).bind(&stage.version).execute(&mut *tx).await?;
        } else {
            query("UPDATE stages SET status='rejected',decision_reason=$2 WHERE id=$1 AND status='staged'").bind(&stage.id).bind(reason).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn append_event(
        &self,
        event_json: &str,
        previous: &str,
        hash: &str,
        signature: &str,
    ) -> Result<()> {
        query("INSERT INTO registry_events(event_json,previous_hash,event_hash,signature,created_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(event_json).bind(previous).bind(hash).bind(signature).bind(crate::now() as i64).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn event_hashes(&self) -> Result<Vec<String>> {
        Ok(
            query_scalar("SELECT event_hash FROM registry_events ORDER BY sequence")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn latest_event_hash(&self) -> Result<Option<String>> {
        Ok(
            query_scalar("SELECT event_hash FROM registry_events ORDER BY sequence DESC LIMIT 1")
                .fetch_optional(&self.pool)
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

    pub async fn package_versions(&self, name: &str) -> Result<Vec<PackageVersionRecord>> {
        let rows = query("SELECT version,digest,status,private,assessment,published_at FROM versions WHERE name=$1 ORDER BY published_at")
            .bind(name).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| PackageVersionRecord {
                version: row.get("version"),
                digest: row.get("digest"),
                status: row.get("status"),
                private: row.get("private"),
                assessment: row.get("assessment"),
                published_at: row.get("published_at"),
            })
            .collect())
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
        signature: &str,
        public_key: &str,
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
            .bind(name).bind(version).bind(status).bind(reason).bind(actor_org).bind(crate::now() as i64).bind(signature).bind(public_key).execute(&mut *tx).await?;
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
        }
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
        assessment: row.get::<Value, _>("assessment"),
        created_at: row.get::<i64, _>("created_at") as u64,
    }
}
