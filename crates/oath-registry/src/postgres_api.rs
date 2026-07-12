use std::{path::Path, sync::Arc};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    ApiError, DecisionRequest, PackageRoleRequest, Principal, RevokeRequest, StageRecord,
    StageRequest, TokenRequest, TransparencyCheckpoint,
    billing::StripeBilling,
    control_plane::PostgresControlPlane,
    hex_sha256,
    identity::{InvitationMailer, OidcVerifier},
    merkle_root,
    metrics::RegistryMetrics,
    now,
    object_backend::ArtifactStore,
    registry_signing_key,
};

#[derive(Clone)]
pub struct PostgresRegistry {
    control: PostgresControlPlane,
    objects: ArtifactStore,
    signing_key: SigningKey,
    oidc: Option<OidcVerifier>,
    mailer: Option<InvitationMailer>,
    public_url: String,
    metrics: RegistryMetrics,
    billing: Option<StripeBilling>,
}

impl PostgresRegistry {
    pub async fn connect(
        database_url: &str,
        objects: ArtifactStore,
        key_path: &Path,
    ) -> Result<Self> {
        let oidc = match (
            std::env::var("OATH_OIDC_ISSUER").ok(),
            std::env::var("OATH_OIDC_AUDIENCE").ok(),
        ) {
            (Some(issuer), Some(audience)) => {
                Some(OidcVerifier::discover(&issuer, &audience).await?)
            }
            (None, None) => None,
            _ => {
                anyhow::bail!("OATH_OIDC_ISSUER and OATH_OIDC_AUDIENCE must be configured together")
            }
        };
        let mailer = match (
            std::env::var("OATH_RESEND_API_KEY").ok(),
            std::env::var("OATH_EMAIL_FROM").ok(),
        ) {
            (Some(key), Some(from)) => Some(InvitationMailer::resend(key, from)),
            (None, None) => None,
            _ => {
                anyhow::bail!("OATH_RESEND_API_KEY and OATH_EMAIL_FROM must be configured together")
            }
        };
        let billing = match (
            std::env::var("STRIPE_SECRET_KEY").ok(),
            std::env::var("STRIPE_WEBHOOK_SECRET").ok(),
        ) {
            (Some(key), Some(webhook)) => Some(StripeBilling::new(key, webhook)),
            (None, None) => None,
            _ => anyhow::bail!(
                "STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET must be configured together"
            ),
        };
        Ok(Self {
            control: PostgresControlPlane::connect(database_url).await?,
            objects,
            signing_key: registry_signing_key(key_path)?,
            oidc,
            mailer,
            public_url: std::env::var("OATH_PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:4873".into()),
            metrics: RegistryMetrics::default(),
            billing,
        })
    }

    async fn issue_identity_token(&self, organization: &str, role: &str) -> Result<String> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!(error))?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        self.control
            .insert_token(
                &hex_sha256(token.as_bytes()),
                organization,
                role,
                now().saturating_add(3600) as i64,
            )
            .await?;
        Ok(token)
    }

    pub async fn bootstrap_token(&self, organization: &str, token: &str, role: &str) -> Result<()> {
        self.control
            .bootstrap_token(organization, &hex_sha256(token.as_bytes()), role)
            .await
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, ApiError> {
        let token = bearer(headers)?;
        self.control
            .authenticate(&hex_sha256(token.as_bytes()))
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(ApiError::unauthorized)
    }

    async fn authorize_name(
        &self,
        principal: &Principal,
        name: &str,
        write: bool,
    ) -> Result<(), ApiError> {
        if write && !matches!(principal.role.as_str(), "publisher" | "admin") {
            return Err(ApiError::forbidden("publisher role required"));
        }
        if let Some(scope) = name
            .strip_prefix('@')
            .and_then(|value| value.split('/').next())
            && scope != principal.organization
            && principal.role != "admin"
        {
            let role = self
                .control
                .package_role(name, &principal.organization)
                .await
                .map_err(ApiError::internal)?;
            let allowed = matches!(
                (write, role.as_deref()),
                (false, Some(_)) | (true, Some("publisher" | "admin"))
            );
            if !allowed {
                return Err(ApiError::forbidden(
                    "private scope belongs to another organization",
                ));
            }
        }
        Ok(())
    }

    async fn append_event(&self, event: &Value) -> Result<()> {
        let previous = self
            .control
            .latest_event_hash()
            .await?
            .unwrap_or_else(|| "GENESIS".into());
        let event_json = serde_json::to_string(event)?;
        let event_hash = hex_sha256(format!("{previous}{event_json}").as_bytes());
        let signature = base64::engine::general_purpose::STANDARD
            .encode(self.signing_key.sign(event_hash.as_bytes()).to_bytes());
        self.control
            .append_event(&event_json, &previous, &event_hash, &signature)
            .await
    }
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)
}

async fn health() -> Json<Value> {
    Json(
        json!({"status":"ok","service":"oath-registry","control_plane":"postgresql","schema_version":1}),
    )
}

async fn create_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<StageRequest>,
) -> Result<(StatusCode, Json<StageRecord>), ApiError> {
    registry.metrics.request();
    let principal = registry.authenticate(&headers).await?;
    registry
        .authorize_name(&principal, &request.name, true)
        .await?;
    request
        .version
        .parse::<node_semver::Version>()
        .map_err(|_| ApiError::bad("invalid semantic version"))?;
    let tarball = base64::engine::general_purpose::STANDARD
        .decode(&request.tarball_base64)
        .map_err(|_| ApiError::bad("invalid tarball base64"))?;
    let digest = hex_sha256(&tarball);
    registry
        .objects
        .put_immutable(&digest, &tarball)
        .await
        .map_err(ApiError::internal)?;
    registry.metrics.stage();
    let created_at = now();
    let stage = StageRecord {
        id: hex_sha256(
            format!(
                "{}:{}:{}:{}:{created_at}",
                principal.organization, request.name, request.version, digest
            )
            .as_bytes(),
        ),
        organization: principal.organization,
        name: request.name,
        version: request.version,
        tag: request.tag,
        digest,
        status: "staged".into(),
        private: request.private,
        assessment: request.assessment,
        created_at,
    };
    registry
        .control
        .create_stage(&stage)
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"stage.created","id":stage.id,"organization":stage.organization,"name":stage.name,"version":stage.version,"digest":stage.digest})).await.map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(stage)))
}

async fn list_stages(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
) -> Result<Json<Vec<StageRecord>>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    Ok(Json(
        registry
            .control
            .list_stages(&principal.organization)
            .await
            .map_err(ApiError::internal)?,
    ))
}

async fn view_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<StageRecord>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    let stage = registry
        .control
        .read_stage(&id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("stage not found"))?;
    if stage.organization != principal.organization && principal.role != "admin" {
        return Err(ApiError::forbidden("stage belongs to another organization"));
    }
    Ok(Json(stage))
}

async fn download_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let Json(stage) = view_stage(State(registry.clone()), headers, AxumPath(id)).await?;
    let bytes = registry
        .objects
        .get(&stage.digest)
        .await
        .map_err(ApiError::internal)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn decide(
    registry: Arc<PostgresRegistry>,
    headers: HeaderMap,
    id: String,
    approve: bool,
    reason: Option<String>,
) -> Result<Json<StageRecord>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin approval required"));
    }
    let stage = registry
        .control
        .read_stage(&id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("stage not found"))?;
    registry
        .control
        .decide_stage(&stage, approve, reason.as_deref())
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":if approve {"stage.approved"} else {"stage.rejected"},"id":id,"organization":principal.organization,"name":stage.name,"version":stage.version,"reason":reason})).await.map_err(ApiError::internal)?;
    Ok(Json(
        registry
            .control
            .read_stage(&id)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError::internal("stage disappeared"))?,
    ))
}

async fn approve_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<StageRecord>, ApiError> {
    decide(registry, headers, id, true, request.reason).await
}
async fn reject_stage(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<StageRecord>, ApiError> {
    decide(registry, headers, id, false, request.reason).await
}

async fn package_metadata(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    registry.authorize_name(&principal, &name, false).await?;
    let mut versions = serde_json::Map::new();
    for row in registry
        .control
        .package_versions(&name)
        .await
        .map_err(ApiError::internal)?
    {
        versions.insert(row.version, json!({"dist":{"integrity":format!("sha256-{}",row.digest)},"oath":{"status":row.status,"private":row.private,"assessment":row.assessment,"published_at":row.published_at}}));
    }
    let tags = registry
        .control
        .dist_tags(&name)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect::<serde_json::Map<_, _>>();
    Ok(Json(
        json!({"name":name,"dist-tags":tags,"versions":versions}),
    ))
}

async fn revoke_version(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath((name, version)): AxumPath<(String, String)>,
    Json(request): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    registry.authorize_name(&principal, &name, true).await?;
    let status = if request.quarantine {
        "quarantined"
    } else {
        "revoked"
    };
    let payload = json!({"name":name,"version":version,"status":status,"reason":request.reason,"actor_org":principal.organization,"created_at":now()});
    let bytes = serde_json::to_vec(&payload).map_err(ApiError::internal)?;
    let signature = base64::engine::general_purpose::STANDARD
        .encode(registry.signing_key.sign(&bytes).to_bytes());
    let public_key = base64::engine::general_purpose::STANDARD
        .encode(registry.signing_key.verifying_key().to_bytes());
    if !registry
        .control
        .revoke_version(
            &name,
            &version,
            status,
            &request.reason,
            &principal.organization,
            &signature,
            &public_key,
        )
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found("package version not found"));
    }
    registry.append_event(&json!({"type":"version.revoked","tombstone":payload,"signature":signature,"public_key":public_key})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"name":name,"version":version,"status":status,"reason":request.reason,"signature":signature,"public_key":public_key}),
    ))
}

async fn download_version(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath((name, version)): AxumPath<(String, String)>,
) -> Result<Response, ApiError> {
    registry.metrics.request();
    let row = registry
        .control
        .version(&name, &version)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("package version not found"))?;
    if row.status != "active" {
        return Err(ApiError::forbidden(format!(
            "package version is {}",
            row.status
        )));
    }
    if row.private {
        let principal = registry.authenticate(&headers).await?;
        if principal.organization != row.organization && principal.role != "admin" {
            return Err(ApiError::forbidden(
                "private package belongs to another organization",
            ));
        }
    }
    let bytes = registry
        .objects
        .get(&row.digest)
        .await
        .map_err(ApiError::internal)?;
    registry.metrics.download();
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn metrics(State(registry): State<Arc<PostgresRegistry>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        registry.metrics.prometheus(),
    )
        .into_response()
}

async fn admin_summary(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        registry.metrics.denied();
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(Json(
        json!({"service":"oath-registry","control_plane":"postgresql","organization":principal.organization,"metrics":registry.metrics.snapshot()}),
    ))
}

async fn admin_ui() -> Html<&'static str> {
    Html(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Oath Registry Administration</title><style>body{font:16px system-ui;max-width:900px;margin:4rem auto;padding:0 1rem;background:#0b0d10;color:#e8edf2}button,input{font:inherit;padding:.7rem}pre{background:#151a20;padding:1rem;overflow:auto}.card{border:1px solid #303842;border-radius:12px;padding:1.25rem}</style><h1>Oath Registry</h1><div class="card"><p>Paste a short-lived administrator token. It stays in this tab.</p><input id="token" type="password" size="50" autocomplete="off"><button id="load">Load control-plane status</button><pre id="output">No data loaded.</pre></div><script>load.onclick=async()=>{const r=await fetch('/-/oath/admin/summary',{headers:{Authorization:'Bearer '+token.value}});output.textContent=JSON.stringify(await r.json(),null,2)}</script>"#,
    )
}

async fn checkpoint(
    State(registry): State<Arc<PostgresRegistry>>,
) -> Result<Json<TransparencyCheckpoint>, ApiError> {
    let hashes = registry
        .control
        .event_hashes()
        .await
        .map_err(ApiError::internal)?;
    let root = merkle_root(hashes.clone());
    let signature = base64::engine::general_purpose::STANDARD
        .encode(registry.signing_key.sign(root.as_bytes()).to_bytes());
    Ok(Json(TransparencyCheckpoint {
        schema_version: 1,
        event_count: hashes.len(),
        merkle_root: root,
        latest_hash: hashes.last().cloned(),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(registry.signing_key.verifying_key().to_bytes()),
        signature,
    }))
}

async fn issue_token(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid token role"));
    }
    if !(60..=86_400).contains(&request.ttl_secs) {
        return Err(ApiError::bad(
            "token ttl must be between 60 and 86400 seconds",
        ));
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(ApiError::internal)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    registry
        .control
        .insert_token(
            &hex_sha256(token.as_bytes()),
            &principal.organization,
            &request.role,
            now().saturating_add(request.ttl_secs) as i64,
        )
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"token.issued","organization":principal.organization,"role":request.role,"expires_at":now()+request.ttl_secs})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","role":request.role,"expires_in":request.ttl_secs}),
    ))
}

async fn grant_role(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(request): Json<PackageRoleRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    registry.authorize_name(&principal, &name, true).await?;
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid package role"));
    }
    registry
        .control
        .grant_package_role(
            &name,
            &principal.organization,
            &request.principal_org,
            &request.role,
        )
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"package.role_granted","name":name,"owner_org":principal.organization,"principal_org":request.principal_org,"role":request.role})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"name":name,"principal_org":request.principal_org,"role":request.role}),
    ))
}

#[derive(Deserialize)]
struct InvitationRequest {
    email: String,
    role: String,
    #[serde(default = "invitation_ttl")]
    ttl_secs: u64,
}
fn invitation_ttl() -> u64 {
    86_400
}
#[derive(Deserialize)]
struct InvitationAcceptRequest {
    invitation_token: String,
    id_token: String,
}
#[derive(Deserialize)]
struct SsoExchangeRequest {
    id_token: String,
}

async fn create_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<InvitationRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !matches!(request.role.as_str(), "reader" | "publisher" | "admin") {
        return Err(ApiError::bad("invalid invitation role"));
    }
    if !(300..=604_800).contains(&request.ttl_secs) {
        return Err(ApiError::bad(
            "invitation ttl must be between 300 and 604800 seconds",
        ));
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(ApiError::internal)?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let token_hash = hex_sha256(token.as_bytes());
    let expires_at = now().saturating_add(request.ttl_secs);
    registry
        .control
        .create_invitation(
            &token_hash,
            &principal.organization,
            &request.email,
            &request.role,
            expires_at as i64,
        )
        .await
        .map_err(ApiError::internal)?;
    let accept_url = format!(
        "{}/invitations/accept?token={}",
        registry.public_url.trim_end_matches('/'),
        token
    );
    let mailer = registry
        .mailer
        .as_ref()
        .ok_or_else(|| ApiError::internal("invitation email provider is not configured"))?;
    mailer
        .send_invitation(&request.email, &principal.organization, &accept_url)
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"invitation.created","organization":principal.organization,"email_hash":hex_sha256(request.email.as_bytes()),"role":request.role,"expires_at":expires_at})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"status":"sent","token_id":token_hash,"expires_at":expires_at}),
    ))
}

async fn revoke_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    AxumPath(token_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    if !registry
        .control
        .revoke_invitation(&token_id, &principal.organization)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found("active invitation not found"));
    }
    registry.append_event(&json!({"type":"invitation.revoked","organization":principal.organization,"token_id":token_id})).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"status":"revoked","token_id":token_id})))
}

async fn accept_invitation(
    State(registry): State<Arc<PostgresRegistry>>,
    Json(request): Json<InvitationAcceptRequest>,
) -> Result<Json<Value>, ApiError> {
    let verifier = registry
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC provider is not configured"))?;
    let claims = verifier
        .verify(&request.id_token)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    if !claims.email_verified {
        return Err(ApiError::forbidden("OIDC email is not verified"));
    }
    let email = claims
        .email
        .ok_or_else(|| ApiError::forbidden("OIDC identity has no email"))?;
    let token_hash = hex_sha256(request.invitation_token.as_bytes());
    let invitation = registry
        .control
        .accept_invitation(&token_hash, &claims.sub, &email)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("active invitation not found"))?;
    let token = registry
        .issue_identity_token(&invitation.organization, &invitation.role)
        .await
        .map_err(ApiError::internal)?;
    registry.append_event(&json!({"type":"invitation.accepted","organization":invitation.organization,"subject_hash":hex_sha256(claims.sub.as_bytes()),"email_hash":hex_sha256(email.as_bytes()),"role":invitation.role})).await.map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","expires_in":3600,"organization":invitation.organization,"role":invitation.role}),
    ))
}

async fn sso_exchange(
    State(registry): State<Arc<PostgresRegistry>>,
    Json(request): Json<SsoExchangeRequest>,
) -> Result<Json<Value>, ApiError> {
    let verifier = registry
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::internal("OIDC provider is not configured"))?;
    let claims = verifier
        .verify(&request.id_token)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    let (organization, role) = registry
        .control
        .membership(&claims.sub)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::forbidden("identity is not an organization member"))?;
    let token = registry
        .issue_identity_token(&organization, &role)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","expires_in":3600,"organization":organization,"role":role}),
    ))
}

#[derive(Deserialize)]
struct CheckoutRequest {
    price_id: String,
    success_url: String,
    cancel_url: String,
}

async fn billing_checkout(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    Json(request): Json<CheckoutRequest>,
) -> Result<Json<Value>, ApiError> {
    let principal = registry.authenticate(&headers).await?;
    if principal.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    let billing = registry
        .billing
        .as_ref()
        .ok_or_else(|| ApiError::internal("billing provider is not configured"))?;
    let url = billing
        .create_checkout(
            &principal.organization,
            &request.price_id,
            &request.success_url,
            &request.cancel_url,
        )
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"checkout_url":url})))
}

async fn billing_webhook(
    State(registry): State<Arc<PostgresRegistry>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let billing = registry
        .billing
        .as_ref()
        .ok_or_else(|| ApiError::internal("billing provider is not configured"))?;
    let event = billing
        .verify_webhook(signature, &body, now())
        .map_err(|_| ApiError::unauthorized())?;
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("billing event has no id"))?;
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("billing event has no type"))?;
    registry
        .control
        .record_billing_event(id, event_type, &event)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router(registry: PostgresRegistry) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/-/oath/stages", post(create_stage).get(list_stages))
        .route("/-/oath/stages/{id}", get(view_stage))
        .route("/-/oath/stages/{id}/download", get(download_stage))
        .route("/-/oath/stages/{id}/approve", post(approve_stage))
        .route("/-/oath/stages/{id}/reject", post(reject_stage))
        .route(
            "/-/oath/versions/{name}/{version}/revoke",
            post(revoke_version),
        )
        .route("/-/oath/tarballs/{name}/{version}", get(download_version))
        .route("/-/oath/transparency/checkpoint", get(checkpoint))
        .route("/-/oath/tokens", post(issue_token))
        .route("/metrics", get(metrics))
        .route("/-/oath/admin/summary", get(admin_summary))
        .route("/-/oath/admin", get(admin_ui))
        .route("/-/oath/invitations", post(create_invitation))
        .route(
            "/-/oath/invitations/{token_id}/revoke",
            post(revoke_invitation),
        )
        .route("/-/oath/invitations/accept", post(accept_invitation))
        .route("/-/oath/sso/exchange", post(sso_exchange))
        .route("/-/oath/billing/checkout", post(billing_checkout))
        .route("/-/oath/billing/webhook", post(billing_webhook))
        .route("/-/oath/packages/{name}/roles", post(grant_role))
        .route("/{name}", get(package_metadata))
        .with_state(Arc::new(registry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use object_store::memory::InMemory;
    use tower::ServiceExt;

    #[tokio::test]
    async fn live_postgres_stage_publish_download_and_revoke() {
        let Ok(database_url) = std::env::var("OATH_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(Arc::new(InMemory::new()));
        let registry = PostgresRegistry::connect(&database_url, store, &temp.path().join("key"))
            .await
            .unwrap();
        registry
            .bootstrap_token("acme", "secret", "admin")
            .await
            .unwrap();
        let app = router(registry);
        let body = json!({"name":"@acme/tool","version":"1.0.0","tag":"latest","tarball_base64":base64::engine::general_purpose::STANDARD.encode(b"tarball"),"assessment":{"decision":"allow"},"private":true});
        let response = app
            .clone()
            .oneshot(
                Request::post("/-/oath/stages")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let stage: StageRecord =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/-/oath/stages/{}/approve", stage.id))
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"reason":"verified"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(
                Request::get("/-/oath/tarballs/@acme%2Ftool/1.0.0")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            b"tarball".as_slice()
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/-/oath/versions/@acme%2Ftool/1.0.0/revoke")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"reason":"bad release"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
