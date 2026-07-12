use anyhow::Result;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub mod billing;
pub mod control_plane;
pub mod identity;
pub mod metrics;
pub mod object_backend;
pub mod postgres_api;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(crate) fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid or missing bearer token".into(),
        }
    }
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    pub(crate) fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub organization: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct TransparencyCheckpoint {
    pub schema_version: u32,
    pub event_count: usize,
    pub merkle_root: String,
    pub latest_hash: Option<String>,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct StageRequest {
    pub name: String,
    pub version: String,
    #[serde(default = "latest_tag")]
    pub tag: String,
    pub tarball_base64: String,
    pub assessment: Value,
    #[serde(default)]
    pub private: bool,
}

fn latest_tag() -> String {
    "latest".into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageRecord {
    pub id: String,
    pub organization: String,
    pub name: String,
    pub version: String,
    pub tag: String,
    pub digest: String,
    pub status: String,
    pub private: bool,
    pub assessment: Value,
    pub created_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub reason: String,
    #[serde(default)]
    pub quarantine: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub role: String,
    #[serde(default = "default_token_ttl")]
    pub ttl_secs: u64,
}

fn default_token_ttl() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
pub struct PackageRoleRequest {
    pub principal_org: String,
    pub role: String,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn registry_signing_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid registry signing key"))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("registry key generation failed: {error}"))?;
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn merkle_root(mut hashes: Vec<String>) -> String {
    if hashes.is_empty() {
        return hex_sha256(&[]);
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(hashes.last().expect("nonempty").clone());
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| hex_sha256(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    hashes.remove(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merkle_checkpoints_are_deterministic() {
        assert_eq!(
            merkle_root(vec!["a".into(), "b".into()]),
            merkle_root(vec!["a".into(), "b".into()])
        );
        assert_ne!(merkle_root(vec!["a".into()]), merkle_root(vec!["b".into()]));
    }
}
