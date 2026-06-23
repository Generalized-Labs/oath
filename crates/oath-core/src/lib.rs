//! oath-core: shared types, config, and error definitions

pub mod manifest;
pub mod permissions;
pub mod integrity;
pub mod config;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OathError {
    #[error("package not found: {0}")]
    PackageNotFound(String),
    #[error("integrity check failed for {package}: expected {expected}, got {actual}")]
    IntegrityMismatch { package: String, expected: String, actual: String },
    #[error("permission denied: {0} requires {1}")]
    PermissionDenied(String, String),
    #[error("transparency log verification failed: {0}")]
    TransparencyVerificationFailed(String),
    #[error("sandbox violation: {package} attempted {action}")]
    SandboxViolation { package: String, action: String },
    #[error("publish rejected: {0}")]
    PublishRejected(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, OathError>;
