//! Oath configuration

use serde::{Deserialize, Serialize};

/// Global oath configuration (~/.oath/config.json or oath.json in project)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OathConfig {
    /// Default registry URL
    #[serde(default = "default_registry")]
    pub registry: String,

    /// Transparency log URL
    #[serde(default = "default_log")]
    pub transparency_log: String,

    /// Local store path
    #[serde(default = "default_store")]
    pub store: String,

    /// Default permission policy
    #[serde(default)]
    pub policy: PermissionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PermissionPolicy {
    /// Prompt for every new permission (default)
    #[default]
    Prompt,
    /// Trust packages with declared permissions below threshold
    TrustLowRisk,
    /// Deny all undeclared permissions (strict)
    Strict,
    /// Allow everything (npm-compatible, unsafe)
    Permissive,
}

fn default_registry() -> String {
    "https://registry.oath.dev".into()
}
fn default_log() -> String {
    "https://log.oath.dev".into()
}
fn default_store() -> String {
    std::env::var("HOME")
        .map(|h| format!("{h}/.oath/store"))
        .unwrap_or_else(|_| "~/.oath/store".into())
}

impl Default for OathConfig {
    fn default() -> Self {
        Self {
            registry: default_registry(),
            transparency_log: default_log(),
            store: default_store(),
            policy: PermissionPolicy::default(),
        }
    }
}
