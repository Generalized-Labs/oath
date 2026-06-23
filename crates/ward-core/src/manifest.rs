//! Extended package manifest with security metadata
//!
//! Compatible with package.json but adds a "ward" section
//! for permissions, provenance, and capability declarations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::permissions::Permissions;

/// Standard package.json + ward extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub main: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub types: Option<String>,
    #[serde(default)]
    pub bin: Option<BinField>,
    #[serde(default)]
    pub scripts: HashMap<String, String>,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    /// Ward security extensions
    #[serde(default)]
    pub ward: Option<WardSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BinField {
    Single(String),
    Map(HashMap<String, String>),
}

/// The "ward" section in package.json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WardSection {
    /// Declared permissions/capabilities
    #[serde(default)]
    pub permissions: Permissions,

    /// Content hash of the published artifact (set by registry)
    #[serde(default)]
    pub integrity: Option<String>,

    /// Provenance attestation (OIDC subject + build info)
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// OIDC identity that published (e.g., "github:user/repo")
    pub identity: String,
    /// Build system (e.g., "github-actions")
    pub builder: String,
    /// Source commit hash
    pub commit: String,
    /// Timestamp
    pub timestamp: String,
    /// Sigstore bundle (base64)
    pub signature: Option<String>,
}
