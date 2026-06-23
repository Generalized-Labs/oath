//! npm registry packument types
//!
//! These represent the abbreviated packument returned when requesting
//! with Accept: application/vnd.npm.install-v1+json

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Abbreviated packument (install metadata only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packument {
    pub name: String,

    /// Last modified timestamp
    #[serde(default)]
    pub modified: Option<String>,

    /// Distribution tags (e.g., "latest" -> "1.0.0")
    #[serde(default, rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,

    /// All published versions with their metadata
    #[serde(default)]
    pub versions: HashMap<String, VersionInfo>,
}

/// Per-version metadata (abbreviated form)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub name: String,
    pub version: String,

    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependenciesMeta")]
    pub peer_dependencies_meta: HashMap<String, PeerDepMeta>,

    #[serde(default)]
    pub bin: Option<BinField>,

    #[serde(default)]
    pub engines: HashMap<String, String>,

    #[serde(default)]
    pub os: Vec<String>,

    #[serde(default)]
    pub cpu: Vec<String>,

    /// Distribution info (tarball URL, integrity hash)
    pub dist: DistInfo,

    /// Whether this version has install scripts
    #[serde(default, rename = "hasInstallScript")]
    pub has_install_script: bool,

    /// Whether this version has a shrinkwrap
    #[serde(default, rename = "_hasShrinkwrap")]
    pub has_shrinkwrap: bool,

    /// Funding info
    #[serde(default)]
    pub funding: Option<serde_json::Value>,
}

/// Distribution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistInfo {
    /// Tarball download URL
    pub tarball: String,

    /// SHA-1 hash (legacy, but still present)
    #[serde(default)]
    pub shasum: Option<String>,

    /// SRI integrity string (preferred, sha512-based)
    #[serde(default)]
    pub integrity: Option<String>,

    /// Number of files in the package
    #[serde(default, rename = "fileCount")]
    pub file_count: Option<u32>,

    /// Unpacked size in bytes
    #[serde(default, rename = "unpackedSize")]
    pub unpacked_size: Option<u64>,

    /// Registry signatures
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

/// Registry signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

/// Peer dependency metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDepMeta {
    #[serde(default)]
    pub optional: bool,
}

/// Bin field can be a single string or a map
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BinField {
    Single(String),
    Map(HashMap<String, String>),
}

impl Packument {
    /// Get the version string for a given dist-tag (e.g., "latest")
    pub fn dist_tag_version(&self, tag: &str) -> Option<&str> {
        self.dist_tags.get(tag).map(|s| s.as_str())
    }

    /// Get the latest version string
    pub fn latest_version(&self) -> Option<&str> {
        self.dist_tag_version("latest")
    }

    /// Get version info for a specific version string
    pub fn version_info(&self, version: &str) -> Option<&VersionInfo> {
        self.versions.get(version)
    }

    /// Get all version strings
    pub fn all_versions(&self) -> Vec<&str> {
        self.versions.keys().map(|s| s.as_str()).collect()
    }
}
