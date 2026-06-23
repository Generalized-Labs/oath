//! Lockfile read/write
//!
//! oath-lock.json format, compatible with npm's package-lock.json concepts
//! but cleaner and verifiable against a transparency log.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::graph::{DepGraph, DepNode};

/// oath-lock.json structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lockfile {
    /// Lock format version
    pub lockfile_version: u32,
    /// Project name
    pub name: String,
    /// Project version
    pub version: String,
    /// All resolved packages
    pub packages: HashMap<String, LockEntry>,
}

/// A single entry in the lockfile
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockEntry {
    /// Exact resolved version
    pub version: String,
    /// Tarball URL
    pub resolved: String,
    /// SRI integrity hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    /// Dependencies: name -> version range
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub dependencies: HashMap<String, String>,
    /// Whether this is dev-only
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dev: bool,
    /// Whether this is optional
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
    /// Has install scripts
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_install_script: bool,
    /// Alias name if installed under a different name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

impl Lockfile {
    /// Create a lockfile from a resolved dependency graph
    pub fn from_graph(graph: &DepGraph, project_name: &str, project_version: &str) -> Self {
        let mut packages = HashMap::new();

        for (key, node) in &graph.nodes {
            packages.insert(
                key.clone(),
                LockEntry {
                    version: node.version.clone(),
                    resolved: node.resolved.clone(),
                    integrity: node.integrity.clone(),
                    dependencies: node.dependencies.clone(),
                    dev: node.dev,
                    optional: node.optional,
                    has_install_script: node.has_install_script,
                    alias: node.alias.clone(),
                },
            );
        }

        Self {
            lockfile_version: 1,
            name: project_name.to_string(),
            version: project_version.to_string(),
            packages,
        }
    }

    /// Write lockfile to disk
    pub fn write(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("failed to serialize lockfile")?;
        std::fs::write(path, json).context("failed to write lockfile")?;
        Ok(())
    }

    /// Read lockfile from disk
    pub fn read(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path).context("failed to read lockfile")?;
        serde_json::from_str(&data).context("failed to parse lockfile")
    }

    /// Check if a package is already locked at a specific version
    pub fn is_locked(&self, name: &str, version: &str) -> bool {
        let key = format!("{name}@{version}");
        self.packages.contains_key(&key)
    }

    /// Total packages in lockfile
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Convert lockfile back to a DepGraph (for fast-path installs without resolution)
    pub fn to_graph(&self) -> DepGraph {
        use crate::graph::{DepGraph, DepNode};
        let mut graph = DepGraph::new();

        for (key, entry) in &self.packages {
            // Extract package name from key (format: "name@version")
            let name = if let Some(at_pos) = key.rfind('@') {
                key[..at_pos].to_string()
            } else {
                key.clone()
            };

            graph.nodes.insert(
                key.clone(),
                DepNode {
                    name: name.clone(),
                    alias: entry.alias.clone(),
                    version: entry.version.clone(),
                    resolved: entry.resolved.clone(),
                    integrity: entry.integrity.clone(),
                    dependencies: entry.dependencies.clone(),
                    has_install_script: entry.has_install_script,
                    dev: entry.dev,
                    optional: entry.optional,
                },
            );
        }

        graph
    }
}
