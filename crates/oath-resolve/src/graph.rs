//! Dependency graph representation
//!
//! A flat map of resolved packages, compatible with npm's lockfile format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A resolved dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepGraph {
    /// All resolved packages: key is "name@version"
    pub nodes: HashMap<String, DepNode>,
    /// Root dependencies (direct deps of the project)
    pub roots: Vec<String>,
}

/// A single resolved package in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepNode {
    /// Package name
    pub name: String,
    /// Exact resolved version
    pub version: String,
    /// Tarball URL
    pub resolved: String,
    /// SRI integrity hash
    pub integrity: Option<String>,
    /// Production dependencies: name -> resolved "name@version" key
    pub dependencies: HashMap<String, String>,
    /// Whether this package has install scripts
    pub has_install_script: bool,
    /// Whether this is a dev dependency
    pub dev: bool,
    /// Whether this is an optional dependency
    pub optional: bool,
}

impl DepGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
        }
    }

    /// Get a node by "name@version" key
    pub fn get(&self, key: &str) -> Option<&DepNode> {
        self.nodes.get(key)
    }

    /// Total number of packages in the graph
    pub fn package_count(&self) -> usize {
        self.nodes.len()
    }

    /// All packages that have install scripts (security concern)
    pub fn packages_with_install_scripts(&self) -> Vec<&DepNode> {
        self.nodes.values().filter(|n| n.has_install_script).collect()
    }

    /// Unique key for a package
    pub fn key(name: &str, version: &str) -> String {
        format!("{name}@{version}")
    }
}

impl Default for DepGraph {
    fn default() -> Self {
        Self::new()
    }
}
