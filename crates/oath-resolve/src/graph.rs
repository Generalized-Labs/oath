//! Dependency graph representation
//!
//! A flat map of resolved packages, compatible with npm's lockfile format.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A resolved dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepGraph {
    /// All resolved packages: key is "name@version"
    pub nodes: HashMap<String, DepNode>,
    /// Root dependencies (direct deps of the project)
    pub roots: Vec<String>,
    /// Peer dependency report (not serialized – computed at resolve time)
    #[serde(skip)]
    pub peer_report: PeerReport,
}

/// A single resolved package in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepNode {
    /// Package name
    pub name: String,
    /// If this package was installed under an alias (npm:real-name@version),
    /// this is the alias name. The `name` field holds the real package name.
    pub alias: Option<String>,
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
    /// peerDependencies declared by this package: name -> semver range
    #[serde(default)]
    pub peer_dependencies: HashMap<String, String>,
    /// Names of peer deps that are optional (from peerDependenciesMeta)
    #[serde(default)]
    pub optional_peers: HashSet<String>,
    /// Resolved peers: peer_name -> "name@version" key in the graph
    /// Populated after the peer resolution pass.
    #[serde(default)]
    pub resolved_peers: HashMap<String, String>,
}

/// Outcome of resolving a single peer dependency
#[derive(Debug, Clone)]
pub enum PeerResolution {
    /// Peer was found and satisfies the required range
    Satisfied {
        required_by: String,
        peer_name: String,
        peer_key: String,
    },
    /// Peer not found anywhere in the install context
    Missing {
        required_by: String,
        peer_name: String,
        range: String,
    },
    /// Peer found but installed version does not satisfy the required range
    Conflict {
        required_by: String,
        peer_name: String,
        range: String,
        found_version: String,
    },
}

/// Aggregate report of all peer dependency outcomes in this install
#[derive(Debug, Clone, Default)]
pub struct PeerReport {
    /// Successfully resolved peer deps
    pub satisfied: Vec<PeerResolution>,
    /// Non-optional peers that were not found in the install context
    pub missing: Vec<PeerResolution>,
    /// Peers found but at an incompatible version
    pub conflicts: Vec<PeerResolution>,
    /// Optional peers that were absent (silent, no warning needed)
    pub optional_missing: Vec<String>,
}

impl DepGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            peer_report: PeerReport::default(),
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
