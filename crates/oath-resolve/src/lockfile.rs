//! Lockfile read/write
//!
//! oath-lock.json format, compatible with npm's package-lock.json concepts
//! but cleaner and verifiable against a transparency log.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::graph::DepGraph;

pub const LOCKFILE_VERSION: u32 = 2;

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
    /// Direct resolved package keys for the root project.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,
    /// Root package.json dependencies snapshot (name -> requested range/spec).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_dependencies: BTreeMap<String, String>,
    /// Root package.json devDependencies snapshot (name -> requested range/spec).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_dev_dependencies: BTreeMap<String, String>,
    /// All resolved packages
    pub packages: BTreeMap<String, LockEntry>,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
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
    /// Peer dependencies declared by this package (name -> range)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_dependencies: BTreeMap<String, String>,
    /// Resolved peers (name -> "name@version" key)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolved_peers: BTreeMap<String, String>,
}

impl Lockfile {
    /// Create a lockfile from a resolved dependency graph
    pub fn from_graph(graph: &DepGraph, project_name: &str, project_version: &str) -> Self {
        Self::from_graph_with_manifest(
            graph,
            project_name,
            project_version,
            &HashMap::new(),
            &HashMap::new(),
        )
    }

    /// Create a lockfile from a graph plus the root manifest dependency snapshot.
    pub fn from_graph_with_manifest(
        graph: &DepGraph,
        project_name: &str,
        project_version: &str,
        root_dependencies: &HashMap<String, String>,
        root_dev_dependencies: &HashMap<String, String>,
    ) -> Self {
        let mut packages = BTreeMap::new();

        for (key, node) in &graph.nodes {
            packages.insert(
                key.clone(),
                LockEntry {
                    version: node.version.clone(),
                    resolved: node.resolved.clone(),
                    integrity: node.integrity.clone(),
                    dependencies: node.dependencies.clone().into_iter().collect(),
                    dev: node.dev,
                    optional: node.optional,
                    has_install_script: node.has_install_script,
                    alias: node.alias.clone(),
                    peer_dependencies: node.peer_dependencies.clone().into_iter().collect(),
                    resolved_peers: node.resolved_peers.clone().into_iter().collect(),
                },
            );
        }

        let mut roots = graph.roots.clone();
        roots.sort();
        roots.dedup();

        Self {
            lockfile_version: LOCKFILE_VERSION,
            name: project_name.to_string(),
            version: project_version.to_string(),
            roots,
            root_dependencies: root_dependencies.clone().into_iter().collect(),
            root_dev_dependencies: root_dev_dependencies.clone().into_iter().collect(),
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

    /// Returns true when the lockfile was generated from this root manifest.
    pub fn matches_manifest(
        &self,
        dependencies: &HashMap<String, String>,
        dev_dependencies: &HashMap<String, String>,
    ) -> bool {
        self.root_dependencies == dependencies.clone().into_iter().collect()
            && self.root_dev_dependencies == dev_dependencies.clone().into_iter().collect()
    }

    /// Convert lockfile back to a DepGraph (for fast-path installs without resolution)
    pub fn to_graph(&self) -> DepGraph {
        use crate::graph::{DepGraph, DepNode};
        let mut graph = DepGraph::new();
        graph.roots = self.roots.clone();

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
                    dependencies: entry.dependencies.clone().into_iter().collect(),
                    has_install_script: entry.has_install_script,
                    dev: entry.dev,
                    optional: entry.optional,
                    peer_dependencies: entry.peer_dependencies.clone().into_iter().collect(),
                    optional_peers: std::collections::HashSet::new(),
                    resolved_peers: entry.resolved_peers.clone().into_iter().collect(),
                },
            );
        }

        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DepNode;
    use std::collections::{HashMap, HashSet};

    fn test_node(name: &str, version: &str, dependencies: HashMap<String, String>) -> DepNode {
        DepNode {
            name: name.to_string(),
            alias: None,
            version: version.to_string(),
            resolved: format!("https://registry.example/{name}-{version}.tgz"),
            integrity: Some(format!("sha512-{name}-{version}")),
            dependencies,
            has_install_script: false,
            dev: false,
            optional: false,
            peer_dependencies: HashMap::new(),
            optional_peers: HashSet::new(),
            resolved_peers: HashMap::new(),
        }
    }

    #[test]
    fn lockfile_serialization_is_deterministic() {
        let mut deps_a = HashMap::new();
        deps_a.insert("zeta".to_string(), "zeta@1.0.0".to_string());
        deps_a.insert("alpha".to_string(), "alpha@1.0.0".to_string());

        let mut deps_b = HashMap::new();
        deps_b.insert("alpha".to_string(), "alpha@1.0.0".to_string());
        deps_b.insert("zeta".to_string(), "zeta@1.0.0".to_string());

        let mut graph_a = DepGraph::new();
        graph_a.nodes.insert(
            "zeta@1.0.0".to_string(),
            test_node("zeta", "1.0.0", HashMap::new()),
        );
        graph_a.nodes.insert(
            "alpha@1.0.0".to_string(),
            test_node("alpha", "1.0.0", deps_a),
        );

        let mut graph_b = DepGraph::new();
        graph_b.nodes.insert(
            "alpha@1.0.0".to_string(),
            test_node("alpha", "1.0.0", deps_b),
        );
        graph_b.nodes.insert(
            "zeta@1.0.0".to_string(),
            test_node("zeta", "1.0.0", HashMap::new()),
        );

        let json_a =
            serde_json::to_string_pretty(&Lockfile::from_graph(&graph_a, "app", "1.0.0")).unwrap();
        let json_b =
            serde_json::to_string_pretty(&Lockfile::from_graph(&graph_b, "app", "1.0.0")).unwrap();

        assert_eq!(json_a, json_b);
        assert!(json_a.find("\"alpha@1.0.0\"").unwrap() < json_a.find("\"zeta@1.0.0\"").unwrap());
    }

    #[test]
    fn lockfile_v2_round_trips_roots_and_manifest_snapshot() {
        let mut graph = DepGraph::new();
        graph.roots.push("app@1.0.0".to_string());
        graph.nodes.insert(
            "app@1.0.0".to_string(),
            test_node("app", "1.0.0", HashMap::new()),
        );

        let mut deps = HashMap::new();
        deps.insert("app".to_string(), "^1.0.0".to_string());
        let mut dev_deps = HashMap::new();
        dev_deps.insert("tester".to_string(), "~2.0.0".to_string());

        let lockfile =
            Lockfile::from_graph_with_manifest(&graph, "project", "1.0.0", &deps, &dev_deps);
        assert_eq!(lockfile.lockfile_version, LOCKFILE_VERSION);
        assert_eq!(lockfile.roots, vec!["app@1.0.0"]);
        assert!(lockfile.matches_manifest(&deps, &dev_deps));

        let graph_again = lockfile.to_graph();
        assert_eq!(graph_again.roots, vec!["app@1.0.0"]);
    }

    #[test]
    fn v1_lockfiles_deserialize_with_empty_v2_metadata() {
        let raw = r#"{
  "lockfileVersion": 1,
  "name": "project",
  "version": "1.0.0",
  "packages": {}
}"#;
        let lockfile: Lockfile = serde_json::from_str(raw).unwrap();
        assert_eq!(lockfile.lockfile_version, 1);
        assert!(lockfile.roots.is_empty());
        assert!(lockfile.root_dependencies.is_empty());
        assert!(lockfile.root_dev_dependencies.is_empty());
    }
}
