//! Linker: hardlink from global store into project node_modules
//!
//! Creates the pnpm-style layout:
//!   node_modules/
//!     .oath/           <- hidden dir with the real packages
//!       express@4.18.2/
//!         node_modules/
//!           express/ -> hardlinks to store files
//!           accepts/ -> hardlinks to its dep
//!     express/        <- symlink to .oath/express@4.18.2/node_modules/express

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::cas::ContentStore;
use oath_resolve::graph::{DepGraph, DepNode};

/// Links resolved packages into a project's node_modules
pub struct Linker {
    store: ContentStore,
}

impl Linker {
    pub fn new(store: ContentStore) -> Self {
        Self { store }
    }

    /// Link an entire resolved dependency graph into project_dir/node_modules
    pub fn link_all(&self, graph: &DepGraph, project_dir: &Path) -> Result<LinkResult> {
        let nm_dir = project_dir.join("node_modules");
        let oath_dir = nm_dir.join(".oath");

        // Clean existing
        if nm_dir.exists() {
            std::fs::remove_dir_all(&nm_dir).context("failed to clean node_modules")?;
        }
        std::fs::create_dir_all(&oath_dir).context("failed to create node_modules/.oath")?;

        let mut result = LinkResult::default();

        // Phase 1: Link each package into .oath/{name}@{version}/node_modules/{name}
        for (key, node) in &graph.nodes {
            let pkg_store_dir = self.store.package_dir(&node.name, &node.version);
            if !pkg_store_dir.exists() {
                tracing::warn!("package not in store: {key}");
                result.missing += 1;
                continue;
            }

            let virtual_dir = oath_dir.join(key).join("node_modules").join(&node.name);
            std::fs::create_dir_all(virtual_dir.parent().unwrap())?;

            // Hardlink all files from store into virtual dir
            hardlink_dir(&pkg_store_dir, &virtual_dir)?;
            result.linked += 1;
        }

        // Phase 2: Create top-level symlinks for direct deps (root packages)
        for root_key in &graph.roots {
            if let Some(node) = graph.nodes.get(root_key) {
                let symlink_target = PathBuf::from(".oath")
                    .join(root_key)
                    .join("node_modules")
                    .join(&node.name);
                let symlink_path = nm_dir.join(&node.name);

                // Handle scoped packages
                if node.name.contains('/') {
                    if let Some(scope) = node.name.split('/').next() {
                        std::fs::create_dir_all(nm_dir.join(scope))?;
                    }
                }

                // Create relative symlink
                std::os::unix::fs::symlink(&symlink_target, &symlink_path).with_context(
                    || {
                        format!(
                            "failed to symlink {} -> {}",
                            symlink_path.display(),
                            symlink_target.display()
                        )
                    },
                )?;
                result.symlinks += 1;
            }
        }

        // Phase 3: Link transitive deps within each package's node_modules
        for (key, node) in &graph.nodes {
            for (dep_name, dep_spec) in &node.dependencies {
                // Find the resolved version of this dep
                if let Some(dep_node) = find_dep_in_graph(graph, dep_name, dep_spec) {
                    let dep_key = DepGraph::key(&dep_node.name, &dep_node.version);
                    let source = oath_dir.join(&dep_key).join("node_modules").join(dep_name);
                    let target = oath_dir.join(key).join("node_modules").join(dep_name);

                    if source.exists() && !target.exists() {
                        // Handle scoped packages in dep name
                        if dep_name.contains('/') {
                            if let Some(scope) = dep_name.split('/').next() {
                                std::fs::create_dir_all(
                                    oath_dir.join(key).join("node_modules").join(scope),
                                )?;
                            }
                        }
                        // Symlink to the dep's virtual package
                        let relative = pathdiff_relative(&target, &source);
                        std::os::unix::fs::symlink(&relative, &target).ok();
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Result of a link operation
#[derive(Debug, Default)]
pub struct LinkResult {
    /// Number of packages hardlinked from store
    pub linked: usize,
    /// Number of top-level symlinks created
    pub symlinks: usize,
    /// Number of packages missing from store
    pub missing: usize,
}

/// Hardlink all files from src to dst recursively
fn hardlink_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            hardlink_dir(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            // Try hardlink first (saves disk), fall back to copy
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }
    Ok(())
}

/// Find a dependency node in the graph by name and specifier
fn find_dep_in_graph<'a>(graph: &'a DepGraph, name: &str, _spec: &str) -> Option<&'a DepNode> {
    // Simple: find any node with this name (could be smarter about version matching)
    graph.nodes.values().find(|n| n.name == name)
}

/// Compute a relative path from `from` to `to`
fn pathdiff_relative(from: &Path, to: &Path) -> PathBuf {
    // Simple relative path: go up from `from` and down to `to`
    // For node_modules layout, we can use the absolute path
    to.to_path_buf()
}
