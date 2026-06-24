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
//!
//! Supports nested node_modules for version conflicts:
//!   node_modules/
//!     foo/            <- hoisted (most common version)
//!     bar/
//!       node_modules/
//!         foo/        <- nested (different version required by bar)

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::cas::ContentStore;
use oath_resolve::graph::{DepGraph, DepNode};

/// Links resolved packages into a project's node_modules
pub struct Linker {
    store: ContentStore,
}

/// Plan for how to lay out packages in node_modules
struct LinkPlan {
    /// install_name -> key of the version to hoist to top-level
    hoisted: HashMap<String, String>,
    /// (parent_key, install_name, child_key) for nested deps
    nested: Vec<(String, String, String)>,
}

impl Linker {
    pub fn new(store: ContentStore) -> Self {
        Self { store }
    }

    /// Analyze the graph and build a hoisting plan.
    /// Groups packages by install_name, picks the most commonly depended-on
    /// version to hoist, and nests the rest under their dependents.
    fn build_plan(&self, graph: &DepGraph) -> LinkPlan {
        // Step 1: Group all nodes by install_name -> list of keys
        let mut by_install_name: HashMap<String, Vec<String>> = HashMap::new();
        for (key, node) in &graph.nodes {
            let install_name = node.alias.as_deref().unwrap_or(&node.name).to_string();
            by_install_name
                .entry(install_name)
                .or_default()
                .push(key.clone());
        }

        // Step 2: For each install_name, pick the most common version to hoist.
        // "Most common" = referenced by the most packages in their dependencies.
        let mut hoisted: HashMap<String, String> = HashMap::new();

        // Count how many times each key is referenced as a dependency
        let mut ref_counts: HashMap<String, usize> = HashMap::new();
        for node in graph.nodes.values() {
            for dep_key in node.dependencies.values() {
                *ref_counts.entry(dep_key.clone()).or_insert(0) += 1;
            }
        }
        // Root deps also count
        for root_key in &graph.roots {
            *ref_counts.entry(root_key.clone()).or_insert(0) += 1;
        }

        for (install_name, keys) in &by_install_name {
            if keys.len() == 1 {
                // No conflict, hoist the only version
                hoisted.insert(install_name.clone(), keys[0].clone());
            } else {
                // Multiple versions: pick the one with highest ref count
                let best = keys
                    .iter()
                    .max_by_key(|k| ref_counts.get(*k).copied().unwrap_or(0))
                    .unwrap()
                    .clone();
                hoisted.insert(install_name.clone(), best);
            }
        }

        // Step 3: Build nested list. For each dependency reference that points
        // to a non-hoisted version, nest it under the parent.
        let mut nested: Vec<(String, String, String)> = Vec::new();

        for (parent_key, parent_node) in &graph.nodes {
            for (dep_name, dep_key) in &parent_node.dependencies {
                // Determine the install_name for this dep
                let dep_install_name = if let Some(dep_node) = graph.nodes.get(dep_key) {
                    dep_node
                        .alias
                        .as_deref()
                        .unwrap_or(&dep_node.name)
                        .to_string()
                } else {
                    dep_name.clone()
                };

                // Check if this dep_key is the hoisted version
                let is_hoisted = hoisted
                    .get(&dep_install_name)
                    .map(|h| h == dep_key)
                    .unwrap_or(false);

                if !is_hoisted {
                    // This dep needs to be nested under parent
                    nested.push((parent_key.clone(), dep_install_name, dep_key.clone()));
                }
            }
        }

        LinkPlan { hoisted, nested }
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

        // Build the hoisting plan
        let plan = self.build_plan(graph);

        // Phase 1: Link each package into .oath/{key}/node_modules/{install_name}
        for (key, node) in &graph.nodes {
            let pkg_store_dir = self.store.package_dir(&node.name, &node.version);
            if !pkg_store_dir.exists() {
                tracing::warn!("package not in store: {key}");
                result.missing += 1;
                continue;
            }

            let install_name = node.alias.as_deref().unwrap_or(&node.name);
            let virtual_dir = oath_dir.join(key).join("node_modules").join(install_name);
            std::fs::create_dir_all(virtual_dir.parent().unwrap())?;

            // Hardlink all files from store into virtual dir
            hardlink_dir(&pkg_store_dir, &virtual_dir)?;
            result.linked += 1;
        }

        // Phase 2: Create top-level symlinks for hoisted packages
        for (install_name, key) in &plan.hoisted {
            if !graph.nodes.contains_key(key) {
                continue;
            }

            // Scoped packages (@scope/name) live at node_modules/@scope/name,
            // so the symlink's parent dir is node_modules/@scope/ -- one level deeper.
            // Relative symlink target must go up one extra level with "../"
            let symlink_target = if install_name.contains('/') {
                PathBuf::from("..")
                    .join(".oath")
                    .join(key)
                    .join("node_modules")
                    .join(install_name)
            } else {
                PathBuf::from(".oath")
                    .join(key)
                    .join("node_modules")
                    .join(install_name)
            };
            let symlink_path = nm_dir.join(install_name);

            // Handle scoped packages: ensure @scope dir exists
            if install_name.contains('/')
                && let Some(scope) = install_name.split('/').next()
            {
                std::fs::create_dir_all(nm_dir.join(scope))?;
            }

            // Create relative symlink
            std::os::unix::fs::symlink(&symlink_target, &symlink_path).with_context(|| {
                format!(
                    "failed to symlink {} -> {}",
                    symlink_path.display(),
                    symlink_target.display()
                )
            })?;
            result.symlinks += 1;
        }

        // Phase 3: Create nested node_modules for version conflicts
        for (parent_key, install_name, child_key) in &plan.nested {
            let parent_node = match graph.nodes.get(parent_key) {
                Some(n) => n,
                None => continue,
            };
            if !graph.nodes.contains_key(child_key) {
                continue;
            }

            let parent_install_name = parent_node.alias.as_deref().unwrap_or(&parent_node.name);

            // Create: node_modules/<parent_install_name>/node_modules/<install_name>/
            // as a symlink to .oath/<child_key>/node_modules/<install_name>
            let nested_nm_dir = nm_dir.join(parent_install_name).join("node_modules");
            // Handle scoped parent packages
            if install_name.contains('/') {
                if let Some(scope) = install_name.split('/').next() {
                    std::fs::create_dir_all(nested_nm_dir.join(scope))?;
                }
            } else {
                std::fs::create_dir_all(&nested_nm_dir)?;
            }

            let nested_symlink = nested_nm_dir.join(install_name);
            // The symlink target is relative from nested_symlink's parent dir.
            // If parent is scoped: node_modules/@scope/pkg/node_modules/ -> depth 3
            // If child is scoped: nested_symlink's parent is .../@scope/ -> add 1 more
            let base_depth = if parent_install_name.contains('/') {
                3
            } else {
                2
            };
            let child_extra = if install_name.contains('/') { 1 } else { 0 };
            let depth = base_depth + child_extra;
            let mut rel_target = PathBuf::new();
            for _ in 0..depth {
                rel_target.push("..");
            }
            rel_target.push(".oath");
            rel_target.push(child_key);
            rel_target.push("node_modules");
            rel_target.push(install_name);

            if !nested_symlink.exists() {
                std::os::unix::fs::symlink(&rel_target, &nested_symlink).with_context(|| {
                    format!(
                        "failed to create nested symlink {} -> {}",
                        nested_symlink.display(),
                        rel_target.display()
                    )
                })?;
                result.nested += 1;
            }
        }

        // Phase 4: Link transitive deps within each package's .oath node_modules
        for (key, node) in &graph.nodes {
            for (dep_name, dep_key) in &node.dependencies {
                // Determine install name for the dep
                let dep_install_name = if let Some(dep_node) = graph.nodes.get(dep_key) {
                    dep_node
                        .alias
                        .as_deref()
                        .unwrap_or(&dep_node.name)
                        .to_string()
                } else {
                    dep_name.clone()
                };

                let source = oath_dir
                    .join(dep_key)
                    .join("node_modules")
                    .join(&dep_install_name);
                let target = oath_dir
                    .join(key)
                    .join("node_modules")
                    .join(&dep_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped packages in dep name
                    if dep_install_name.contains('/')
                        && let Some(scope) = dep_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir.join(key).join("node_modules").join(scope),
                        )?;
                    }
                    // Symlink to the dep's virtual package
                    let relative = pathdiff_relative(&target, &source);
                    std::os::unix::fs::symlink(&relative, &target).ok();
                }
            }
        }

        // Phase 4b: Create peer dep symlinks within each package's .oath node_modules
        for (key, node) in &graph.nodes {
            for peer_key in node.resolved_peers.values() {
                let peer_node = match graph.nodes.get(peer_key) {
                    Some(n) => n,
                    None => continue,
                };
                let peer_install_name = peer_node.alias.as_deref().unwrap_or(&peer_node.name);

                let source = oath_dir
                    .join(peer_key)
                    .join("node_modules")
                    .join(peer_install_name);
                let target = oath_dir
                    .join(key)
                    .join("node_modules")
                    .join(peer_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped peer package
                    if peer_install_name.contains('/')
                        && let Some(scope) = peer_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir.join(key).join("node_modules").join(scope),
                        )?;
                    }
                    let relative = pathdiff_relative(&target, &source);
                    std::os::unix::fs::symlink(&relative, &target).ok();
                    result.symlinks += 1;
                }
            }
        }

        // Phase 5: Create .bin symlinks for packages with bin entries
        let bin_dir = nm_dir.join(".bin");
        std::fs::create_dir_all(&bin_dir)?;

        for (install_name, key) in &plan.hoisted {
            if !graph.nodes.contains_key(key) {
                continue;
            }

            // Read package.json from the linked location to get bin field
            let pkg_json_path = nm_dir.join(install_name).join("package.json");
            let bins = read_bin_entries(&pkg_json_path, install_name);

            for (bin_name, bin_path) in &bins {
                let target = nm_dir.join(install_name).join(bin_path);
                let link_path = bin_dir.join(bin_name);

                if target.exists() && !link_path.exists() {
                    // Create relative symlink from .bin/name -> ../pkg/bin/path
                    let rel = PathBuf::from("..").join(install_name).join(bin_path);
                    std::os::unix::fs::symlink(&rel, &link_path).ok();

                    // Make executable
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(meta) = std::fs::metadata(&target) {
                            let mut perms = meta.permissions();
                            let mode = perms.mode() | 0o111; // +x
                            perms.set_mode(mode);
                            std::fs::set_permissions(&target, perms).ok();
                        }
                    }

                    result.bins += 1;
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
    /// Number of nested symlinks created (version conflicts)
    pub nested: usize,
    /// Number of .bin symlinks created
    pub bins: usize,
    /// Number of packages missing from store
    pub missing: usize,
}

/// Read bin entries from a package.json file
/// Returns Vec<(bin_name, relative_path)>
fn read_bin_entries(pkg_json_path: &Path, install_name: &str) -> Vec<(String, String)> {
    let content = match std::fs::read_to_string(pkg_json_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut bins = Vec::new();

    if let Some(bin) = json.get("bin") {
        match bin {
            serde_json::Value::String(path) => {
                // Single bin: use package name (last segment) as bin name
                let bin_name = install_name.split('/').next_back().unwrap_or(install_name);
                bins.push((bin_name.to_string(), path.clone()));
            }
            serde_json::Value::Object(map) => {
                for (name, path) in map {
                    if let Some(p) = path.as_str() {
                        bins.push((name.clone(), p.to_string()));
                    }
                }
            }
            _ => {}
        }
    }

    // Also check "directories.bin" (less common)
    if bins.is_empty()
        && let Some(dirs) = json.get("directories")
        && let Some(bin_dir) = dirs.get("bin").and_then(|v| v.as_str())
    {
        // Would need to list files in that dir - skip for now
        let _ = bin_dir;
    }

    bins
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
#[allow(dead_code)]
fn find_dep_in_graph<'a>(graph: &'a DepGraph, name: &str, _spec: &str) -> Option<&'a DepNode> {
    // Simple: find any node with this name (could be smarter about version matching)
    graph.nodes.values().find(|n| n.name == name)
}

/// Compute a relative path from `from` (symlink location) to `to` (symlink target).
///
/// For a symlink at `/a/b/c/link` pointing at `/a/b/d/e/target`:
/// - Go up from the symlink's parent dir (/a/b/c) to the common ancestor (/a/b)
/// - Then descend into d/e/target
///
/// Both paths should be absolute. `from` is the path of the symlink itself
/// (not its parent directory).
fn pathdiff_relative(from: &Path, to: &Path) -> PathBuf {
    // We compute relative from the *parent* of `from` (the dir containing the symlink)
    let from_dir = from.parent().unwrap_or(from);

    // Collect components
    let from_parts: Vec<_> = from_dir.components().collect();
    let to_parts: Vec<_> = to.components().collect();

    // Find the length of the common prefix
    let common_len = from_parts
        .iter()
        .zip(to_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut rel = PathBuf::new();
    // Go up from from_dir to the common ancestor
    for _ in common_len..from_parts.len() {
        rel.push("..");
    }
    // Descend into the target
    for part in &to_parts[common_len..] {
        rel.push(part);
    }

    // If the result is empty (same dir), use "."
    if rel.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rel
    }
}
