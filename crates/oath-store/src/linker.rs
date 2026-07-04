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

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
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
    hoisted: BTreeMap<String, String>,
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
        let mut by_install_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, node) in &graph.nodes {
            let install_name = node.alias.as_deref().unwrap_or(&node.name).to_string();
            by_install_name
                .entry(install_name)
                .or_default()
                .push(key.clone());
        }

        // Step 2: For each install_name, pick the most common version to hoist.
        // "Most common" = referenced by the most packages in their dependencies.
        let mut hoisted: BTreeMap<String, String> = BTreeMap::new();

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
                // Multiple versions: pick the one with highest ref count.
                // Ties break lexicographically so layout is deterministic.
                let best = keys
                    .iter()
                    .max_by(|a, b| {
                        let a_count = ref_counts.get(*a).copied().unwrap_or(0);
                        let b_count = ref_counts.get(*b).copied().unwrap_or(0);
                        a_count.cmp(&b_count).then_with(|| b.cmp(a))
                    })
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

        nested.sort();

        LinkPlan { hoisted, nested }
    }

    /// Link an entire resolved dependency graph into project_dir/node_modules
    pub fn link_all(&self, graph: &DepGraph, project_dir: &Path) -> Result<LinkResult> {
        validate_graph_path_names(graph)?;

        let nm_dir = project_dir.join("node_modules");
        let oath_dir = nm_dir.join(".oath");

        // No-op fast path: if the previous link's manifest matches this graph
        // exactly and node_modules is present, skip the nuke-and-rebuild.
        let manifest_path = oath_dir.join(".link-manifest");
        let manifest = link_manifest(graph);
        if nm_dir.exists()
            && std::fs::read_to_string(&manifest_path)
                .map(|prev| prev == manifest)
                .unwrap_or(false)
        {
            return Ok(LinkResult {
                linked: graph.nodes.len(),
                ..Default::default()
            });
        }

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
            let virtual_key = virtual_key_component(key);
            let virtual_dir = oath_dir
                .join(&virtual_key)
                .join("node_modules")
                .join(install_name);
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
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(install_name)
            } else {
                PathBuf::from(".oath")
                    .join(virtual_key_component(key))
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
            rel_target.push(virtual_key_component(child_key));
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
                    .join(virtual_key_component(dep_key))
                    .join("node_modules")
                    .join(&dep_install_name);
                let target = oath_dir
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(&dep_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped packages in dep name
                    if dep_install_name.contains('/')
                        && let Some(scope) = dep_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir
                                .join(virtual_key_component(key))
                                .join("node_modules")
                                .join(scope),
                        )?;
                    }
                    // Symlink to the dep's virtual package
                    let relative = pathdiff_relative(&target, &source);
                    std::os::unix::fs::symlink(&relative, &target).with_context(|| {
                        format!(
                            "failed to symlink dependency {} -> {}",
                            target.display(),
                            relative.display()
                        )
                    })?;
                    result.symlinks += 1;
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
                    .join(virtual_key_component(peer_key))
                    .join("node_modules")
                    .join(peer_install_name);
                let target = oath_dir
                    .join(virtual_key_component(key))
                    .join("node_modules")
                    .join(peer_install_name);

                if source.exists() && !target.exists() {
                    // Handle scoped peer package
                    if peer_install_name.contains('/')
                        && let Some(scope) = peer_install_name.split('/').next()
                    {
                        std::fs::create_dir_all(
                            oath_dir
                                .join(virtual_key_component(key))
                                .join("node_modules")
                                .join(scope),
                        )?;
                    }
                    let relative = pathdiff_relative(&target, &source);
                    std::os::unix::fs::symlink(&relative, &target).with_context(|| {
                        format!(
                            "failed to symlink peer dependency {} -> {}",
                            target.display(),
                            relative.display()
                        )
                    })?;
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
                    std::os::unix::fs::symlink(&rel, &link_path).with_context(|| {
                        format!(
                            "failed to symlink bin {} -> {}",
                            link_path.display(),
                            rel.display()
                        )
                    })?;

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

        // Record the manifest so an unchanged re-install can skip the rebuild.
        let _ = std::fs::write(&manifest_path, &manifest);

        Ok(result)
    }
}

/// A stable fingerprint of the graph layout inputs, used to skip relinking an
/// unchanged node_modules.
fn link_manifest(graph: &DepGraph) -> String {
    let mut out = String::new();

    let mut roots = graph.roots.clone();
    roots.sort();
    for root in roots {
        out.push_str("root\t");
        out.push_str(&root);
        out.push('\n');
    }

    let mut keys: Vec<&str> = graph.nodes.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    for key in keys {
        if let Some(node) = graph.nodes.get(key) {
            out.push_str("pkg\t");
            out.push_str(key);
            out.push('\t');
            out.push_str(&node.name);
            out.push('\t');
            out.push_str(node.alias.as_deref().unwrap_or(""));
            out.push('\t');
            out.push_str(&node.version);
            out.push('\n');

            let mut deps: Vec<(&String, &String)> = node.dependencies.iter().collect();
            deps.sort_by(|(a_name, a_key), (b_name, b_key)| {
                a_name.cmp(b_name).then_with(|| a_key.cmp(b_key))
            });
            for (name, dep_key) in deps {
                out.push_str("dep\t");
                out.push_str(key);
                out.push('\t');
                out.push_str(name);
                out.push('\t');
                out.push_str(dep_key);
                out.push('\n');
            }

            let mut peers: Vec<(&String, &String)> = node.resolved_peers.iter().collect();
            peers.sort_by(|(a_name, a_key), (b_name, b_key)| {
                a_name.cmp(b_name).then_with(|| a_key.cmp(b_key))
            });
            for (name, peer_key) in peers {
                out.push_str("peer\t");
                out.push_str(key);
                out.push('\t');
                out.push_str(name);
                out.push('\t');
                out.push_str(peer_key);
                out.push('\n');
            }
        }
    }

    out
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
fn read_bin_entries(pkg_json_path: &Path, install_name: &str) -> Vec<(String, PathBuf)> {
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
                if is_safe_bin_name(bin_name)
                    && let Some(safe_path) = sanitize_package_relative_path(path)
                {
                    bins.push((bin_name.to_string(), safe_path));
                }
            }
            serde_json::Value::Object(map) => {
                for (name, path) in map {
                    if let Some(p) = path.as_str()
                        && is_safe_bin_name(name)
                        && let Some(safe_path) = sanitize_package_relative_path(p)
                    {
                        bins.push((name.clone(), safe_path));
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

fn validate_graph_path_names(graph: &DepGraph) -> Result<()> {
    for node in graph.nodes.values() {
        let install_name = node.alias.as_deref().unwrap_or(&node.name);
        validate_install_name(install_name)?;

        for dep_name in node.dependencies.keys() {
            validate_install_name(dep_name)?;
        }

        for peer_name in node.resolved_peers.keys() {
            validate_install_name(peer_name)?;
        }
    }

    Ok(())
}

pub fn validate_install_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("invalid empty package install name");
    }

    let parts: Vec<&str> = name.split('/').collect();
    if name.starts_with('@') {
        if parts.len() != 2
            || parts[0].len() == 1
            || !is_safe_path_name_part(parts[0])
            || !is_safe_path_name_part(parts[1])
        {
            bail!("invalid scoped package install name: {name}");
        }
    } else if parts.len() != 1 || !is_safe_path_name_part(parts[0]) {
        bail!("invalid package install name: {name}");
    }

    Ok(())
}

fn is_safe_path_name_part(part: &str) -> bool {
    !part.is_empty() && part != "." && part != ".." && !part.contains('\\') && !part.contains('\0')
}

fn is_safe_bin_name(name: &str) -> bool {
    is_safe_path_name_part(name) && !name.contains('/')
}

fn sanitize_package_relative_path(path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    let mut safe = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::Normal(part) if is_safe_os_part(part) => safe.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }

    (!safe.as_os_str().is_empty()).then_some(safe)
}

fn is_safe_os_part(part: &OsStr) -> bool {
    let Some(part) = part.to_str() else {
        return false;
    };
    is_safe_path_name_part(part)
}

fn virtual_key_component(key: &str) -> String {
    safe_fs_component(key)
}

fn safe_fs_component(input: &str) -> String {
    if input.is_empty() {
        return "_".to_string();
    }

    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'@' | b'+' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }

    match out.as_str() {
        "." => "%2E".to_string(),
        ".." => "%2E%2E".to_string(),
        _ => out,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use oath_resolve::graph::{DepGraph, DepNode};
    use std::collections::{HashMap, HashSet};

    fn node(name: &str, version: &str, dependencies: HashMap<String, String>) -> DepNode {
        DepNode {
            name: name.to_string(),
            alias: None,
            version: version.to_string(),
            resolved: format!("https://registry.example/{name}-{version}.tgz"),
            integrity: None,
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
    fn link_manifest_changes_when_edges_change() {
        let mut deps = HashMap::new();
        deps.insert("dep".to_string(), "dep@1.0.0".to_string());

        let mut graph_a = DepGraph::new();
        graph_a.roots.push("app@1.0.0".to_string());
        graph_a
            .nodes
            .insert("app@1.0.0".to_string(), node("app", "1.0.0", deps));
        graph_a.nodes.insert(
            "dep@1.0.0".to_string(),
            node("dep", "1.0.0", HashMap::new()),
        );

        let mut graph_b = graph_a.clone();
        graph_b
            .nodes
            .get_mut("app@1.0.0")
            .unwrap()
            .dependencies
            .clear();

        assert_ne!(link_manifest(&graph_a), link_manifest(&graph_b));
    }

    #[test]
    fn build_plan_breaks_ref_count_ties_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let linker = Linker::new(store);

        let mut graph = DepGraph::new();
        graph.roots.push("pkg@2.0.0".to_string());
        graph.roots.push("pkg@1.0.0".to_string());
        graph.nodes.insert(
            "pkg@2.0.0".to_string(),
            node("pkg", "2.0.0", HashMap::new()),
        );
        graph.nodes.insert(
            "pkg@1.0.0".to_string(),
            node("pkg", "1.0.0", HashMap::new()),
        );

        let plan = linker.build_plan(&graph);

        assert_eq!(plan.hoisted.get("pkg").unwrap(), "pkg@1.0.0");
    }

    #[test]
    fn link_all_rejects_unsafe_install_names_before_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        let project = tmp.path().join("project");
        let sentinel = project.join("node_modules").join("keep.txt");
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        std::fs::write(&sentinel, "keep").unwrap();

        let mut graph = DepGraph::new();
        graph.nodes.insert(
            "../evil@1.0.0".to_string(),
            node("../evil", "1.0.0", HashMap::new()),
        );

        let err = Linker::new(store).link_all(&graph, &project).unwrap_err();

        assert!(err.to_string().contains("invalid package install name"));
        assert!(
            sentinel.exists(),
            "linker cleaned node_modules before validation"
        );
    }

    #[test]
    fn link_all_creates_scoped_transitive_links_under_scoped_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().join("store")).unwrap();
        for (name, version) in [("@scope/parent", "1.0.0"), ("@scope/child", "1.0.0")] {
            let dir = store.package_dir(name, version);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), "{}").unwrap();
        }

        let mut parent_deps = HashMap::new();
        parent_deps.insert("@scope/child".to_string(), "@scope/child@1.0.0".to_string());
        let mut graph = DepGraph::new();
        graph.roots.push("@scope/parent@1.0.0".to_string());
        graph.nodes.insert(
            "@scope/parent@1.0.0".to_string(),
            node("@scope/parent", "1.0.0", parent_deps),
        );
        graph.nodes.insert(
            "@scope/child@1.0.0".to_string(),
            node("@scope/child", "1.0.0", HashMap::new()),
        );

        let project = tmp.path().join("project");
        Linker::new(store).link_all(&graph, &project).unwrap();

        let transitive_link = project
            .join("node_modules")
            .join(".oath")
            .join("@scope%2Fparent@1.0.0")
            .join("node_modules")
            .join("@scope")
            .join("child");
        assert!(
            transitive_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "scoped transitive dependency link was not created"
        );
    }

    #[test]
    fn read_bin_entries_filters_unsafe_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_json = tmp.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{
              "bin": {
                "../owned": "bin/owned.js",
                "escape": "../escape.js",
                "safe": "bin/safe.js"
              }
            }"#,
        )
        .unwrap();

        let bins = read_bin_entries(&pkg_json, "pkg");

        assert_eq!(
            bins,
            vec![("safe".to_string(), PathBuf::from("bin/safe.js"))]
        );
    }

    #[test]
    fn virtual_keys_are_single_safe_components() {
        assert_eq!(
            virtual_key_component("@scope/pkg@1.0.0"),
            "@scope%2Fpkg@1.0.0"
        );
        assert_eq!(virtual_key_component("../pkg@1.0.0"), "..%2Fpkg@1.0.0");
    }
}
