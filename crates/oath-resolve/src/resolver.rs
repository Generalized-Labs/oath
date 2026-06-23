//! Dependency resolver
//!
//! Level-parallel BFS: all packages at the same depth are fetched concurrently.
//! This turns N serial HTTP requests into ceil(depth) parallel batches.

use anyhow::{Context, Result};
use futures::future::join_all;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use oath_fetch::{resolve_version, Packument, RegistryClient};

use crate::graph::{DepGraph, DepNode};

/// Check if a package is compatible with the current platform.
/// os field uses npm convention: ["darwin", "linux"] = only these, ["!win32"] = all except win32
/// cpu field uses: ["x64", "arm64"] = only these, ["!ia32"] = all except ia32
fn is_platform_compatible(os: &[String], cpu: &[String]) -> bool {
    let current_os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "win32"
    } else {
        "unknown"
    };

    let current_cpu = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else {
        "unknown"
    };

    // Check OS compatibility
    if !os.is_empty() {
        let has_exclusions = os.iter().any(|s| s.starts_with('!'));
        if has_exclusions {
            // Exclusion mode: skip if current OS is excluded
            if os.iter().any(|s| s == &format!("!{}", current_os)) {
                return false;
            }
        } else {
            // Inclusion mode: must be in the list
            if !os.iter().any(|s| s == current_os) {
                return false;
            }
        }
    }

    // Check CPU compatibility
    if !cpu.is_empty() {
        let has_exclusions = cpu.iter().any(|s| s.starts_with('!'));
        if has_exclusions {
            if cpu.iter().any(|s| s == &format!("!{}", current_cpu)) {
                return false;
            }
        } else {
            if !cpu.iter().any(|s| s == current_cpu) {
                return false;
            }
        }
    }

    true
}

/// Resolution options
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// Include dev dependencies
    pub include_dev: bool,
    /// Include optional dependencies
    pub include_optional: bool,
    /// Maximum depth (prevent infinite recursion)
    pub max_depth: u32,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            include_dev: true,
            include_optional: true,
            max_depth: 256,
        }
    }
}

/// A dependency to resolve
#[derive(Debug, Clone)]
struct PendingDep {
    name: String,
    specifier: String,
    depth: u32,
    dev: bool,
    optional: bool,
    /// If this dep was specified via npm: alias, this is the alias name
    alias: Option<String>,
}

/// Find the resolved key in the graph that matches a dependency name.
/// Since we resolve one version per package, just look for name@* in the keys.
fn find_matching_key(all_keys: &[String], graph: &DepGraph, dep_name: &str, _dep_spec: &str) -> Option<String> {
    // Check for alias-resolved packages first
    for key in all_keys {
        if let Some(node) = graph.nodes.get(key) {
            // Match by alias if set, otherwise by name
            let matches_name = node.alias.as_deref() == Some(dep_name) || node.name == dep_name;
            if matches_name {
                return Some(key.clone());
            }
        }
    }
    None
}

/// Parse an npm alias specifier like "npm:real-package@^1.0.0"
/// Returns (real_name, version_spec) or None if not an alias
fn parse_alias_spec(specifier: &str) -> Option<(String, String)> {
    if !specifier.starts_with("npm:") {
        return None;
    }
    let rest = &specifier[4..]; // after "npm:"
    // Handle scoped: npm:@scope/pkg@version
    if rest.starts_with('@') {
        // Find second @ (version separator)
        if let Some(at_pos) = rest[1..].find('@').map(|p| p + 1) {
            let real_name = rest[..at_pos].to_string();
            let version = rest[at_pos + 1..].to_string();
            return Some((real_name, version));
        }
        // No version specified
        return Some((rest.to_string(), "latest".to_string()));
    }
    // Non-scoped: npm:pkg@version
    if let Some(at_pos) = rest.rfind('@') {
        if at_pos > 0 {
            let real_name = rest[..at_pos].to_string();
            let version = rest[at_pos + 1..].to_string();
            return Some((real_name, version));
        }
    }
    Some((rest.to_string(), "latest".to_string()))
}

/// The dependency resolver
pub struct Resolver {
    client: RegistryClient,
    options: ResolveOptions,
    /// Cache of fetched packuments to avoid redundant requests
    packument_cache: Arc<RwLock<HashMap<String, Packument>>>,
}

impl Resolver {
    pub fn new(client: RegistryClient, options: ResolveOptions) -> Self {
        Self {
            client,
            options,
            packument_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolve all dependencies starting from a map of direct dependencies.
    ///
    /// Uses level-parallel BFS: all packages at depth N are fetched concurrently,
    /// then their deps form the batch for depth N+1.
    pub async fn resolve(
        &mut self,
        dependencies: &HashMap<String, String>,
        dev_dependencies: &HashMap<String, String>,
    ) -> Result<DepGraph> {
        let mut graph = DepGraph::new();
        let mut resolved: HashSet<String> = HashSet::new();

        // Current level of deps to process
        let mut current_level: Vec<PendingDep> = Vec::new();

        // Seed with direct dependencies
        for (name, spec) in dependencies {
            let (real_name, real_spec, alias) = if let Some((real, ver)) = parse_alias_spec(spec) {
                (real, ver, Some(name.clone()))
            } else {
                (name.clone(), spec.clone(), None)
            };
            current_level.push(PendingDep {
                name: real_name,
                specifier: real_spec,
                depth: 0,
                dev: false,
                optional: false,
                alias,
            });
        }

        if self.options.include_dev {
            for (name, spec) in dev_dependencies {
                let (real_name, real_spec, alias) = if let Some((real, ver)) = parse_alias_spec(spec) {
                    (real, ver, Some(name.clone()))
                } else {
                    (name.clone(), spec.clone(), None)
                };
                current_level.push(PendingDep {
                    name: real_name,
                    specifier: real_spec,
                    depth: 0,
                    dev: true,
                    optional: false,
                    alias,
                });
            }
        }

        let mut packages_resolved = 0u32;

        // Process level by level
        while !current_level.is_empty() {
            // Deduplicate fetch targets: only fetch names we haven't cached yet
            let mut names_to_fetch: Vec<String> = Vec::new();
            {
                let cache = self.packument_cache.read().await;
                let mut seen = HashSet::new();
                for dep in &current_level {
                    if dep.depth > self.options.max_depth {
                        continue;
                    }
                    if !cache.contains_key(&dep.name) && seen.insert(dep.name.clone()) {
                        names_to_fetch.push(dep.name.clone());
                    }
                }
            }

            // Fetch all uncached packuments in parallel
            if !names_to_fetch.is_empty() {
                let fetches: Vec<_> = names_to_fetch
                    .iter()
                    .map(|name| {
                        let client = self.client.clone();
                        let name = name.clone();
                        async move {
                            let result = client.fetch_packument(&name).await;
                            (name, result)
                        }
                    })
                    .collect();

                let results = join_all(fetches).await;

                let mut cache = self.packument_cache.write().await;
                for (name, result) in results {
                    match result {
                        Ok(packument) => {
                            cache.insert(name, packument);
                        }
                        Err(e) => {
                            // Store error later when we try to use it
                            debug!("failed to fetch {name}: {e}");
                        }
                    }
                }
            }

            // Now resolve all deps in this level using cached packuments
            let mut next_level: Vec<PendingDep> = Vec::new();

            for pending in current_level {
                if pending.depth > self.options.max_depth {
                    warn!("max depth exceeded for {}", pending.name);
                    continue;
                }

                // Get packument from cache
                let cache = self.packument_cache.read().await;
                let packument = match cache.get(&pending.name) {
                    Some(p) => p.clone(),
                    None => {
                        if pending.optional {
                            debug!("skipping optional dep {}: fetch failed", pending.name);
                            continue;
                        }
                        return Err(anyhow::anyhow!(
                            "failed to fetch packument for {}",
                            pending.name
                        ));
                    }
                };
                drop(cache);

                // Resolve version
                let resolved_version = match resolve_version(&packument, &pending.specifier) {
                    Ok(v) => v,
                    Err(e) => {
                        if pending.optional {
                            debug!("skipping optional dep {}: {e}", pending.name);
                            continue;
                        }
                        return Err(e).with_context(|| {
                            format!("resolving {}@{}", pending.name, pending.specifier)
                        });
                    }
                };

                let key = DepGraph::key(
                    pending.alias.as_deref().unwrap_or(&pending.name),
                    resolved_version.version,
                );

                // Skip if already resolved
                if resolved.contains(&key) {
                    continue;
                }
                resolved.insert(key.clone());

                // Track root deps
                if pending.depth == 0 {
                    graph.roots.push(key.clone());
                }

                packages_resolved += 1;
                if packages_resolved % 50 == 0 {
                    info!("resolved {packages_resolved} packages...");
                }

                let info = resolved_version.info;

                // Skip platform-incompatible packages (only for optional deps)
                if pending.optional && !is_platform_compatible(&info.os, &info.cpu) {
                    debug!("skipping {} (platform mismatch: os={:?} cpu={:?})", pending.name, info.os, info.cpu);
                    continue;
                }

                // Build dependency map for this node
                let mut node_deps = HashMap::new();

                // Queue production dependencies for next level
                for (dep_name, dep_spec) in &info.dependencies {
                    node_deps.insert(dep_name.clone(), dep_spec.clone());

                    let (real_dep_name, real_dep_spec, dep_alias) = if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                        (real, ver, Some(dep_name.clone()))
                    } else {
                        (dep_name.clone(), dep_spec.clone(), None)
                    };

                    next_level.push(PendingDep {
                        name: real_dep_name,
                        specifier: real_dep_spec,
                        depth: pending.depth + 1,
                        dev: pending.dev,
                        optional: false,
                        alias: dep_alias,
                    });
                }

                // Queue optional dependencies
                if self.options.include_optional {
                    for (dep_name, dep_spec) in &info.optional_dependencies {
                        node_deps.insert(dep_name.clone(), dep_spec.clone());

                        let (real_dep_name, real_dep_spec, dep_alias) = if let Some((real, ver)) = parse_alias_spec(dep_spec) {
                            (real, ver, Some(dep_name.clone()))
                        } else {
                            (dep_name.clone(), dep_spec.clone(), None)
                        };

                        next_level.push(PendingDep {
                            name: real_dep_name,
                            specifier: real_dep_spec,
                            depth: pending.depth + 1,
                            dev: pending.dev,
                            optional: true,
                            alias: dep_alias,
                        });
                    }
                }

                // Insert node into graph
                graph.nodes.insert(
                    key,
                    DepNode {
                        name: pending.name.clone(),
                        alias: pending.alias.clone(),
                        version: resolved_version.version.to_string(),
                        resolved: info.dist.tarball.clone(),
                        integrity: info.dist.integrity.clone(),
                        dependencies: node_deps,
                        has_install_script: info.has_install_script,
                        dev: pending.dev,
                        optional: pending.optional,
                    },
                );
            }

            current_level = next_level;
        }

        // Fix up dependency maps: resolve spec strings to actual "name@version" keys
        // At this point all nodes are resolved, so we can find which key satisfies each dep
        let all_keys: Vec<String> = graph.nodes.keys().cloned().collect();
        let mut fixups: Vec<(String, HashMap<String, String>)> = Vec::new();

        for (node_key, node) in &graph.nodes {
            let mut resolved_deps: HashMap<String, String> = HashMap::new();
            for (dep_name, dep_spec) in &node.dependencies {
                // The dep_spec might be a semver range like "~2.0.0" or "^1.3.8"
                // Find the node in the graph that has this name and satisfies the spec
                let resolved_key = find_matching_key(&all_keys, &graph, dep_name, dep_spec);
                if let Some(rk) = resolved_key {
                    resolved_deps.insert(dep_name.clone(), rk);
                }
                // If not found (optional dep that was skipped), just drop it
            }
            fixups.push((node_key.clone(), resolved_deps));
        }

        for (key, deps) in fixups {
            if let Some(node) = graph.nodes.get_mut(&key) {
                node.dependencies = deps;
            }
        }

        info!(
            "resolution complete: {} packages",
            graph.package_count()
        );

        Ok(graph)
    }
}
