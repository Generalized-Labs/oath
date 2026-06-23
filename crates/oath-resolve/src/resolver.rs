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
            current_level.push(PendingDep {
                name: name.clone(),
                specifier: spec.clone(),
                depth: 0,
                dev: false,
                optional: false,
            });
        }

        if self.options.include_dev {
            for (name, spec) in dev_dependencies {
                current_level.push(PendingDep {
                    name: name.clone(),
                    specifier: spec.clone(),
                    depth: 0,
                    dev: true,
                    optional: false,
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

                let key = DepGraph::key(&pending.name, resolved_version.version);

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

                // Build dependency map for this node
                let mut node_deps = HashMap::new();

                // Queue production dependencies for next level
                for (dep_name, dep_spec) in &info.dependencies {
                    node_deps.insert(dep_name.clone(), dep_spec.clone());

                    next_level.push(PendingDep {
                        name: dep_name.clone(),
                        specifier: dep_spec.clone(),
                        depth: pending.depth + 1,
                        dev: pending.dev,
                        optional: false,
                    });
                }

                // Queue optional dependencies
                if self.options.include_optional {
                    for (dep_name, dep_spec) in &info.optional_dependencies {
                        node_deps.insert(dep_name.clone(), dep_spec.clone());
                        next_level.push(PendingDep {
                            name: dep_name.clone(),
                            specifier: dep_spec.clone(),
                            depth: pending.depth + 1,
                            dev: pending.dev,
                            optional: true,
                        });
                    }
                }

                // Insert node into graph
                graph.nodes.insert(
                    key,
                    DepNode {
                        name: pending.name.clone(),
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

        info!(
            "resolution complete: {} packages",
            graph.package_count()
        );

        Ok(graph)
    }
}
