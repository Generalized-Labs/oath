//! Dependency resolver
//!
//! BFS resolution: start with root deps, resolve each, collect their deps,
//! repeat until all dependencies are resolved. Deduplicates automatically
//! (same name + compatible version = share one resolved copy).

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
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
    packument_cache: HashMap<String, Packument>,
}

impl Resolver {
    pub fn new(client: RegistryClient, options: ResolveOptions) -> Self {
        Self {
            client,
            options,
            packument_cache: HashMap::new(),
        }
    }

    /// Resolve all dependencies starting from a map of direct dependencies.
    ///
    /// Returns a complete dependency graph with all transitive deps resolved.
    pub async fn resolve(
        &mut self,
        dependencies: &HashMap<String, String>,
        dev_dependencies: &HashMap<String, String>,
    ) -> Result<DepGraph> {
        let mut graph = DepGraph::new();
        let mut queue: VecDeque<PendingDep> = VecDeque::new();
        let mut resolved: HashSet<String> = HashSet::new(); // "name@version" keys we've processed

        // Seed queue with direct dependencies
        for (name, spec) in dependencies {
            queue.push_back(PendingDep {
                name: name.clone(),
                specifier: spec.clone(),
                depth: 0,
                dev: false,
                optional: false,
            });
        }

        if self.options.include_dev {
            for (name, spec) in dev_dependencies {
                queue.push_back(PendingDep {
                    name: name.clone(),
                    specifier: spec.clone(),
                    depth: 0,
                    dev: true,
                    optional: false,
                });
            }
        }

        let mut packages_resolved = 0u32;

        while let Some(pending) = queue.pop_front() {
            if pending.depth > self.options.max_depth {
                warn!("max depth exceeded for {}", pending.name);
                continue;
            }

            // Fetch packument (cached)
            let packument = self.get_packument(&pending.name).await?;

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

            // Queue production dependencies
            for (dep_name, dep_spec) in &info.dependencies {
                let dep_key = format!("{dep_name}@{dep_spec}"); // placeholder, real key computed on resolve
                node_deps.insert(dep_name.clone(), dep_spec.clone());

                queue.push_back(PendingDep {
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
                    queue.push_back(PendingDep {
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

        info!(
            "resolution complete: {} packages",
            graph.package_count()
        );

        Ok(graph)
    }

    /// Get a packument, using cache if available
    async fn get_packument(&mut self, name: &str) -> Result<Packument> {
        if let Some(cached) = self.packument_cache.get(name) {
            return Ok(cached.clone());
        }

        let packument = self
            .client
            .fetch_packument(name)
            .await
            .with_context(|| format!("fetching packument for {name}"))?;

        self.packument_cache.insert(name.to_string(), packument.clone());
        Ok(packument)
    }
}
