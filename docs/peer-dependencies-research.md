# Peer Dependencies: Deep Technical Research for oath

## 1. What Are Peer Dependencies Exactly

### Semantic Definition

`peerDependencies` in package.json means:

> "I need a package at my **call site** (the project that installed me), not a copy I own. I will use whatever version the consumer provides, and we share the same instance."

This contrasts with:

| Field | Who installs it | Who owns the instance | When missing |
|---|---|---|---|
| `dependencies` | The package manager | The package itself (nested copy allowed) | Hard error |
| `devDependencies` | The package manager | The package itself | Not installed in production |
| `optionalDependencies` | The package manager | The package itself | Silently skipped |
| `peerDependencies` | **The consumer** | **Shared with consumer** | Warning (npm v3-v6) or auto-install (npm v7+) |

The critical semantic is **singleton enforcement**. When react-dom and react must share the same React instance (the reconciler, fiber tree, hooks state), they cannot be different copies. A duplicate `react` in node_modules causes the infamous "Hooks can only be called inside a function component" error. Peer deps are the mechanism to say "resolve this from the host environment."

### History: npm v3, v6, v7

**npm v1-v2**: Nested deps. Each package got its own copy. Peer deps weren't needed because hoisting didn't exist.

**npm v3-v6 (2015-2020)**: Flat hoisting introduced. `peerDependencies` listed in package.json but **npm did NOT auto-install them**. npm v3+ emitted a warning if the peer dep was missing or incompatible. The consumer had to add it themselves.

```
npm WARN react-dom@18.2.0 requires a peer of react@^18.0.0 but none is installed.
```

**npm v7+ (2021-present)**: `peerDependencies` are **auto-installed by default**. This is a breaking change from v6. The algorithm npm v7 uses:

1. Walk the full dependency tree
2. For every package with `peerDependencies`, find the **closest ancestor** in the logical tree that satisfies the peer range
3. If found and compatible: use that version (no duplicate)
4. If two consumers need incompatible versions: install both, nested under each consumer
5. If missing entirely: install the peer at the root level choosing `latest` matching the range

npm v7 also introduced `--legacy-peer-deps` flag to restore v6 behavior (skip auto-install, just warn).

### peerDependenciesMeta

Introduced in npm v6.25 / node_modules spec. Allows marking individual peer deps as optional:

```json
{
  "peerDependencies": {
    "react": "^18.0.0",
    "@types/react": "^18.0.0"
  },
  "peerDependenciesMeta": {
    "@types/react": {
      "optional": true
    }
  }
}
```

Semantics:
- `optional: true` → if the peer dep is missing, do NOT warn. The package will work without it.
- `optional: false` (default) → if missing, emit a warning (or error in strict modes)
- The `peerDependenciesMeta` key must match a key in `peerDependencies`

**oath already parses this** in `packument.rs` (`PeerDepMeta { optional: bool }`). It is not yet used.

---

## 2. The Three Behaviors Across Tools

### npm v7+ Algorithm

npm v7 uses an **arborist** (tree manipulation library) with this peer dep strategy:

```
function placePeer(pkg, peerName, peerRange, parent):
  // Walk up from parent to find who can provide peerName
  node = parent
  while node != root:
    if node.deps.has(peerName):
      resolved = node.deps[peerName]
      if semver.satisfies(resolved.version, peerRange):
        // Peer satisfied by ancestor - done, no new install
        return resolved
      else:
        // Conflict! Need to nest
        break
    node = node.parent

  // Not found walking up: install at the deepest common ancestor
  // that owns pkg, resolving the range against registry
  install_at(commonAncestor(pkg), peerName, peerRange)
```

Conflict handling in npm v7: when `plugin-a` needs `eslint@^7` and `plugin-b` needs `eslint@^8`, npm v7 will:
1. If root has `eslint@8`: satisfy plugin-b at root, nest `eslint@7` under plugin-a's subtree
2. Emit `ERESOLVE` if there's no way to satisfy without duplication (strict mode)
3. With `--legacy-peer-deps`: ignore, just warn

The `ERESOLVE` error includes the full conflict chain.

### pnpm Peer Dep Modes

pnpm is the most sophisticated. It uses **virtual store instances** (exactly what oath is doing with `.oath/`). Its key insight: if `eslint-plugin-react` is installed with different `eslint` versions by different consumers, they become **different virtual store entries**:

```
node_modules/.pnpm/eslint-plugin-react@7.33.2_eslint@7.32.0/
node_modules/.pnpm/eslint-plugin-react@7.33.2_eslint@8.57.0/
```

The `_peers` suffix in pnpm lockfile keys encodes this. This is the pnpm lockfile entry:

```yaml
# pnpm-lock.yaml
/eslint-plugin-react@7.33.2:
  resolution: {integrity: sha512-...}
  peerDependencies:
    eslint: ^3 || ^4 || ^5 || ^6 || ^7 || ^8 || ^9
  dependencies:
    eslint: 8.57.0  # <-- resolved peer
    # ... other deps
```

pnpm has three peer dep modes (set in `.npmrc` or `pnpm-workspace.yaml`):

| Mode | Behavior |
|---|---|
| `strict` (default) | Error if peer dep is missing. No auto-install. Consumer must list peers explicitly. |
| `auto` | Auto-install missing peers from registry. Most like npm v7. |
| `legacy` | Like npm v3-v6: warn only, no auto-install, no error. |

pnpm peer resolution algorithm:
1. When resolving package A with `peerDeps: [B@^2]`
2. Walk up A's **dependency chain in the install tree** (not the registry tree)
3. Find the nearest ancestor that has B installed
4. If B's version satisfies `^2`: A and that ancestor **share** the same B instance
5. If B's version does NOT satisfy `^2`: conflict, create a new virtual store entry for A with the correct B version nested
6. The virtual store key becomes `A@x.y.z_B@version` where `B@version` is the peer that was resolved

**This is why pnpm's approach is correct for oath**: since oath already uses `.oath/` as a virtual store, it can do the same peer-keyed instancing.

### Yarn Berry (PnP)

Yarn Berry uses Plug'n'Play (PnP) which replaces node_modules entirely with a zip store + resolution map. Its peer dep approach:

1. Each package instance is identified by `(name, version, set_of_peer_resolutions)`
2. The `.pnp.cjs` file contains a flat map of `(package, peer_context) -> location`
3. Peer deps are "virtualized" - a package with peers gets a unique virtual path per peer resolution context

```
# .pnp.cjs entry (simplified)
["eslint-plugin-react", [
  ["npm:7.33.2", {
    "packageLocation": ".yarn/cache/eslint-plugin-react-npm-7.33.2-abc.zip/node_modules/eslint-plugin-react/",
    "packageDependencies": [
      ["eslint", "npm:8.57.0"],   # peer resolved to this
      ...
    ]
  }]
]]
```

For oath, PnP is out of scope. The node_modules layout model is more relevant.

### Correct node_modules Layout for Peer Deps

Given project with:
```json
{
  "dependencies": {
    "react": "^18.0.0",
    "react-dom": "^18.0.0"
  }
}
```

`react-dom` has `peerDependencies: { "react": "^18.0.0" }`.

**Correct layout (pnpm-style, what oath should do):**

```
node_modules/
  .oath/
    react@18.3.1/
      node_modules/
        react/              <- the actual react package files
    react-dom@18.3.1/
      node_modules/
        react-dom/          <- the actual react-dom package files
        react/              <- SYMLINK to .oath/react@18.3.1/node_modules/react
                               (peer dep resolved to consumer's react)
  react/                    <- top-level symlink -> .oath/react@18.3.1/node_modules/react
  react-dom/                <- top-level symlink -> .oath/react-dom@18.3.1/node_modules/react-dom
```

The key: `react-dom`'s virtual store entry gets a symlink to the consumer's `react` instance, NOT a new copy. Both `react` and `react-dom` resolve `require('react')` to the **same physical files**.

**With a conflict** (two packages need different react versions):

```
node_modules/
  .oath/
    react@17.0.2/
      node_modules/
        react/
    react@18.3.1/
      node_modules/
        react/
    legacy-component@1.0.0/
      node_modules/
        legacy-component/
        react/  <- symlink to .oath/react@17.0.2/...  (peer resolved to 17)
    react-dom@18.3.1/
      node_modules/
        react-dom/
        react/  <- symlink to .oath/react@18.3.1/...  (peer resolved to 18)
  react/         <- top-level: hoisted v18
  react-dom/
```

---

## 3. Real Package Examples

### react-dom@18.3.1

```json
{
  "name": "react-dom",
  "version": "18.3.1",
  "peerDependencies": {
    "react": "^18.3.1"
  }
}
```

Note: react-dom 18.x has exactly one peer dep (react), no optional meta. The version range is tight (`^18.3.1` as of 18.3.1 release).

react-dom 19.x:
```json
{
  "peerDependencies": {
    "react": "^19.0.0"
  }
}
```

### @testing-library/react@14.x

```json
{
  "peerDependencies": {
    "@testing-library/dom": "^9.0.0",
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "react": "^18.0.0",
    "react-dom": "^18.0.0"
  },
  "peerDependenciesMeta": {
    "@types/react": {
      "optional": true
    },
    "@types/react-dom": {
      "optional": true
    }
  }
}
```

This is a canonical example of `peerDependenciesMeta`: TypeScript types are optional because non-TypeScript projects don't need them.

### eslint-plugin-react@7.33.2

```json
{
  "peerDependencies": {
    "eslint": "^3 || ^4 || ^5 || ^6 || ^7 || ^8 || ^9"
  }
}
```

Wide range because ESLint has been stable for years and plugin authors want maximum compatibility. This is why the conflict detection must check version intersection, not just "is it installed."

### tailwindcss@3.4.x

```json
{
  "peerDependencies": {
    "postcss": "^8.0.9"
  },
  "peerDependenciesMeta": {
    "postcss": {
      "optional": true
    }
  }
}
```

Tailwind can run CLI without postcss (it bundles its own transformer), but postcss is required when used as a postcss plugin. Hence `optional: true`.

### @fastify/cors@9.x (representative fastify plugin)

```json
{
  "peerDependencies": {
    "fastify": "^4.x.x"
  }
}
```

All `@fastify/*` plugins declare fastify itself as a peer:

- `@fastify/cors`: `"fastify": "^4.x.x"`
- `@fastify/jwt`: `"fastify": "^4.x.x"`
- `@fastify/static`: `"fastify": "^4.x.x"`
- `@fastify/multipart`: `"fastify": "^4.x.x"`
- `@fastify/rate-limit`: `"fastify": "^4.x.x"`

In fastify v5 ecosystem these are being bumped to `"fastify": "^5.x.x"`. This is the canonical plugin host pattern: the plugin decorates the host instance (fastify server), so they must share the exact same instance.

### Summary Table of Real Peer Deps

| Package | Peer | Range | Optional? |
|---|---|---|---|
| react-dom@18 | react | ^18.3.1 | no |
| @testing-library/react@14 | react | ^18.0.0 | no |
| @testing-library/react@14 | react-dom | ^18.0.0 | no |
| @testing-library/react@14 | @types/react | ^18.0.0 | **yes** |
| @testing-library/react@14 | @types/react-dom | ^18.0.0 | **yes** |
| eslint-plugin-react@7 | eslint | ^3\|\|^4\|\|^5\|\|^6\|\|^7\|\|^8\|\|^9 | no |
| tailwindcss@3 | postcss | ^8.0.9 | **yes** |
| @fastify/* | fastify | ^4.x.x | no |

---

## 4. The Resolution Algorithm

### Core Principle: Peers Come From The Consumer

When package A declares `peerDependencies: { B: "^2.0.0" }`, B must come from **A's install context**, not from A's own subtree. Specifically:

```
Given install tree:
  project
    ├── A@1.0.0  [peerDep: B@^2]
    └── B@2.5.0  [direct dep of project]

Resolution: A's peer B resolves to B@2.5.0 (from project, A's parent/ancestor)
```

The lookup rule: **walk up the dependency chain from A until you find an ancestor that directly depends on B, and whose B satisfies A's peer range.**

```
function resolve_peer(pkg_A, peer_name, peer_range, install_tree):
  // Start at the package that depends on pkg_A
  node = install_tree.parent_of(pkg_A)
  while node != null:
    if node.has_dependency(peer_name):
      b_version = node.resolved_version(peer_name)
      if semver_satisfies(b_version, peer_range):
        return b_version  // Success: use this instance
      else:
        return PeerConflict { found: b_version, required: peer_range }
    node = node.parent
  return PeerMissing { name: peer_name, range: peer_range }
```

### Conflict Detection

A **peer conflict** occurs when two packages need incompatible versions of the same peer:

```
project
  ├── plugin-a@1.0  [peerDep: eslint@^7]
  ├── plugin-b@2.0  [peerDep: eslint@^8]
  └── eslint@8.57   [direct dep]
```

Here `plugin-a` needs `eslint@^7` but only `eslint@8.57` is available. This is a conflict.

**Detection algorithm:**
```
function detect_peer_conflicts(graph):
  conflicts = []
  for each pkg in graph:
    for (peer_name, peer_range) in pkg.peer_dependencies:
      resolved = resolve_peer(pkg, peer_name, peer_range, graph)
      match resolved:
        PeerMissing => conflicts.push(Missing { pkg, peer_name, peer_range })
        PeerConflict { found, required } =>
          conflicts.push(Conflict { pkg, peer_name, required: peer_range, found })
        Ok(version) => record_peer_resolution(pkg, peer_name, version)
  return conflicts
```

**Resolution strategies for conflicts:**
1. **Error** (pnpm strict): fail with message showing the conflict chain
2. **Auto-nest** (npm v7): install a separate copy of the peer that satisfies the conflicting consumer, nested under it
3. **Warn** (legacy): emit warning, use whatever peer version exists

### The pnpm Lockfile Peers Suffix

pnpm encodes peer resolution in lockfile keys to ensure reproducibility:

```
# In pnpm-lock.yaml
packages:

  /eslint-plugin-react@7.33.2(eslint@8.57.0):
    resolution: {integrity: sha512-...}
    peerDependencies:
      eslint: ^3 || ^4 || ^5 || ^6 || ^7 || ^8 || ^9
    dependencies:
      eslint: 8.57.0   # the resolved peer
      array-includes: 3.1.7
      ...

  /eslint-plugin-react@7.33.2(eslint@7.32.0):
    # A DIFFERENT instance of the same package version
    # because a different consumer provides eslint@7
    dependencies:
      eslint: 7.32.0
      ...
```

The key insight: **the same package version can appear multiple times in the lockfile with different peer resolutions**. The key uniquely identifies the (package, peers) combination.

For oath, the equivalent would be lockfile keys like:
```json
"eslint-plugin-react@7.33.2+eslint@8.57.0": { ... }
```

And in the virtual store:
```
node_modules/.oath/eslint-plugin-react@7.33.2+eslint@8.57.0/
```

### Missing Peer Dep Decision Matrix

| Peer marked optional? | Consumer has peer? | Version satisfies? | Action |
|---|---|---|---|
| yes | no | n/a | Silent skip - no warning |
| yes | yes | no | Warn: found incompatible version |
| yes | yes | yes | Ok |
| no | no | n/a | **Warn** (MVP) or **Error** (strict mode) |
| no | yes | no | **Error** or conflict resolution |
| no | yes | yes | Ok |

For an MVP: warn on missing non-optional peers, error on version incompatibility when the range doesn't overlap at all.

---

## 5. What To Build for oath: Concrete Implementation Plan

### Current State (What Already Exists)

oath already has:
- `packument.rs`: Deserializes `peerDependencies` and `peerDependenciesMeta` from registry metadata ✓
- `manifest.rs`: Has `peer_dependencies: HashMap<String, String>` field ✓
- `graph.rs/DepNode`: Does NOT have a `peer_dependencies` field ✗
- `resolver.rs`: Does NOT process peer deps AT ALL ✗
- `linker.rs`: Does NOT handle peer dep linking ✗
- `lockfile.rs`: Does NOT record peer resolutions ✗

### Phase 1: Data Structures (oath-resolve, oath-core)

#### 1a. Add peer info to DepNode (`graph.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepNode {
    pub name: String,
    pub alias: Option<String>,
    pub version: String,
    pub resolved: String,
    pub integrity: Option<String>,
    pub dependencies: HashMap<String, String>,
    pub has_install_script: bool,
    pub dev: bool,
    pub optional: bool,
    // NEW FIELDS:
    /// peerDependencies: name -> semver range (from package.json)
    #[serde(default)]
    pub peer_dependencies: HashMap<String, String>,
    /// Which peers are optional (from peerDependenciesMeta)
    #[serde(default)]
    pub optional_peers: HashSet<String>,
    /// Resolved peer deps: name -> "name@version" key in the graph
    /// Populated after resolution pass
    #[serde(default)]
    pub resolved_peers: HashMap<String, String>,
}
```

#### 1b. Add peer conflict types (`resolver.rs` or new `peers.rs`)

```rust
#[derive(Debug, Clone)]
pub enum PeerResolution {
    /// Peer was found and satisfies the range
    Satisfied { peer_key: String },
    /// Peer not found in the install context
    Missing { peer_name: String, range: String, required_by: String },
    /// Peer found but wrong version
    Conflict {
        peer_name: String,
        range: String,
        found_version: String,
        required_by: String,
    },
}

#[derive(Debug, Default)]
pub struct PeerReport {
    pub satisfied: Vec<PeerResolution>,
    pub missing: Vec<PeerResolution>,     // warn: non-optional, missing
    pub conflicts: Vec<PeerResolution>,   // warn/error: version mismatch
    pub optional_missing: Vec<String>,    // silent: optional peers absent
}
```

#### 1c. Add peers to lockfile (`lockfile.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub version: String,
    pub resolved: String,
    pub integrity: Option<String>,
    pub dependencies: HashMap<String, String>,
    pub dev: bool,
    pub optional: bool,
    pub has_install_script: bool,
    pub alias: Option<String>,
    // NEW:
    /// Peer dependencies declared by this package (name -> range)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub peer_dependencies: HashMap<String, String>,
    /// Resolved peers (name -> "name@version" key)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub resolved_peers: HashMap<String, String>,
}
```

### Phase 2: Resolver Changes (`resolver.rs`)

The BFS resolver needs a two-pass approach because peers can only be resolved after the full tree is built (you need to know what the consumer has).

#### Step 1: During BFS - Capture Peer Requirements

In the BFS loop where packages are processed, record peer deps but **do NOT add them to next_level**:

```rust
// In the BFS loop, after building node_deps:
// Record peer deps declared by this package
let peer_dependencies: HashMap<String, String> = info.peer_dependencies.clone();
let optional_peers: HashSet<String> = info.peer_dependencies_meta
    .iter()
    .filter(|(_, meta)| meta.optional)
    .map(|(name, _)| name.clone())
    .collect();

// Insert node with peer info
graph.nodes.insert(key, DepNode {
    name: pending.name.clone(),
    // ... existing fields ...
    peer_dependencies,
    optional_peers,
    resolved_peers: HashMap::new(), // filled in pass 2
});
```

#### Step 2: Build Parent Map

After BFS completes, build a map of `child_key -> parent_key(s)` (which packages depend on which):

```rust
fn build_parent_map(graph: &DepGraph) -> HashMap<String, Vec<String>> {
    let mut parents: HashMap<String, Vec<String>> = HashMap::new();
    // Root packages have the "project" as parent
    for root_key in &graph.roots {
        parents.entry(root_key.clone()).or_default(); // root has no package parent
    }
    for (parent_key, parent_node) in &graph.nodes {
        for dep_key in parent_node.dependencies.values() {
            parents.entry(dep_key.clone())
                .or_default()
                .push(parent_key.clone());
        }
    }
    parents
}
```

#### Step 3: Resolve Peers (Post-BFS Pass)

```rust
fn resolve_peers(graph: &mut DepGraph) -> PeerReport {
    let mut report = PeerReport::default();
    // Build the parent map first
    let parents = build_parent_map(graph);

    // For each node with peer deps, walk up to find the peer
    let node_keys: Vec<String> = graph.nodes.keys().cloned().collect();
    for pkg_key in &node_keys {
        let peer_deps: Vec<(String, String)> = {
            let node = &graph.nodes[pkg_key];
            node.peer_dependencies.iter()
                .map(|(n, r)| (n.clone(), r.clone()))
                .collect()
        };
        let optional_peers: HashSet<String> = {
            graph.nodes[pkg_key].optional_peers.clone()
        };

        for (peer_name, peer_range) in peer_deps {
            let resolution = find_peer_in_context(
                graph, &parents, pkg_key, &peer_name, &peer_range
            );
            match &resolution {
                Ok(peer_key) => {
                    graph.nodes.get_mut(pkg_key)
                        .unwrap()
                        .resolved_peers
                        .insert(peer_name.clone(), peer_key.clone());
                    report.satisfied.push(PeerResolution::Satisfied {
                        peer_key: peer_key.clone()
                    });
                }
                Err(PeerError::Missing) => {
                    if optional_peers.contains(&peer_name) {
                        report.optional_missing.push(peer_name.clone());
                    } else {
                        report.missing.push(PeerResolution::Missing {
                            peer_name: peer_name.clone(),
                            range: peer_range.clone(),
                            required_by: pkg_key.clone(),
                        });
                    }
                }
                Err(PeerError::Conflict { found_version }) => {
                    report.conflicts.push(PeerResolution::Conflict {
                        peer_name: peer_name.clone(),
                        range: peer_range.clone(),
                        found_version: found_version.clone(),
                        required_by: pkg_key.clone(),
                    });
                }
            }
        }
    }
    report
}

fn find_peer_in_context(
    graph: &DepGraph,
    parents: &HashMap<String, Vec<String>>,
    pkg_key: &str,
    peer_name: &str,
    peer_range: &str,
) -> Result<String, PeerError> {
    // BFS/walk up through parents looking for peer_name
    let mut visited = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    if let Some(parent_keys) = parents.get(pkg_key) {
        for p in parent_keys {
            queue.push_back(p.clone());
        }
    }

    while let Some(ancestor_key) = queue.pop_front() {
        if !visited.insert(ancestor_key.clone()) {
            continue;
        }
        // Check if this ancestor has peer_name as a resolved dependency
        let ancestor = match graph.nodes.get(&ancestor_key) {
            Some(n) => n,
            None => continue,
        };

        // Does this ancestor have peer_name in its deps?
        if let Some(resolved_key) = ancestor.dependencies.get(peer_name) {
            // Extract version from "name@version" key
            if let Some(at) = resolved_key.rfind('@') {
                let found_version = &resolved_key[at+1..];
                if semver_satisfies(found_version, peer_range) {
                    return Ok(resolved_key.clone());
                } else {
                    return Err(PeerError::Conflict {
                        found_version: found_version.to_string()
                    });
                }
            }
        }
        // Walk further up
        if let Some(grandparents) = parents.get(&ancestor_key) {
            for gp in grandparents {
                queue.push_back(gp.clone());
            }
        }
    }

    // Also check roots (direct project deps)
    // Roots are in graph.roots - these represent the consumer's direct deps
    for root_key in &graph.roots {
        let root_node = match graph.nodes.get(root_key) {
            Some(n) => n,
            None => continue,
        };
        let install_name = root_node.alias.as_deref().unwrap_or(&root_node.name);
        if install_name == peer_name || root_node.name == peer_name {
            let found_version = &root_node.version;
            if semver_satisfies(found_version, peer_range) {
                return Ok(root_key.clone());
            } else {
                return Err(PeerError::Conflict {
                    found_version: found_version.to_string()
                });
            }
        }
    }

    Err(PeerError::Missing)
}
```

**Note on current resolver architecture**: The current BFS in `resolver.rs` uses a flat graph where `resolved` is a `HashSet<String>` of `name@version` keys. There is no parent tracking. You need to add parent tracking during the BFS:

```rust
// Add to Resolver struct or pass through BFS:
// pending_dep -> parent key that enqueued it
let mut parent_of: HashMap<String, Option<String>> = HashMap::new();
// When enqueueing deps from a node:
parent_of.insert(child_key, Some(parent_key.clone()));
// Root deps:
parent_of.insert(root_key, None);
```

### Phase 3: Linker Changes (`linker.rs`)

The linker needs to know about peer resolutions to correctly wire up symlinks.

#### Current behavior: deps are linked via `node.dependencies`
The linker already creates symlinks for dependencies in Phase 4 (transitive dep linking). Peer deps need the same treatment but sourced from `resolved_peers`.

#### New linker logic for peers

In Phase 4 of `link_all`, add peer symlink creation:

```rust
// Phase 4b: Create peer dep symlinks within each package's .oath node_modules
for (key, node) in &graph.nodes {
    for (peer_name, peer_key) in &node.resolved_peers {
        let peer_node = match graph.nodes.get(peer_key) {
            Some(n) => n,
            None => continue,
        };
        let peer_install_name = peer_node.alias.as_deref()
            .unwrap_or(&peer_node.name);

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
            if peer_install_name.contains('/') {
                if let Some(scope) = peer_install_name.split('/').next() {
                    std::fs::create_dir_all(
                        oath_dir.join(key).join("node_modules").join(scope)
                    )?;
                }
            }
            let relative = compute_relative_path(&target, &source);
            std::os::unix::fs::symlink(&relative, &target).ok();
        }
    }
}
```

Note the current `pathdiff_relative` function in `linker.rs` is broken (returns absolute path). For peer symlinks to work correctly across `.oath/pkg@ver/node_modules/` paths, proper relative path computation is critical. The current function returns `to.to_path_buf()` (absolute path), which will break on any system where the project is not at `/`. This must be fixed.

### Phase 4: User-Facing Warnings/Errors

In `oath-cli` (where `link_all` and `resolve` are called), after running resolution:

```
oath install:
  Resolving 47 packages...

  Peer dependency warnings:
  ⚠  eslint-plugin-react@7.33.2 requires eslint@^3||^4||^5||^6||^7||^8||^9
     → satisfied by eslint@8.57.0 ✓

  ⚠  @testing-library/react@14.0.0 requires react@^18.0.0
     → satisfied by react@18.3.1 ✓

  ⚠  react-dom@18.3.1 requires react@^18.3.1 but none found in dependencies
     → Add "react": "^18.3.1" to your package.json dependencies

  ✗  @fastify/cors@9.0.0 requires fastify@^4.x.x
     Found fastify@5.0.0 — incompatible! Required: ^4.x.x, Found: 5.0.0
```

Severity rules:
- `PeerResolution::Satisfied` → debug log only (verbose mode)
- `PeerResolution::Missing` (non-optional) → `WARN` to stderr
- `PeerResolution::Conflict` → `ERROR` to stderr, non-zero exit with `--strict-peer-deps`
- `optional_missing` → completely silent

### Phase 5: Lockfile Peer Recording

Update `Lockfile::from_graph` to serialize `resolved_peers`:

```rust
pub fn from_graph(graph: &DepGraph, project_name: &str, project_version: &str) -> Self {
    let packages = graph.nodes.iter().map(|(key, node)| {
        let entry = LockEntry {
            // ... existing fields ...
            peer_dependencies: node.peer_dependencies.clone(),
            resolved_peers: node.resolved_peers.clone(),
        };
        (key.clone(), entry)
    }).collect();
    // ...
}
```

On fast-path install (lockfile present, no changes), read `resolved_peers` directly from lockfile entries. Skip peer resolution pass entirely.

---

## 6. MVP Scope: What Unblocks Real Projects

The minimum peer dep support that makes real ecosystems work:

### Must Have (MVP)

1. **Pass peer dep info through BFS into DepNode** (5 lines in resolver.rs)
   - Already parsed by packument.rs, just not stored in graph nodes
   - Blocks: everything below

2. **Post-BFS peer resolution pass** (new ~100 line function)
   - Walk up parent chain for each package with peer deps
   - Populate `resolved_peers` on each DepNode
   - Output: `PeerReport` with satisfied/missing/conflicts

3. **Peer symlinks in linker** (~30 lines in linker.rs Phase 4b)
   - For each `resolved_peers` entry, create symlink in virtual store
   - This makes react-dom able to find react, fastify plugins find fastify
   - **Fix `pathdiff_relative`** — currently returns absolute paths, peer symlinks will be broken

4. **Warnings for missing non-optional peers** (in oath-cli)
   - Emit warning to stderr when non-optional peer is absent
   - Use `peerDependenciesMeta.optional` to suppress false warnings

### Nice to Have (Post-MVP)

5. **`--strict-peer-deps` flag** — exit with error on any peer conflict
6. **Auto-install missing peers** — like npm v7, resolve and add missing peers to install set
7. **Peer-keyed virtual store entries** — like pnpm's `pkg@ver+peer@ver` keys for true isolation of conflicting peer instances
8. **`peerDependencies` in oath's own `PackageManifest`** — currently missing `peerDependenciesMeta` field

### Critical Bug to Fix Before Peers

`pathdiff_relative` in `linker.rs` (line 418-422):
```rust
fn pathdiff_relative(_from: &Path, to: &Path) -> PathBuf {
    // BUG: returns absolute path, not relative
    to.to_path_buf()
}
```
This is used for peer symlinks and transitive dep symlinks in Phase 4. Any project not running from `/` will have broken symlinks. Replace with actual relative path computation (walk up from `from` to common ancestor, then down to `to`).

### Effort Estimate

| Task | Files | Complexity | Lines |
|---|---|---|---|
| Add peer fields to DepNode | graph.rs | trivial | ~15 |
| Add peer fields to LockEntry | lockfile.rs | trivial | ~10 |
| Capture peers in BFS | resolver.rs | easy | ~20 |
| Build parent map | resolver.rs | medium | ~30 |
| Post-BFS peer resolution | resolver.rs | medium-hard | ~100 |
| Peer symlinks in linker | linker.rs | easy | ~40 |
| Fix pathdiff_relative | linker.rs | medium | ~30 |
| CLI warnings | oath-cli/main.rs | easy | ~40 |
| Tests | resolver tests | medium | ~100 |

Total: ~385 lines for full MVP peer dep support.

---

## 7. The pnpm `__virtual__` / Peer-Keyed Store Pattern

For oath to handle the hard case (same package version with two different peer resolutions), it needs peer-keyed virtual store entries. This is how pnpm does it:

```
# Two consumers use different eslint:
# project-a uses eslint@8, project-b uses eslint@7

node_modules/.pnpm/
  eslint-plugin-react@7.33.2_eslint@7.32.0/
    node_modules/
      eslint-plugin-react/
      eslint -> ../../eslint@7.32.0/node_modules/eslint  # peer symlink
  eslint-plugin-react@7.33.2_eslint@8.57.0/
    node_modules/
      eslint-plugin-react/
      eslint -> ../../eslint@8.57.0/node_modules/eslint  # peer symlink
```

For oath to do this, the `DepGraph` key generation in `DepGraph::key` needs a variant:

```rust
pub fn key_with_peers(name: &str, version: &str, peers: &[(String, String)]) -> String {
    if peers.is_empty() {
        return format!("{name}@{version}");
    }
    let peer_suffix: String = peers.iter()
        .map(|(n, v)| format!("{n}@{v}"))
        .collect::<Vec<_>>()
        .join("+");
    format!("{name}@{version}+{peer_suffix}")
}
```

This is **not needed for MVP** but is needed for correctness in monorepos where different workspaces use different versions of shared plugins.

---

## Quick Reference: Files to Modify

```
oath/
  crates/
    oath-resolve/src/
      graph.rs          -- Add peer_dependencies, optional_peers, resolved_peers to DepNode
      resolver.rs       -- Capture peers in BFS; add post-BFS peer resolution pass
      lockfile.rs       -- Add peer_dependencies, resolved_peers to LockEntry

    oath-store/src/
      linker.rs         -- Add Phase 4b peer symlinks; fix pathdiff_relative

    oath-cli/src/
      main.rs           -- Print PeerReport warnings after resolve()

    oath-core/src/
      manifest.rs       -- Add peerDependenciesMeta field (already has peer_dependencies)
```
