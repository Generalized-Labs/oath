# Workspace (Monorepo) Support for oath -- Deep Technical Research

---

## 1. THE WORKSPACE SPEC

### npm Workspaces

npm workspaces (v7+) are declared in the **root** `package.json`:

```json
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}
```

The `workspaces` field accepts:
- An **array of glob patterns** (most common)
- An object `{ "packages": ["apps/*"] }` (legacy Yarn Berry form)

The `@npmcli/map-workspaces` library (used internally by npm) expands these globs
using `glob` + `minimatch`. It:
1. Appends a trailing `/` to each pattern to force directory-only matching
2. Handles negation (`!packages/ignore-me/**`) by stripping excluded paths eagerly
3. Reads `package.json` inside each matched dir to get the canonical name
4. Returns a `Map<pkgName, absolutePath>` 
5. Errors with `EDUPLICATEWORKSPACE` if two dirs resolve to the same package name

**npm node_modules layout after workspace install:**

```
my-monorepo/
  node_modules/
    web/              <- symlink -> ../apps/web           (actual: relative symlink)
    @repo/ui/         <- symlink -> ../../packages/ui
    react/            <- hoisted (shared by all)
    react-dom/        <- hoisted
  apps/
    web/
      node_modules/   <- ONLY created if version conflict
        lodash/       <- nested, only if apps/web needs different version
  packages/
    ui/
      node_modules/   <- usually empty; uses root hoisted
```

npm's hoisting strategy: **flat hoisted by default**. All external deps are
deduped and placed at root `node_modules`. Workspace packages themselves get
symlinked at `node_modules/<pkg-name>` pointing to their actual disk location.
There is NO `.npm/` virtual store -- it goes directly to the workspace directory.

**Key npm workspace filter behavior** (from `lib/utils/get-workspaces.js`):
- `npm run build --workspace=web` -- matches by name
- `npm run build --workspace=apps/web` -- matches by relative path
- `npm run build --workspace=apps` -- matches all packages under that path prefix

### pnpm Workspaces

pnpm uses a **separate YAML file**: `pnpm-workspace.yaml` at the repo root:

```yaml
packages:
  - "apps/*"
  - "packages/*"
  - "!packages/ignore-this"
```

Real pnpm repo (pnpm itself at github.com/pnpm/pnpm):
```yaml
packages:
  - .meta-updater
  - pnpm11/__utils__/*
  - '!pnpm11/__utils__/build-artifacts'
  - pnpm11/auth/*
  - pnpm11/building/*
  # ... many more nested glob patterns
```

Real Next.js repo (github.com/vercel/next.js):
```yaml
packages:
  - 'apps/*'
  - 'packages/*'
  - 'bench/*'
  - 'crates/*/js'
  - 'turbopack/packages/*'
updateNotifier: false
publicHoistPattern:
  - '*eslint*'
allowBuilds:
  '@ast-grep/cli': true
ignoredBuiltDependencies:
  - '@swc/core'
```

Note `publicHoistPattern` -- pnpm by default does **NOT hoist** anything but
workspace packages and `.bin` entries to the root. `publicHoistPattern` forces
specific packages (like eslint plugins) to be publicly hoisted so editors can
find them.

**pnpm node_modules layout:**
```
root/
  node_modules/
    .pnpm/                          <- virtual store
      react@19.2.0/
        node_modules/
          react/                    <- hardlinked from global store
          js-tokens/                <- react's own dep
      @repo+ui@0.0.0/
        node_modules/
          @repo/ui/                 <- symlink -> ../../../../packages/ui
    react/                          <- symlink -> .pnpm/react@19.2.0/node_modules/react
    @repo/
      ui/                           <- symlink -> ../.pnpm/@repo+ui@0.0.0/node_modules/@repo/ui
  apps/
    web/
      node_modules/
        .modules.yaml               <- pnpm metadata
        react/                      <- symlink to root .pnpm (if same version)
  packages/
    ui/
      node_modules/
        # empty unless ui has unique deps
```

**The critical difference**: pnpm symlinks workspace packages *through* the
virtual store. The workspace package gets a `.pnpm` entry keyed as
`@repo+ui@0.0.0` (scoped slash replaced with `+`), and the actual content
is a symlink back to the workspace directory on disk. This means the workspace
package is always at its source location, but node's resolution still goes
through the virtual store path.

**pnpm --filter syntax:**
```
pnpm --filter web build             # exact package name
pnpm --filter @repo/ui build        # scoped name
pnpm --filter "./apps/**" build     # glob over paths
pnpm --filter "...web" build        # web and all its deps
pnpm --filter "web..." build        # web and all dependents
pnpm --filter "[HEAD~1]" build      # changed since git ref (Turborepo style)
pnpm -r run build                   # --recursive, all packages
```

### Yarn Workspaces (v1 Classic)

Yarn Classic uses the `workspaces` field in root `package.json` (same as npm):
```json
{
  "private": true,
  "workspaces": ["apps/*", "packages/*"]
}
```

Turborepo's `with-yarn` example uses exactly this format with `yarn@1.22.22`.

Yarn Classic hoisting: aggressive flat hoisting identical to npm. All deps at
root `node_modules`, workspace packages symlinked at `node_modules/<name>`.

Yarn Berry (v2+): uses Plug'n'Play (PnP) by default -- no `node_modules` at
all, packages stored as zip files. For non-PnP mode (`nodeLinker: node-modules`),
behavior is similar to Yarn Classic.

### Key Hoisting Strategy Differences

| Tool | Workspace symlink location | External dep hoisting | Virtual store |
|------|---------------------------|----------------------|---------------|
| npm  | `root/node_modules/<name>` -> `../packages/name` | Flat at root | None |
| pnpm | `root/node_modules/<name>` -> `.pnpm/<key>/node_modules/<name>` -> `../../../packages/name` | Only `.bin` + `publicHoistPattern` | `.pnpm/` |
| yarn classic | `root/node_modules/<name>` -> `../packages/name` | Flat at root | None |

**oath currently uses pnpm-style**: `.oath/` virtual store, hardlinks, symlinks.
Workspace support should follow the pnpm model.

---

## 2. REAL MONOREPO LAYOUTS

### Turborepo Basic Example (github.com/vercel/turbo/examples/basic)

**Root `pnpm-workspace.yaml`:**
```yaml
packages:
  - "apps/*"
  - "packages/*"
```

**Root `package.json`:**
```json
{
  "name": "my-turborepo",
  "private": true,
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev"
  },
  "devDependencies": {
    "prettier": "^3.7.4",
    "turbo": "^2.9.6",
    "typescript": "5.9.2"
  },
  "packageManager": "pnpm@9.0.0"
}
```

**apps/web/package.json:**
```json
{
  "name": "web",
  "dependencies": {
    "@repo/ui": "workspace:*",
    "next": "16.2.0",
    "react": "^19.2.0",
    "react-dom": "^19.2.0"
  },
  "devDependencies": {
    "@repo/eslint-config": "workspace:*",
    "@repo/typescript-config": "workspace:*"
  }
}
```

**packages/ui/package.json:**
```json
{
  "name": "@repo/ui",
  "version": "0.0.0",
  "private": true,
  "exports": {
    "./*": "./src/*.tsx"
  },
  "dependencies": {
    "react": "^19.2.0",
    "react-dom": "^19.2.0"
  }
}
```

**packages/typescript-config/package.json:**
```json
{
  "name": "@repo/typescript-config",
  "version": "0.0.0",
  "private": true
}
```

**packages/eslint-config/package.json:**
```json
{
  "name": "@repo/eslint-config",
  "version": "0.0.0",
  "private": true,
  "exports": {
    "./base": "./base.js",
    "./next-js": "./next.js",
    "./react-internal": "./react-internal.js"
  }
}
```

### Turborepo with-yarn Example

Root `package.json` for npm/yarn (no separate workspace yaml):
```json
{
  "name": "with-npm",
  "private": true,
  "workspaces": ["apps/*", "packages/*"],
  "packageManager": "npm@10.5.0"
}
```

With yarn, apps/web uses `"@repo/ui": "*"` (not `workspace:*`, which is pnpm-specific).
With pnpm, apps/web uses `"@repo/ui": "workspace:*"`.

### Expected node_modules after `pnpm install` in that monorepo:

```
root/
  node_modules/
    .pnpm/
      next@16.2.0/node_modules/next/
      react@19.2.0/node_modules/react/
      react-dom@19.2.0/node_modules/react-dom/
      typescript@5.9.2/node_modules/typescript/
      @repo+ui@0.0.0/node_modules/@repo/ui/  <- symlink -> ../../../../packages/ui
      @repo+eslint-config@0.0.0/...          <- symlink -> ../../../../packages/eslint-config
      @repo+typescript-config@0.0.0/...      <- symlink -> ../../../../packages/typescript-config
    .bin/
      tsc -> ../.pnpm/typescript@5.9.2/node_modules/.bin/tsc
      next -> ../.pnpm/next@16.2.0/node_modules/.bin/next
    react/            -> .pnpm/react@19.2.0/node_modules/react
    react-dom/        -> .pnpm/react-dom@19.2.0/node_modules/react-dom
    typescript/       -> .pnpm/typescript@5.9.2/node_modules/typescript
    @repo/
      ui/             -> ../.pnpm/@repo+ui@0.0.0/node_modules/@repo/ui
      eslint-config/  -> ../.pnpm/@repo+eslint-config@0.0.0/node_modules/@repo/eslint-config
      typescript-config/ -> ../.pnpm/...
  apps/
    web/
      node_modules/
        # pnpm creates per-package node_modules with symlinks only for that
        # package's direct dependencies, NOT a copy of root
        next/         -> symlink to root .pnpm entry (or workspace-local .pnpm)
        @repo/
          ui/         -> symlink to root .pnpm entry
  packages/
    ui/
      # no node_modules unless ui has deps not already in root
```

**Key insight**: In pnpm strict mode, each workspace package has its OWN
`node_modules` with symlinks only to packages it directly depends on. This
enforces no phantom dependencies -- `web` cannot `require('lodash')` if it
didn't declare lodash as a dependency, even if lodash was installed for
another workspace.

---

## 3. THE HARD PROBLEMS

### 3.1 Circular Dependencies Between Workspace Packages

Example:
- `packages/a` depends on `packages/b` via `"b": "workspace:*"`
- `packages/b` depends on `packages/a` via `"a": "workspace:*"`

This is a **DAG violation** but is valid in JavaScript because Node's `require`
handles circular CommonJS modules (returns partial exports). For type checking,
TypeScript handles project references cycles with `--allowCircularReferences`.

**How pnpm handles it**: pnpm allows workspace circular deps. Both packages get
their symlinks set up. The resolution terminates because workspace packages are
resolved to their disk path, not fetched recursively -- there's no infinite
resolution loop like with registry packages.

**For oath**: the resolver must detect `workspace:` references and short-circuit:
do NOT recurse into them during BFS. Instead, record them as `WorkspaceDep`
and resolve them in a second pass after all workspace packages are enumerated.

```rust
enum DepSource {
    Registry { tarball: String, integrity: Option<String> },
    Workspace { path: PathBuf },   // resolved from workspace manifest
    Local { path: PathBuf },       // file: or link: protocol
}
```

Cycle detection for the dependency graph: use a `visited: HashSet<PackageName>`
during workspace graph construction. Cycles between workspace packages are
allowed (just stop recursing on second visit). Cycles in external registry
packages cannot exist in practice (npm registry enforces acyclic deps).

### 3.2 Version Mismatches: lodash@3 vs lodash@4

Monorepo with:
- `apps/web` depends on `lodash@^4.0.0`
- `packages/legacy-utils` depends on `lodash@^3.0.0`

**npm behavior**: hoists `lodash@4` to root, nests `lodash@3` under `packages/legacy-utils/node_modules/lodash`.

**pnpm behavior**: both versions in virtual store:
```
.pnpm/
  lodash@4.17.21/node_modules/lodash/
  lodash@3.10.1/node_modules/lodash/
root/node_modules/
  lodash/   -> .pnpm/lodash@4.17.21/.../lodash    (whichever is most referenced)
packages/legacy-utils/node_modules/
  lodash/   -> root/.pnpm/lodash@3.10.1/.../lodash
```

**For oath**: the existing `Linker::build_plan` already handles this! It
picks the most-referenced version for hoisting and nests others. The workspace
extension must:
1. Treat each workspace package as a separate "root" with its own dep list
2. Feed ALL workspace deps into the single combined resolver
3. The hoisting plan operates on the combined graph

The combined graph for the above would have:
- `lodash@4.17.21` (referenced by web, count=1 or more)
- `lodash@3.10.1` (referenced by legacy-utils, count=1)
- Hoisted: lodash@4 (tie-break by root membership or first seen)
- Nested under legacy-utils: lodash@3

### 3.3 The `workspace:*` Protocol

`workspace:*` (pnpm-specific) means: "use whatever version is currently in the
workspace, exactly as-is (don't pin to a semver range)".

Variants:
- `workspace:*`  -- resolve to workspace package, use its current version as-is
- `workspace:^`  -- resolve to workspace package, replace with `^<version>` on publish
- `workspace:~`  -- resolve to workspace package, replace with `~<version>` on publish
- `workspace:1.2.3` -- explicit version, must match workspace package's version field

The `^` and `~` variants only matter at **publish time** (when `pnpm publish`
replaces them with real semver ranges in the published tarball). During
development/install, all `workspace:` variants behave the same: use the local
copy.

**Resolution algorithm for `workspace:*`:**
1. Detect specifier starts with `workspace:`
2. Strip prefix to get version hint (`*`, `^`, `~`, or a version)
3. Look up the workspace package by name in the workspace map
4. If found: this dep resolves to `WorkspaceDep { path: workspace_pkg_path }`
5. If NOT found: error -- cannot use `workspace:` for a non-workspace package
6. If version hint is a semver (not `*`/`^`/`~`): validate it matches the
   workspace package's `version` field, error if mismatch

For npm/yarn compatibility, `"@repo/ui": "*"` should also be checked against
workspace packages first. If a workspace package matches by name, prefer it
over the registry. This is what yarn classic does -- it intercepts `*` and
any semver range that matches the workspace version.

```rust
pub enum WorkspaceSpecifier {
    Any,                    // workspace:*
    Caret,                  // workspace:^  (publish-time transformation)
    Tilde,                  // workspace:~
    Exact(semver::Version), // workspace:1.2.3
}

pub struct WorkspaceDep {
    pub name: String,
    pub specifier: WorkspaceSpecifier,
    pub resolved_path: PathBuf,
    pub version: String,    // from workspace package's package.json
}
```

### 3.4 Filter/Run Commands

pnpm `--filter` is a rich selector syntax. The minimum viable subset for oath:

```
oath run build --filter web              # by package name
oath run build --filter @repo/ui         # scoped package name
oath run build --filter ./apps/web       # by path
oath run build --recursive               # all workspaces
oath run build --filter "web..."         # web + all packages that depend on web
```

Implementation requires the **workspace dependency graph** (which packages
depend on which other workspace packages). This is a `HashMap<PkgName, Vec<PkgName>>`.

For `"web..."` (dependents): reverse the edges and do a BFS from `web`.
For `"...web"` (dependencies): forward BFS from `web`.

Git-based filtering (`[HEAD~1]`) is Turborepo territory -- oath should not
need to implement this; Turborepo sits on top and calls `oath run` per package.

### 3.5 Parallel Script Execution

When `oath run build --recursive`, execution order must respect the workspace
dependency DAG to avoid building a package before its workspace deps are built.

**Topological sort** of the workspace graph:
1. Build adjacency list: `workspace_deps: HashMap<PkgName, Vec<PkgName>>`
2. Kahn's algorithm for topo sort
3. Execute packages at the same "level" in parallel (tokio::task or rayon)
4. Propagate failures: if `packages/ui` build fails, skip `apps/web` build

```rust
pub struct WorkspaceRunPlan {
    /// Packages in topological order (levels that can run in parallel)
    pub levels: Vec<Vec<WorkspacePackage>>,
}

impl WorkspaceRunPlan {
    pub fn from_graph(graph: &WorkspaceGraph, filter: &[PackageFilter]) -> Self { ... }
}
```

---

## 4. WHAT TOOLS ACTUALLY DO

### pnpm Implementation Details

pnpm's virtual store key for workspace packages uses `+` for `/` in scoped names:
- `@repo/ui@0.0.0` -> stored as `@repo+ui@0.0.0` in `.pnpm/`

The workspace package entry in `.pnpm` is a **symlink to the actual workspace
directory**, not a hardlink or copy:
```
.pnpm/@repo+ui@0.0.0/node_modules/@repo/ui  ->  ../../../../packages/ui
```

This means editing `packages/ui/src/Button.tsx` immediately takes effect for
`apps/web` -- no install needed after editing workspace source.

pnpm also writes `.modules.yaml` in each `node_modules` dir with metadata:
```yaml
hoistPattern:
  - '*'
hoistedDependencies:
  react: public
  react-dom: public
included:
  dependencies: true
  devDependencies: true
  optionalDependencies: true
layoutVersion: 5
nodeLinker: isolated
packageManager: pnpm@9.0.0
pendingBuilds: []
publicHoistPattern:
  - '*eslint*'
  - '*prettier*'
registries:
  default: https://registry.npmjs.org/
skipped: []
storeDir: /Users/user/.pnpm-store/v3
virtualStoreDir: .pnpm
workspaceSymlinks:
  - packages/ui
  - packages/eslint-config
```

### npm Workspaces Implementation

npm uses arborist (the dependency tree manager). For workspaces:
1. `mapWorkspaces()` called first to find all workspace packages
2. Each workspace package added as a virtual "node" in the arborist tree
3. During `reify` (install), workspace nodes get symlinked at `root/node_modules/<name>`
4. The symlink is a **relative symlink** from `node_modules/<name>` to `../packages/name`
5. External deps are flat-hoisted: deduped at root, nested only on conflict

npm does NOT use a virtual store -- there's no `.npm/` hidden dir. The workspace
package's `node_modules` is only created for its nested conflicts.

### Turborepo: What It Does and Doesn't Do

Turborepo is a **build orchestration layer**, not a package installer.

What Turborepo does:
- Reads `turbo.json` to define task pipelines and dependencies
- Wraps the underlying package manager (`npm run`, `pnpm run`, etc.)
- Provides caching of build artifacts (local + remote)
- Understands the workspace graph for affected-package detection
- Handles topological ordering of tasks across packages
- Provides `--filter` with git-diff awareness

What Turborepo does NOT do:
- Install packages (delegates entirely to npm/pnpm/yarn)
- Manage `node_modules` layout
- Resolve semver ranges

For oath: Turborepo should work on top of oath unchanged if oath correctly:
1. Implements the pnpm workspace protocol (pnpm-workspace.yaml)
2. Supports `oath run <script> --filter <pattern>` 
3. Writes a compatible lockfile that Turborepo can hash

---

## 5. IMPLEMENTATION PLAN FOR OATH

### Step 1: Detect Workspace Root

```rust
pub struct WorkspaceRoot {
    pub path: PathBuf,
    pub source: WorkspaceSource,
}

pub enum WorkspaceSource {
    PnpmWorkspaceYaml(PathBuf),   // pnpm-workspace.yaml
    PackageJsonWorkspaces(PathBuf), // package.json "workspaces" field
}

pub fn find_workspace_root(start: &Path) -> Option<WorkspaceRoot> {
    let mut current = start.to_path_buf();
    loop {
        // Check for pnpm-workspace.yaml first (pnpm wins)
        let pnpm_ws = current.join("pnpm-workspace.yaml");
        if pnpm_ws.exists() {
            return Some(WorkspaceRoot {
                path: current,
                source: WorkspaceSource::PnpmWorkspaceYaml(pnpm_ws),
            });
        }
        // Check package.json with workspaces field
        let pkg_json = current.join("package.json");
        if pkg_json.exists() {
            if let Ok(content) = std::fs::read_to_string(&pkg_json) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if v.get("workspaces").is_some() {
                        return Some(WorkspaceRoot {
                            path: current,
                            source: WorkspaceSource::PackageJsonWorkspaces(pkg_json),
                        });
                    }
                }
            }
        }
        // Traverse up
        if !current.pop() {
            return None;
        }
    }
}
```

### Step 2: Glob-Expand All Workspace Package Paths

Add `glob` crate (or use `globset`). Parse workspace patterns and expand:

```rust
#[derive(Debug, Deserialize)]
pub struct PnpmWorkspaceYaml {
    pub packages: Vec<String>,
}

pub fn expand_workspace_packages(root: &Path, patterns: &[String]) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let (positive, negative): (Vec<_>, Vec<_>) = patterns
        .iter()
        .partition(|p| !p.starts_with('!'));
    
    for pattern in &positive {
        // glob::glob relative to root
        let full_pattern = root.join(pattern).join("package.json");
        if let Ok(entries) = glob::glob(&full_pattern.to_string_lossy()) {
            for entry in entries.flatten() {
                let pkg_dir = entry.parent().unwrap().to_path_buf();
                // Check not excluded
                let rel = pkg_dir.strip_prefix(root).unwrap_or(&pkg_dir);
                let excluded = negative.iter().any(|neg| {
                    let neg_pattern = neg.trim_start_matches('!');
                    glob::Pattern::new(neg_pattern)
                        .map(|p| p.matches(&rel.to_string_lossy()))
                        .unwrap_or(false)
                });
                if !excluded {
                    results.push(pkg_dir);
                }
            }
        }
    }
    results
}
```

### Step 3: Build the Workspace Graph

```rust
/// A single package in the workspace
#[derive(Debug, Clone)]
pub struct WorkspacePackage {
    pub name: String,
    pub version: String,
    pub path: PathBuf,               // absolute path to package dir
    pub dependencies: HashMap<String, String>,     // raw spec strings
    pub dev_dependencies: HashMap<String, String>,
    pub peer_dependencies: HashMap<String, String>,
    pub scripts: HashMap<String, String>,
    pub private: bool,
}

/// The workspace graph: all packages + their inter-dependencies
#[derive(Debug)]
pub struct WorkspaceGraph {
    /// All workspace packages, indexed by name
    pub packages: HashMap<String, WorkspacePackage>,
    /// Directed edges: pkg_name -> [workspace_dep_names]
    /// (only workspace-to-workspace edges, not external deps)
    pub workspace_edges: HashMap<String, Vec<String>>,
    /// Root workspace package (the monorepo root itself, may be None if root has no name)
    pub root: Option<String>,
    /// Absolute path to workspace root directory
    pub root_path: PathBuf,
}

impl WorkspaceGraph {
    pub fn load(root: &WorkspaceRoot) -> Result<Self> {
        let patterns = match &root.source {
            WorkspaceSource::PnpmWorkspaceYaml(path) => {
                let content = std::fs::read_to_string(path)?;
                let yaml: PnpmWorkspaceYaml = serde_yaml::from_str(&content)?;
                yaml.packages
            }
            WorkspaceSource::PackageJsonWorkspaces(path) => {
                let content = std::fs::read_to_string(path)?;
                let v: serde_json::Value = serde_json::from_str(&content)?;
                extract_workspace_patterns(&v)?
            }
        };
        
        let pkg_paths = expand_workspace_packages(&root.path, &patterns);
        let mut packages = HashMap::new();
        
        for pkg_path in pkg_paths {
            let pkg = WorkspacePackage::load(&pkg_path)?;
            packages.insert(pkg.name.clone(), pkg);
        }
        
        // Build inter-package edges
        let pkg_names: HashSet<String> = packages.keys().cloned().collect();
        let mut workspace_edges: HashMap<String, Vec<String>> = HashMap::new();
        
        for (name, pkg) in &packages {
            let edges: Vec<String> = pkg.dependencies.keys()
                .chain(pkg.dev_dependencies.keys())
                .filter(|dep_name| pkg_names.contains(*dep_name))
                .cloned()
                .collect();
            workspace_edges.insert(name.clone(), edges);
        }
        
        Ok(WorkspaceGraph { packages, workspace_edges, root: None, root_path: root.path.clone() })
    }
    
    /// Topological sort of workspace packages (Kahn's algorithm)
    /// Returns Vec of levels, each level can run in parallel
    pub fn topo_levels(&self) -> Result<Vec<Vec<String>>, String> {
        // in-degree counting
        let mut in_degree: HashMap<&str, usize> = self.packages.keys()
            .map(|k| (k.as_str(), 0))
            .collect();
        
        for (_, edges) in &self.workspace_edges {
            for dep in edges {
                *in_degree.entry(dep.as_str()).or_insert(0) += 1;
            }
        }
        
        let mut queue: Vec<&str> = in_degree.iter()
            .filter(|(_, &d)| d == 0)
            .map(|(k, _)| *k)
            .collect();
        
        let mut levels = Vec::new();
        let mut total = 0;
        
        while !queue.is_empty() {
            levels.push(queue.iter().map(|s| s.to_string()).collect());
            total += queue.len();
            let mut next_queue = Vec::new();
            for node in &queue {
                if let Some(edges) = self.workspace_edges.get(*node) {
                    for dep in edges {
                        let d = in_degree.get_mut(dep.as_str()).unwrap();
                        *d -= 1;
                        if *d == 0 {
                            next_queue.push(dep.as_str());
                        }
                    }
                }
            }
            queue = next_queue;
        }
        
        if total != self.packages.len() {
            return Err("circular dependency detected in workspace packages".to_string());
        }
        Ok(levels)
    }
    
    /// Get all packages that a given package depends on (transitively)
    pub fn transitive_deps(&self, pkg_name: &str) -> HashSet<String> { ... }
    
    /// Get all packages that depend on a given package (reverse transitive)
    pub fn transitive_dependents(&self, pkg_name: &str) -> HashSet<String> { ... }
}
```

### Step 4: Modify the Resolver for Workspace Deps

The key change: when resolving dependencies, intercept any dep whose name
matches a workspace package OR whose spec starts with `workspace:`.

```rust
pub struct WorkspaceResolver<'a> {
    workspace: &'a WorkspaceGraph,
    registry_resolver: Resolver,
}

impl<'a> WorkspaceResolver<'a> {
    /// Resolve a single dependency specifier in workspace context
    pub fn classify_dep(&self, name: &str, spec: &str) -> DepClassification {
        // 1. workspace: protocol -- explicit local
        if spec.starts_with("workspace:") {
            let ws_spec = parse_workspace_specifier(spec);
            if let Some(pkg) = self.workspace.packages.get(name) {
                return DepClassification::Workspace {
                    path: pkg.path.clone(),
                    version: pkg.version.clone(),
                    specifier: ws_spec,
                };
            }
            // workspace: but package not found -- hard error
            return DepClassification::Error(format!(
                "workspace:{spec} but '{name}' is not a workspace package"
            ));
        }
        
        // 2. Name matches a workspace package and semver matches -- prefer local
        if let Some(ws_pkg) = self.workspace.packages.get(name) {
            // Check if spec satisfies workspace version (for "*", "^", semver range)
            if spec == "*" || semver_matches(spec, &ws_pkg.version) {
                return DepClassification::Workspace {
                    path: ws_pkg.path.clone(),
                    version: ws_pkg.version.clone(),
                    specifier: WorkspaceSpecifier::Any,
                };
            }
        }
        
        // 3. Registry dep
        DepClassification::Registry { name: name.to_string(), spec: spec.to_string() }
    }
}

pub enum DepClassification {
    Workspace { path: PathBuf, version: String, specifier: WorkspaceSpecifier },
    Registry { name: String, spec: String },
    Error(String),
}
```

### Step 5: Combined Resolution and Linking

For a workspace install, oath needs to:

1. Collect ALL external deps from ALL workspace packages into one combined BFS
2. Resolve them with the existing registry BFS resolver
3. Track which workspace packages need which external deps
4. Build a `WorkspaceLinkPlan` that knows where to symlink everything

```rust
pub struct WorkspaceLinkPlan {
    /// External deps resolved for the whole monorepo
    pub combined_graph: DepGraph,
    
    /// Per-workspace-package: which external deps are direct deps
    /// Used to create per-package node_modules symlinks in strict mode
    pub per_package_direct_deps: HashMap<String, HashSet<String>>, // pkg_name -> dep keys
    
    /// Workspace packages to symlink at root node_modules
    pub workspace_symlinks: Vec<WorkspaceSymlink>,
    
    /// Root path
    pub root: PathBuf,
}

pub struct WorkspaceSymlink {
    pub name: String,      // "@repo/ui"
    pub source: PathBuf,   // /Users/.../packages/ui  (the actual workspace dir)
    pub version: String,
}
```

**Link execution:**

```
root/node_modules/
  .oath/                                     <- virtual store for external deps
    react@19.2.0/node_modules/react/         <- hardlinked from ~/.oath/store
    next@16.2.0/node_modules/next/           <- hardlinked from ~/.oath/store
  .oath-workspace/                           <- NEW: workspace package stubs
    @repo+ui@0.0.0/node_modules/@repo/ui/    <- SYMLINK -> ../../../packages/ui
    @repo+eslint-config@0.0.0/.../           <- SYMLINK -> ../../../packages/eslint-config
  react/   -> .oath/react@19.2.0/node_modules/react
  @repo/
    ui/    -> .oath-workspace/@repo+ui@0.0.0/node_modules/@repo/ui
apps/
  web/
    node_modules/       <- created in STRICT mode
      react/            -> ../../node_modules/react  (shared from root)
      @repo/ui/         -> ../../node_modules/@repo/ui
packages/
  ui/
    node_modules/
      react/            -> ../../node_modules/react
```

### Minimum Viable React + Shared Component Library Support

**Target monorepo structure:**
```
my-app/
  pnpm-workspace.yaml   (or package.json workspaces field)
  package.json          (root: private: true, devDeps only)
  apps/
    web/
      package.json      (name: "web", deps: @myorg/ui, react, next)
  packages/
    ui/
      package.json      (name: "@myorg/ui", deps: react)
```

**Minimum feature set needed:**
1. Detect workspace root (pnpm-workspace.yaml OR package.json.workspaces)
2. Glob-expand workspace packages
3. Resolve `workspace:*` and `"*"` to local packages
4. Single combined external dep resolution (no per-package isolation initially)
5. Root-level node_modules with hoisted externals
6. Symlinks for workspace packages at `node_modules/@myorg/ui -> ../../packages/ui`
7. NO per-workspace node_modules yet (use hoisted mode initially)

**NOT required for MVP:**
- Strict per-package isolation (each workspace gets its own node_modules)
- `--filter` selector syntax
- Parallel script execution with topo ordering
- `pnpm publish` workspace protocol rewriting (`workspace:^` -> `^1.2.3`)
- Catalog protocol (`catalog:default`)

### Configuration File Format

**Recommendation: support pnpm-workspace.yaml natively** (it's the industry
direction; Next.js, Turborepo, pnpm itself all use it).

For oath-specific workspace config, add an optional `oath` section to
`pnpm-workspace.yaml` (it's YAML, not strict schema):

```yaml
# pnpm-workspace.yaml (fully compatible with pnpm)
packages:
  - "apps/*"
  - "packages/*"

# oath-specific extensions (ignored by pnpm)
oath:
  hoist_mode: strict     # strict (default) | hoisted
  shared_deps:           # always hoist these to root regardless
    - react
    - react-dom
  script_concurrency: 4  # max parallel script jobs
```

Also continue supporting `package.json` `workspaces` field for npm/yarn compat.

oath's workspace detection priority:
1. `pnpm-workspace.yaml` (pnpm native)
2. `package.json` `workspaces` field (npm/yarn compat)

### Extended `PackageManifest` Changes in `oath-core`

Add `workspaces` field to `PackageManifest`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    // ... existing fields ...
    
    /// Workspace patterns (npm/yarn style, root package.json only)
    #[serde(default)]
    pub workspaces: Option<WorkspacesField>,
    
    /// private: true (required for workspace roots)
    #[serde(default)]
    pub private: bool,
    
    /// packageManager field (e.g. "pnpm@9.0.0")
    #[serde(rename = "packageManager", default)]
    pub package_manager: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkspacesField {
    /// Simple array: ["apps/*", "packages/*"]
    Patterns(Vec<String>),
    /// Object form: { "packages": ["apps/*"] }  (legacy yarn)
    Object { packages: Vec<String> },
}

impl WorkspacesField {
    pub fn patterns(&self) -> &[String] {
        match self {
            Self::Patterns(p) => p,
            Self::Object { packages } => packages,
        }
    }
}
```

### New Crate: `oath-workspace`

Create `crates/oath-workspace/` with:

```
oath-workspace/
  src/
    lib.rs          - pub re-exports
    detect.rs       - find_workspace_root()
    graph.rs        - WorkspaceGraph, WorkspacePackage
    resolver.rs     - WorkspaceResolver wrapping Resolver
    linker.rs       - WorkspaceLinkPlan, workspace-aware link_all()
    filter.rs       - PackageFilter, filter_packages()
    runner.rs       - parallel script execution with topo ordering
  Cargo.toml
```

**Cargo.toml dependencies:**
```toml
[dependencies]
oath-core = { path = "../oath-core" }
oath-resolve = { path = "../oath-resolve" }
oath-store = { path = "../oath-store" }
oath-fetch = { path = "../oath-fetch" }
glob = "0.3"
globset = "0.4"
serde_yaml = "0.9"
semver = "1.0"
tokio = { version = "1", features = ["full"] }
```

### CLI Changes in `oath-cli`

Add workspace-aware commands:

```rust
enum Commands {
    // Existing:
    Install { ... },
    Run { script: String, args: Vec<String> },
    
    // New workspace subcommand:
    Workspace {
        #[command(subcommand)]
        cmd: WorkspaceCommands,
    },
}

enum WorkspaceCommands {
    /// List all workspace packages
    List,
    /// Run a script across workspace packages
    Run {
        script: String,
        #[arg(long, short = 'F')]
        filter: Vec<String>,
        #[arg(long, short = 'r')]
        recursive: bool,
        #[arg(long)]
        parallel: bool,
    },
    /// Install deps across all workspace packages
    Install {
        #[arg(long)]
        frozen_lockfile: bool,
    },
}
```

Also modify `Commands::Install` to detect workspace root automatically -- if
`oath install` is run from any subdirectory of a workspace, it should either:
a) walk up to the workspace root and install everything (pnpm behavior), or
b) install only the current package's deps using the root's lockfile

**Recommended**: always install from workspace root when detected (pnpm behavior).

---

## 6. COMPLETE WORKSPACE GRAPH + RESOLVER RUST STRUCTS

```rust
// crates/oath-workspace/src/graph.rs

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePackage {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub dependencies: HashMap<String, String>,
    pub dev_dependencies: HashMap<String, String>,
    pub peer_dependencies: HashMap<String, String>,
    pub scripts: HashMap<String, String>,
    pub private: bool,
}

#[derive(Debug)]
pub struct WorkspaceGraph {
    pub packages: HashMap<String, WorkspacePackage>,
    /// workspace-to-workspace edges only (external deps excluded)
    /// key: dependent, value: [workspace deps it depends on]
    pub edges: HashMap<String, Vec<String>>,
    pub root_path: PathBuf,
}

impl WorkspaceGraph {
    /// Topological sort using Kahn's algorithm
    /// Returns levels: packages in each level can execute in parallel
    pub fn topo_levels(&self) -> Result<Vec<Vec<String>>, String> {
        // reverse edges: for each pkg, how many workspace deps does it have?
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for name in self.packages.keys() {
            in_degree.insert(name, 0);
        }
        for (_, deps) in &self.edges {
            for dep in deps {
                *in_degree.entry(dep).or_insert(0) += 1;
            }
        }
        
        let mut queue: VecDeque<&str> = in_degree.iter()
            .filter(|(_, &d)| d == 0)
            .map(|(k, _)| *k)
            .collect();
        
        let mut levels: Vec<Vec<String>> = Vec::new();
        let mut processed = 0;
        
        while !queue.is_empty() {
            let level_size = queue.len();
            let level: Vec<String> = queue.drain(..level_size).map(|s| s.to_string()).collect();
            
            for name in &level {
                processed += 1;
                if let Some(deps) = self.edges.get(name.as_str()) {
                    for dep in deps {
                        if let Some(d) = in_degree.get_mut(dep.as_str()) {
                            *d -= 1;
                            if *d == 0 {
                                queue.push_back(dep);
                            }
                        }
                    }
                }
            }
            levels.push(level);
        }
        
        if processed != self.packages.len() {
            Err("circular workspace dependency detected".to_string())
        } else {
            Ok(levels)
        }
    }
    
    /// BFS: all transitive workspace deps of `pkg`
    pub fn deps_of(&self, pkg: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(pkg.to_string());
        while let Some(current) = queue.pop_front() {
            if let Some(deps) = self.edges.get(&current) {
                for dep in deps {
                    if visited.insert(dep.clone()) {
                        queue.push_back(dep.clone());
                    }
                }
            }
        }
        visited.remove(pkg);
        visited
    }
    
    /// BFS on reversed edges: all packages that (transitively) depend on `pkg`
    pub fn dependents_of(&self, pkg: &str) -> HashSet<String> {
        // Build reverse edges first
        let mut rev: HashMap<&str, Vec<&str>> = HashMap::new();
        for (name, deps) in &self.edges {
            for dep in deps {
                rev.entry(dep).or_default().push(name);
            }
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(pkg);
        while let Some(current) = queue.pop_front() {
            if let Some(dependents) = rev.get(current) {
                for &dep in dependents {
                    if visited.insert(dep.to_string()) {
                        queue.push_back(dep);
                    }
                }
            }
        }
        visited.remove(pkg);
        visited
    }
    
    /// Collect ALL external (non-workspace) deps across all packages
    /// Returns combined HashMap<name, spec> -- last write wins for same-name deps
    /// NOTE: for version conflicts, returns ALL unique (name, spec) pairs
    pub fn all_external_deps(&self) -> Vec<(String, String, bool)> {
        // (name, spec, is_dev)
        let ws_names: HashSet<&str> = self.packages.keys().map(|s| s.as_str()).collect();
        let mut deps = Vec::new();
        
        for pkg in self.packages.values() {
            for (name, spec) in &pkg.dependencies {
                if !ws_names.contains(name.as_str()) && !spec.starts_with("workspace:") {
                    deps.push((name.clone(), spec.clone(), false));
                }
            }
            for (name, spec) in &pkg.dev_dependencies {
                if !ws_names.contains(name.as_str()) && !spec.starts_with("workspace:") {
                    deps.push((name.clone(), spec.clone(), true));
                }
            }
        }
        deps
    }
}

// crates/oath-workspace/src/filter.rs

pub enum PackageFilter {
    Name(String),           // exact package name
    Path(String),           // relative path pattern
    WithDeps(String),       // "...pkg" -- pkg and all its workspace deps
    WithDependents(String), // "pkg..." -- pkg and all packages depending on it
    All,                    // no filter = all packages
}

impl PackageFilter {
    pub fn parse(s: &str) -> Self {
        if s == "*" || s.is_empty() {
            return Self::All;
        }
        if s.starts_with("...") {
            return Self::WithDeps(s[3..].to_string());
        }
        if s.ends_with("...") {
            return Self::WithDependents(s[..s.len()-3].to_string());
        }
        if s.starts_with("./") || s.starts_with('/') {
            return Self::Path(s.to_string());
        }
        Self::Name(s.to_string())
    }
    
    pub fn matches(&self, pkg: &WorkspacePackage, graph: &WorkspaceGraph) -> bool {
        match self {
            Self::All => true,
            Self::Name(n) => &pkg.name == n,
            Self::Path(p) => {
                let rel = pkg.path.strip_prefix(&graph.root_path)
                    .unwrap_or(&pkg.path);
                glob::Pattern::new(p)
                    .map(|pat| pat.matches(&rel.to_string_lossy()))
                    .unwrap_or(false)
            }
            Self::WithDeps(name) => {
                &pkg.name == name || graph.deps_of(name).contains(&pkg.name)
            }
            Self::WithDependents(name) => {
                &pkg.name == name || graph.dependents_of(name).contains(&pkg.name)
            }
        }
    }
}
```

---

## 7. LOCKFILE CHANGES FOR WORKSPACES

The current `oath-lock.json` is per-package. For workspaces, it must become
a **root-level lockfile** covering all workspace packages.

Add a `workspaces` section:

```json
{
  "lockfileVersion": 2,
  "workspaces": {
    "apps/web": {
      "name": "web",
      "version": "0.1.0",
      "dependencies": {
        "@repo/ui": "workspace:*",
        "react": "^19.2.0"
      }
    },
    "packages/ui": {
      "name": "@repo/ui",
      "version": "0.0.0",
      "dependencies": {
        "react": "^19.2.0"
      }
    }
  },
  "packages": {
    "react@19.2.0": {
      "version": "19.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
      "integrity": "sha512-...",
      "dependencies": {}
    }
  }
}
```

This mirrors pnpm's `pnpm-lock.yaml` structure where `importers` captures
per-workspace-package dep declarations and `packages` captures resolved
registry packages.

---

## 8. IMPLEMENTATION SEQUENCE (ORDERED BY DEPENDENCY)

1. **oath-core**: Add `workspaces: Option<WorkspacesField>` + `private: bool` to `PackageManifest`
2. **oath-workspace crate**: Create skeleton with `detect.rs`, `graph.rs`
3. **oath-workspace/detect**: `find_workspace_root()` traversal
4. **oath-workspace/graph**: `WorkspaceGraph::load()`, glob expansion (add `glob` crate)
5. **oath-workspace/resolver**: `WorkspaceResolver` wrapping existing `Resolver`
6. **oath-resolve/lockfile**: Extend `Lockfile` to include workspace section
7. **oath-store/linker**: Extend `Linker::link_all()` to accept `Option<&WorkspaceGraph>`
8. **oath-cli**: Add workspace detection in `cmd_install`, add `oath workspace run`
9. **Testing**: Create test fixture monorepo under `tests/fixtures/monorepo-basic/`

Total estimated new code: ~1500-2000 lines across 6-8 new files.
The existing `Resolver` and `Linker` need minimal changes -- the workspace
layer is primarily additive.
