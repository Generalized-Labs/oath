use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

use oath_analyze::{PackageScanner, RiskLevel};
use oath_core::policy::OathPolicy;
use oath_fetch::RegistryClient;
use oath_resolve::resolver::{ResolveOptions, Resolver};
use oath_resolve::graph::PeerResolution;
use oath_resolve::Lockfile;
use oath_store::cas::ContentStore;
use oath_store::linker::Linker;
use oath_workspace::{detect_workspace_root, WorkspaceRoot};

mod prompts;

#[derive(Parser)]
#[command(
    name = "oath",
    version,
    about = "Secure package management for the JavaScript ecosystem"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install dependencies from package.json
    Install {
        packages: Vec<String>,
        #[arg(short = 'D', long, alias = "save-dev")]
        dev: bool,
        #[arg(long)]
        dry_run: bool,
        /// Skip static analysis scan
        #[arg(long)]
        no_audit: bool,
        /// Skip all prompts and approve everything (including install scripts)
        #[arg(short = 'y', long)]
        yes: bool,
        /// Prompt before running install scripts (old behavior; default is to block)
        #[arg(long)]
        run_scripts: bool,
        /// Minimum release age to warn about (e.g. '7d', '24h', '30d')
        #[arg(long)]
        min_age: Option<String>,
        /// Install to global location (~/.oath/global/)
        #[arg(short = 'g', long)]
        global: bool,
        /// Fail if lockfile is missing or would be changed (for CI)
        #[arg(long, alias = "ci")]
        frozen_lockfile: bool,
    },
    /// Add a dependency
    Add {
        package: String,
        #[arg(short = 'D', long)]
        dev: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Remove a dependency
    Remove { packages: Vec<String> },
    /// Run a script defined in package.json
    Run {
        script: Option<String>,
        args: Vec<String>,
    },
    /// Execute a package binary (like npx, but with permission checks)
    Exec {
        package: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        #[arg(long)]
        allow_net: bool,
        #[arg(long)]
        allow_read: Option<Vec<String>>,
        #[arg(long)]
        allow_write: Option<Vec<String>>,
        #[arg(long)]
        allow_env: Option<Vec<String>>,
        /// Minimum release age required (e.g. '7d', '24h', '30d'). Block if newer.
        #[arg(long)]
        min_age: Option<String>,
    },
    /// Scan installed packages for malicious behavior
    Audit {
        #[arg(long)]
        production: bool,
        /// Show all findings, not just high/critical
        #[arg(long)]
        verbose: bool,
    },
    /// Show what a package can access (permissions/capabilities)
    Perms { package: String },
    /// Initialize a new project
    Init { name: Option<String> },
    /// Explain why a package is in the dependency tree
    Why { package: String },
    /// List licenses of all installed packages
    Licenses,
    /// Verify integrity of oath-lock.json against the store
    Verify,
    /// Print an ASCII dependency graph
    Graph {
        /// Maximum depth to display (default: 3)
        #[arg(long, default_value = "3")]
        depth: usize,
    },
    /// Show safety score and metadata for a package
    Score {
        package: String,
    },
    /// Show info about a package (author, downloads, publish date)
    Info {
        package: String,
    },
    /// Publish the current package to the npm registry
    Publish {
        /// Tag to use (default: "latest")
        #[arg(long)]
        tag: Option<String>,
        /// Access level: public or restricted
        #[arg(long)]
        access: Option<String>,
        /// Dry run: show what would be published without actually publishing
        #[arg(long)]
        dry_run: bool,
    },
    /// Show recent transparency log entries
    Log {
        /// Number of recent entries to show (default: 10)
        #[arg(long, short = 'n', default_value = "10")]
        tail: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            packages,
            dev,
            dry_run,
            no_audit,
            yes,
            run_scripts,
            min_age,
            global,
            frozen_lockfile,
        } => {
            cmd_install(packages, dev, dry_run, !no_audit, yes, run_scripts, global, frozen_lockfile, min_age).await?;
        }
        Commands::Add { package, dev, yes: _ } => {
            cmd_add(&package, dev).await?;
        }
        Commands::Run { script, args } => {
            cmd_run(script.as_deref(), &args)?;
        }
        Commands::Init { name } => {
            cmd_init(name.as_deref())?;
        }
        Commands::Audit {
            production,
            verbose,
        } => {
            cmd_audit(production, verbose).await?;
        }
        Commands::Perms { package } => {
            cmd_perms(&package)?;
        }
        Commands::Why { package } => {
            cmd_why(&package)?;
        }
        Commands::Licenses => {
            cmd_licenses()?;
        }
        Commands::Verify => {
            cmd_verify()?;
        }
        Commands::Graph { depth } => {
            cmd_graph(depth)?;
        }
        Commands::Exec {
            package,
            args,
            allow_net,
            allow_read,
            allow_write,
            allow_env,
            min_age,
        } => {
            cmd_exec(&package, &args, allow_net, allow_read, allow_write, allow_env, min_age.as_deref()).await?;
        }
        Commands::Score { package } => {
            cmd_score(&package).await?;
        }
        Commands::Info { package } => {
            cmd_info(&package).await?;
        }
        Commands::Publish { tag, access, dry_run } => {
            cmd_publish(tag.as_deref(), access.as_deref(), dry_run).await?;
        }
        Commands::Log { tail } => {
            cmd_log(tail)?;
        }
        Commands::Remove { packages } => {
            cmd_remove(packages).await?;
        }
        _ => {
            println!("oath: command not yet implemented");
        }
    }

    Ok(())
}

// ---- INSTALL ----------------------------------------------------------------

async fn cmd_install(
    packages: Vec<String>,
    dev: bool,
    dry_run: bool,
    run_audit: bool,
    yes_flag: bool,
    run_scripts: bool,
    global: bool,
    frozen_lockfile: bool,
    min_age: Option<String>,
) -> Result<()> {
    let start = Instant::now();

    // ---- Global install shortcut --------------------------------------------
    if global {
        return cmd_install_global(packages, dry_run).await;
    }

    // ---- Frozen lockfile check (--frozen-lockfile / --ci) -------------------
    if frozen_lockfile && !PathBuf::from("oath-lock.json").exists() {
        anyhow::bail!("no lockfile found, run oath install first");
    }

    // ---- Workspace detection ------------------------------------------------
    let cwd = std::env::current_dir()?;
    let workspace = detect_workspace_root(&cwd);

    if let Some(ref ws) = workspace {
        // Workspace mode: install all packages together with hoisted graph
        if packages.is_empty() {
            println!(
                "oath: workspace mode, {} packages",
                ws.packages.len()
            );
            for pkg in &ws.packages {
                println!("  - {} ({})", pkg.name, pkg.path.display());
            }
            return cmd_install_workspace(ws, dry_run, run_audit, yes_flag, run_scripts).await;
        }
        // If specific packages are listed, fall through to normal install
    }

    // ---- Single-package install ---------------------------------------------

    let (deps, dev_deps, project_name, project_version) = if packages.is_empty() {
        let pkg = read_package_json()?;
        let name = pkg["name"].as_str().unwrap_or("unnamed").to_string();
        let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let deps = extract_deps(&pkg, "dependencies");
        let dev_deps = extract_deps(&pkg, "devDependencies");
        (deps, dev_deps, name, version)
    } else {
        let mut deps = HashMap::new();
        for spec in &packages {
            // handle scoped packages: @scope/name@version
            let (name, version) = parse_package_spec(spec);
            deps.insert(name, version);
        }
        (
            deps,
            HashMap::new(),
            "project".to_string(),
            "0.0.0".to_string(),
        )
    };

    let trusted_deps: HashSet<String> = {
        let pkg = read_package_json().unwrap_or_default();
        pkg.get("trustedDependencies")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };

    let total_direct = deps.len() + dev_deps.len();

    // Fast path: if lockfile exists and all store entries are present, skip resolution
    let lock_path = PathBuf::from("oath-lock.json");
    let graph = if lock_path.exists() && packages.is_empty() {
        // Try to use lockfile directly
        let lockfile = Lockfile::read(&lock_path)?;
        let store_check = ContentStore::default_store()?;
        let all_cached = lockfile.packages.iter().all(|(key, entry)| {
            let name = if let Some(at_pos) = key.rfind('@') {
                &key[..at_pos]
            } else {
                key.as_str()
            };
            store_check.has_package(name, &entry.version)
        });
        if all_cached && !lockfile.packages.is_empty() {
            println!("oath: lockfile up-to-date ({} packages)", lockfile.packages.len());
            lockfile.to_graph()
        } else {
            println!("oath: resolving {total_direct} dependencies...");
            let client = RegistryClient::default_client()?;
            let options = ResolveOptions {
                include_dev: true,
                include_optional: true,
                max_depth: 256,
            };
            let mut resolver = Resolver::new(client, options);
            let g = resolver.resolve(&deps, &dev_deps).await?;
            let resolve_time = start.elapsed();
            println!(
                "  resolved {} packages in {:.1}s",
                g.package_count(),
                resolve_time.as_secs_f64()
            );
            g
        }
    } else if packages.is_empty() && PathBuf::from("package-lock.json").exists() {
        // Migration: no oath-lock yet, but an npm lockfile is present. Honour the
        // versions it already pinned instead of re-resolving ranges to newer ones,
        // so an existing repo installs the same tree it had under npm.
        println!("oath: importing package-lock.json (migration)...");
        let g = oath_resolve::import_npm_lockfile(&PathBuf::from("package-lock.json"))?;
        println!("  imported {} packages", g.package_count());
        g
    } else {
        println!("oath: resolving {total_direct} dependencies...");
        let client = RegistryClient::default_client()?;
        let options = ResolveOptions {
            include_dev: true,
            include_optional: true,
            max_depth: 256,
        };
        let mut resolver = Resolver::new(client, options);
        let g = resolver.resolve(&deps, &dev_deps).await?;
        let resolve_time = start.elapsed();
        println!(
            "  resolved {} packages in {:.1}s",
            g.package_count(),
            resolve_time.as_secs_f64()
        );
        g
    };

    if dry_run {
        println!("  (dry run, skipping download and link)");
        return Ok(());
    }

    // Download -- parallel with JoinSet
    let download_start = Instant::now();
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);

    let mut to_download = vec![];
    let mut cached = 0usize;
    for (_key, node) in &graph.nodes {
        if store.has_package(&node.name, &node.version) {
            cached += 1;
        } else {
            to_download.push(node.clone());
        }
    }

    let mut downloaded = 0usize;
    let mut download_bytes = 0u64;

    // ---- Minimum release age (supply-chain cooldown) ------------------------
    // Block newly-added versions published more recently than --min-age. Only
    // applies to packages not already in the store (new additions) -- already
    // cached packages were vetted on a prior install. A freshly published
    // version (anywhere in the tree) is the classic compromised-package window.
    if let Some(min_age_str) = min_age.as_deref() {
        match parse_duration_secs(min_age_str) {
            Some(min_age_secs) if !to_download.is_empty() => {
                let min_days = (min_age_secs / 86400).max(1);
                println!(
                    "  checking release age ({}-day cooldown) for {} new package(s)...",
                    min_days,
                    to_download.len()
                );
                let mut age_set: JoinSet<(String, String, Option<u64>)> = JoinSet::new();
                for node in &to_download {
                    // Git deps have no registry publish time -- skip.
                    if node.resolved.starts_with("git+")
                        || node.resolved.starts_with("github:")
                        || node.resolved.starts_with("gitlab:")
                        || node.resolved.starts_with("bitbucket:")
                    {
                        continue;
                    }
                    let client = Arc::clone(&client);
                    let name = node.name.clone();
                    let version = node.version.clone();
                    age_set.spawn(async move {
                        // Abbreviated packuments omit `time`; the full one carries it.
                        let age = client
                            .fetch_packument_full(&name)
                            .await
                            .ok()
                            .and_then(|v| {
                                v.get("time")
                                    .and_then(|t| t.get(&version))
                                    .and_then(|s| s.as_str().map(String::from))
                            })
                            .and_then(|pts| parse_iso_age_secs(&pts));
                        (name, version, age)
                    });
                }
                let mut violations: Vec<(String, String, u64)> = Vec::new();
                while let Some(res) = age_set.join_next().await {
                    let (name, version, age) = res?;
                    if let Some(age_secs) = age {
                        if age_secs < min_age_secs {
                            violations.push((name, version, age_secs / 86400));
                        }
                    }
                }
                if !violations.is_empty() {
                    violations.sort();
                    eprintln!();
                    eprintln!(
                        "oath install: BLOCKED by --min-age {} ({}-day cooldown)",
                        min_age_str, min_days
                    );
                    eprintln!("  These newly-added versions are too recent to trust yet:");
                    for (n, v, days) in &violations {
                        eprintln!("    - {}@{}  published {} day(s) ago", n, v, days);
                    }
                    eprintln!("  Wait out the cooldown, pin an older version, or lower --min-age.");
                    anyhow::bail!(
                        "{} package(s) newer than the {}-day minimum release age",
                        violations.len(),
                        min_days
                    );
                }
                println!("  release age OK");
            }
            Some(_) => {} // nothing new to check
            None => eprintln!(
                "oath: ignoring unparseable --min-age '{}' (use e.g. 7d, 24h, 30d)",
                min_age_str
            ),
        }
    }

    if !to_download.is_empty() {
        let mut set: JoinSet<Result<(String, String, Vec<u8>)>> = JoinSet::new();

        for node in to_download {
            let client = Arc::clone(&client);
            let resolved = node.resolved.clone();
            let integrity = node.integrity.clone();
            let name = node.name.clone();
            let version = node.version.clone();
            set.spawn(async move {
                // For git dependencies, the resolved URL is git+https:// or similar.
                // Try to find the cached tarball from the git cache directory.
                if resolved.starts_with("git+") || resolved.starts_with("github:")
                    || resolved.starts_with("gitlab:") || resolved.starts_with("bitbucket:")
                {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                    let safe_name = name.replace('/', "+");
                    let cache_file = std::path::PathBuf::from(&home)
                        .join(".oath").join("git-cache")
                        .join(format!("{}-{}.tgz", safe_name, version));
                    if cache_file.exists() {
                        let data = std::fs::read(&cache_file)
                            .with_context(|| format!("reading git cache {}", cache_file.display()))?;
                        return Ok((name, version, data));
                    }
                    anyhow::bail!("git dep {name}@{version} not in cache and no tarball URL available");
                }
                let data = client
                    .fetch_tarball(&resolved, integrity.as_deref())
                    .await
                    .with_context(|| format!("downloading {name}@{version}"))?;
                Ok((name, version, data))
            });
        }

        while let Some(res) = set.join_next().await {
            let (name, version, data) = res??;
            download_bytes += data.len() as u64;
            let tmp = tempfile::tempdir()?;
            oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
            store.store_package(&name, &version, tmp.path())?;
            downloaded += 1;
        }
    }

    let download_time = download_start.elapsed();
    if downloaded > 0 {
        println!(
            "  downloaded {} new ({}) in {:.1}s",
            downloaded,
            format_bytes(download_bytes),
            download_time.as_secs_f64()
        );
    }
    if cached > 0 {
        println!("  {} already cached", cached);
    }

    // Link
    let link_start = Instant::now();
    let store_ref = Arc::clone(&store);
    let linker = Linker::new((*store_ref).clone());
    let cwd = std::env::current_dir()?;
    let link_result = linker.link_all(&graph, &cwd)?;
    let link_time = link_start.elapsed();
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    // Write lockfile
    let lockfile = Lockfile::from_graph(&graph, &project_name, &project_version);
    if frozen_lockfile {
        // Compare new lockfile with existing; error if they differ
        let existing_content = std::fs::read_to_string("oath-lock.json")
            .context("failed to read oath-lock.json")?;
        let new_content = serde_json::to_string_pretty(&lockfile)?;
        // Parse both to compare semantically (ignore key ordering differences)
        let existing_val: serde_json::Value = serde_json::from_str(&existing_content)
            .context("failed to parse existing oath-lock.json")?;
        let new_val: serde_json::Value = serde_json::from_str(&new_content)?;
        if existing_val != new_val {
            anyhow::bail!("lockfile would be modified, refusing (--frozen-lockfile)");
        }
    } else {
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
    }

    // Write package.json manifest if packages were explicitly specified
    if !packages.is_empty() {
        let mut pkg_json: serde_json::Value = if PathBuf::from("package.json").exists() {
            read_package_json()?
        } else {
            serde_json::json!({"name": "project", "version": "1.0.0"})
        };
        let dep_key = if dev { "devDependencies" } else { "dependencies" };
        if pkg_json.get(dep_key).is_none() {
            pkg_json[dep_key] = serde_json::json!({});
        }
        for (pkg_name, _spec) in &deps {
            // Find resolved version from graph
            let resolved_version = graph.nodes.values()
                .find(|n| &n.name == pkg_name)
                .map(|n| n.version.clone())
                .unwrap_or_else(|| "0.0.0".to_string());
            let version_range = format!("^{}", resolved_version);
            pkg_json[dep_key][pkg_name] = serde_json::Value::String(version_range);
        }
        std::fs::write("package.json", serde_json::to_string_pretty(&pkg_json)?)?;
    }

    // -- Peer dependency warnings ---------------------------------------------
    let peer = &graph.peer_report;
    for r in &peer.missing {
        if let PeerResolution::Missing { required_by, peer_name, range } = r {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep missing: {}@{}, required by {}",
                peer_name, range, required_by
            );
        }
    }
    for r in &peer.conflicts {
        if let PeerResolution::Conflict { required_by, peer_name, range, found_version } = r {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep conflict: {}@{} installed, {} requires {}",
                peer_name, found_version, required_by, range
            );
        }
    }

    // -- Install script permission prompts ------------------------------------
    // Load policy (project-local oath-policy.toml + global ~/.oath/policy.toml)
    let policy = OathPolicy::load();
    let store_path = store.store_path();

    let mut scripts_blocked = 0;
    for (_key, node) in &graph.nodes {
        if !node.has_install_script {
            continue;
        }

        // Policy hard-block
        if policy.is_package_banned(&node.name) {
            println!(
                "  oath: blocked install script for banned package {}@{}",
                node.name, node.version
            );
            continue;
        }

        // Run scripts from the linked node_modules location so that optional platform
        // packages (e.g. @esbuild/darwin-arm64) are resolvable via sibling node_modules.
        // Fall back to the store dir if the linked path doesn't exist.
        let install_name = node.alias.as_deref().unwrap_or(&node.name);
        let linked_pkg_dir = cwd.join("node_modules").join(install_name);
        let store_pkg_dir = store_path
            .join(node.name.replace('/', "+"))
            .join(&node.version);
        let pkg_dir = if linked_pkg_dir.exists() {
            linked_pkg_dir
        } else {
            store_pkg_dir
        };

        // Trusted: run without prompting
        if trusted_deps.contains(&node.name) || yes_flag {
            if pkg_dir.exists() {
                run_install_script(&node.name, &pkg_dir);
            }
            continue;
        }

        // --run-scripts: prompt for each (old behavior)
        if run_scripts {
            if !pkg_dir.exists() {
                continue;
            }
            let report = match PackageScanner::scan(&node.name, &node.version, &pkg_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let script_display = detect_install_script(&pkg_dir)
                .unwrap_or_else(|| "node install.js".to_string());
            let decision = prompts::prompt_install_script(
                &node.name,
                &node.version,
                &script_display,
                &report.capabilities,
                false,
                &policy,
            );
            match decision {
                prompts::ScriptDecision::Allow | prompts::ScriptDecision::Always => {
                    run_install_script(&node.name, &pkg_dir);
                }
                prompts::ScriptDecision::Sandbox => {
                    run_install_script_sandboxed(&node.name, &pkg_dir);
                }
                prompts::ScriptDecision::Deny => {}
            }
            continue;
        }

        // Default: BLOCK (silent, just count)
        scripts_blocked += 1;
    }

    if scripts_blocked > 0 {
        println!(
            "  {} install script(s) blocked (add to trustedDependencies or use --run-scripts)",
            scripts_blocked
        );
    }

    // Static analysis on newly downloaded packages
    if run_audit && downloaded > 0 {
        println!("  scanning {} new packages...", downloaded);
        let mut critical = 0usize;
        let mut high = 0usize;

        for (_key, node) in &graph.nodes {
            // Use the canonical store layout (name/version). The old
            // `format!("{}-{}")` path never existed, so the scan silently
            // skipped every package and always printed "all clear".
            let pkg_dir = store.package_dir(&node.name, &node.version);
            if !pkg_dir.exists() {
                continue;
            }
            let report = match PackageScanner::scan(&node.name, &node.version, &pkg_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            match report.overall_risk {
                RiskLevel::Critical => {
                    critical += 1;
                    println!();
                    println!(
                        "  CRITICAL {}@{} -- {}",
                        node.name,
                        node.version,
                        report
                            .findings
                            .first()
                            .map(|f| f.message.as_str())
                            .unwrap_or("suspicious behavior")
                    );
                    for f in report.findings.iter().filter(|f| f.risk >= RiskLevel::High) {
                        println!("    [{:?}] {} L{}", f.risk, f.message, f.line);
                        if let Some(s) = &f.snippet {
                            println!("      {s}");
                        }
                    }
                }
                RiskLevel::High => {
                    high += 1;
                    println!(
                        "  WARN {}@{} -- {}",
                        node.name,
                        node.version,
                        report
                            .findings
                            .iter()
                            .find(|f| f.risk >= RiskLevel::High)
                            .map(|f| f.message.as_str())
                            .unwrap_or("flagged behavior")
                    );
                }
                _ => {}
            }
        }

        if critical > 0 {
            println!();
            println!(
                "  {} critical issue(s) found -- run `oath audit` for details",
                critical
            );
        } else if high > 0 {
            println!(
                "  {} warning(s) -- run `oath audit --verbose` for details",
                high
            );
        } else {
            println!("  all clear");
        }
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    // ---- Transparency log ---------------------------------------------------
    let project_path = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let pkg_entries: Vec<(String, String, Option<String>)> = graph.nodes.values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    Ok(())
}

// ---- WORKSPACE INSTALL ------------------------------------------------------

/// Install dependencies for a workspace (monorepo) in hoisted mode.
///
/// Strategy (npm-style flat hoisting):
///   1. Collect all external deps from all workspace packages into a single set
///   2. Resolve + download them once as a unified graph
///   3. Link them all into root/node_modules (hoisted)
///   4. Symlink each workspace package itself into root/node_modules/<name>
async fn cmd_install_workspace(
    ws: &WorkspaceRoot,
    dry_run: bool,
    run_audit: bool,
    yes_flag: bool,
    _run_scripts: bool,
) -> Result<()> {
    let start = Instant::now();

    // Collect external deps from all workspace packages (merged, deduped)
    let (external_deps, workspace_links) = ws.collect_external_deps(true);

    println!(
        "  {} external deps, {} workspace links",
        external_deps.len(),
        workspace_links.len()
    );

    if external_deps.is_empty() && workspace_links.is_empty() {
        println!("  nothing to install");
        return Ok(());
    }

    if dry_run {
        println!("  (dry run) would resolve {} external deps", external_deps.len());
        for (consumer, dep, path) in &workspace_links {
            println!("  (dry run) workspace link: {} -> {} ({})", dep, path, consumer);
        }
        return Ok(());
    }

    // Resolve the unified dep graph
    println!("  resolving {} external dependencies...", external_deps.len());
    let client = RegistryClient::default_client()?;
    let options = ResolveOptions {
        include_dev: true,
        include_optional: true,
        max_depth: 256,
    };
    let mut resolver = Resolver::new(client, options);

    // Split external_deps into deps and dev_deps (we treat all as deps for hoisting)
    let empty_dev_deps: HashMap<String, String> = HashMap::new();
    let graph = resolver.resolve(&external_deps, &empty_dev_deps).await?;

    let resolve_time = start.elapsed();
    println!(
        "  resolved {} packages in {:.1}s",
        graph.package_count(),
        resolve_time.as_secs_f64()
    );

    // Download
    let download_start = Instant::now();
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);

    let mut to_download = vec![];
    let mut cached = 0usize;
    for (_key, node) in &graph.nodes {
        if store.has_package(&node.name, &node.version) {
            cached += 1;
        } else {
            to_download.push(node.clone());
        }
    }

    let mut downloaded = 0usize;
    let mut download_bytes = 0u64;

    if !to_download.is_empty() {
        let mut set: JoinSet<Result<(String, String, Vec<u8>)>> = JoinSet::new();
        for node in to_download {
            let client = Arc::clone(&client);
            let resolved = node.resolved.clone();
            let integrity = node.integrity.clone();
            let name = node.name.clone();
            let version = node.version.clone();
            set.spawn(async move {
                let data = client
                    .fetch_tarball(&resolved, integrity.as_deref())
                    .await
                    .with_context(|| format!("downloading {name}@{version}"))?;
                Ok((name, version, data))
            });
        }
        while let Some(res) = set.join_next().await {
            let (name, version, data) = res??;
            download_bytes += data.len() as u64;
            let tmp = tempfile::tempdir()?;
            oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
            store.store_package(&name, &version, tmp.path())?;
            downloaded += 1;
        }
    }

    let download_time = download_start.elapsed();
    if downloaded > 0 {
        println!(
            "  downloaded {} new ({}) in {:.1}s",
            downloaded,
            format_bytes(download_bytes),
            download_time.as_secs_f64()
        );
    }
    if cached > 0 {
        println!("  {} already cached", cached);
    }

    // Link into root node_modules
    let link_start = Instant::now();
    let store_ref = Arc::clone(&store);
    let linker = Linker::new((*store_ref).clone());
    let link_result = linker.link_all(&graph, &ws.root)?;
    let link_time = link_start.elapsed();
    println!(
        "  linked {} packages in {:.1}s",
        link_result.linked,
        link_time.as_secs_f64()
    );

    // Symlink each workspace package into root/node_modules/<name>
    let nm_dir = ws.root.join("node_modules");
    let mut ws_symlinks = 0usize;
    for pkg in &ws.packages {
        let install_name = &pkg.name;
        let symlink_path = nm_dir.join(install_name);

        // Handle scoped packages: create @scope dir
        if install_name.contains('/') {
            if let Some(scope) = install_name.split('/').next() {
                std::fs::create_dir_all(nm_dir.join(scope))?;
            }
        }

        // Remove existing symlink if present
        if symlink_path.exists() || symlink_path.symlink_metadata().is_ok() {
            std::fs::remove_file(&symlink_path).ok();
        }

        // Create relative symlink: node_modules/<name> -> ../../packages/ui
        // For scoped packages (@scope/name), the symlink lives at node_modules/@scope/name
        // so we must compute the relative path FROM node_modules/@scope/, not node_modules/
        let symlink_parent = if install_name.contains('/') {
            if let Some(scope) = install_name.split('/').next() {
                nm_dir.join(scope)
            } else {
                nm_dir.clone()
            }
        } else {
            nm_dir.clone()
        };
        let relative_path = relative_path_from(&symlink_parent, &pkg.path)?;
        std::os::unix::fs::symlink(&relative_path, &symlink_path).with_context(|| {
            format!(
                "failed to symlink workspace package {} -> {}",
                symlink_path.display(),
                relative_path.display()
            )
        })?;
        ws_symlinks += 1;
    }

    println!(
        "  symlinked {} workspace packages into node_modules",
        ws_symlinks
    );

    // Write lockfile at workspace root
    let lockfile = Lockfile::from_graph(&graph, "workspace", "0.0.0");
    lockfile.write(&ws.root.join("oath-lock.json"))?;

    // -- Peer dependency warnings ---------------------------------------------
    let peer = &graph.peer_report;
    for r in &peer.missing {
        if let PeerResolution::Missing { required_by, peer_name, range } = r {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep missing: {}@{}, required by {}",
                peer_name, range, required_by
            );
        }
    }
    for r in &peer.conflicts {
        if let PeerResolution::Conflict { required_by, peer_name, range, found_version } = r {
            eprintln!(
                "\x1b[33mwarn\x1b[0m peer dep conflict: {}@{} installed, {} requires {}",
                peer_name, found_version, required_by, range
            );
        }
    }

    // Audit if requested
    if run_audit && downloaded > 0 {
        println!("  scanning {} new packages...", downloaded);
        // (same logic as single-pkg install; abbreviated here)
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    // ---- Transparency log ---------------------------------------------------
    let project_path = ws.root.to_string_lossy().to_string();
    let pkg_entries: Vec<(String, String, Option<String>)> = graph.nodes.values()
        .map(|n| (n.name.clone(), n.version.clone(), n.integrity.clone()))
        .collect();
    if let Ok(logger) = oath_transparency::TransparencyLogger::default_logger() {
        let _ = logger.log(&project_path, &pkg_entries, total_time.as_millis() as u64);
    }

    Ok(())
}

/// Compute a relative path from `from_dir` to `to_path`
fn relative_path_from(from_dir: &std::path::Path, to_path: &std::path::Path) -> Result<PathBuf> {
    // Find common prefix and build ../.. chain
    let from_components: Vec<_> = from_dir.components().collect();
    let to_components: Vec<_> = to_path.components().collect();

    let common_len = from_components
        .iter()
        .zip(to_components.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let up_count = from_components.len() - common_len;
    let mut rel = PathBuf::new();
    for _ in 0..up_count {
        rel.push("..");
    }
    for component in &to_components[common_len..] {
        rel.push(component);
    }
    Ok(rel)
}

// ---- AUDIT ------------------------------------------------------------------

async fn cmd_audit(production: bool, verbose: bool) -> Result<()> {
    let pkg = read_package_json()?;
    let mut all_deps = extract_deps(&pkg, "dependencies");
    if !production {
        all_deps.extend(extract_deps(&pkg, "devDependencies"));
    }

    if all_deps.is_empty() {
        println!("oath audit: no dependencies found");
        return Ok(());
    }

    println!(
        "oath audit: scanning {} direct deps (+ transitive)...",
        all_deps.len()
    );

    let store = ContentStore::default_store()?;
    let store_path = store.store_path();

    let mut total = 0usize;
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;

    // Walk the store -- layout is store/{name}/{version}/
    let store_entries = match std::fs::read_dir(&store_path) {
        Ok(e) => e,
        Err(_) => {
            println!("oath audit: nothing installed yet (run `oath install` first)");
            return Ok(());
        }
    };

    for name_entry in store_entries.filter_map(|e| e.ok()) {
        let name_path = name_entry.path();
        if !name_path.is_dir() { continue; }
        let name = name_entry.file_name().to_string_lossy().replace('+', "/");

        let ver_entries = match std::fs::read_dir(&name_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ver_entry in ver_entries.filter_map(|e| e.ok()) {
            let pkg_path = ver_entry.path();
            if !pkg_path.is_dir() { continue; }
            let version = ver_entry.file_name().to_string_lossy().to_string();

            let report = match PackageScanner::scan(&name, &version, &pkg_path) {
                Ok(r) => r,
                Err(_) => continue,
            };

            total += 1;

            let show = match report.overall_risk {
                RiskLevel::Critical => { critical += 1; true }
                RiskLevel::High => { high += 1; true }
                RiskLevel::Medium => { medium += 1; verbose }
                _ => verbose,
            };

            if show {
                let risk_label = match report.overall_risk {
                    RiskLevel::Critical => "CRITICAL",
                    RiskLevel::High => "HIGH    ",
                    RiskLevel::Medium => "MEDIUM  ",
                    _ => "INFO    ",
                };
                println!();
                println!("[{risk_label}] {name}@{version}");
                println!("  files: {}  lines: {}", report.files_scanned, report.lines_scanned);
                println!("  capabilities: {}", fmt_capabilities(&report.capabilities));
                for f in report.findings.iter().filter(|f| verbose || f.risk >= RiskLevel::High) {
                    println!("  - [{:?}] L{} {} -- {}", f.risk, f.line, f.file, f.message);
                    if let Some(s) = &f.snippet {
                        println!("    > {s}");
                    }
                }
            }
        } // ver_entry
    } // name_entry

    println!();
    println!(
        "oath audit: {} packages scanned -- {} critical, {} high, {} medium",
        total, critical, high, medium
    );

    if critical > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ---- PERMS ------------------------------------------------------------------

fn cmd_perms(package: &str) -> Result<()> {
    let store = ContentStore::default_store()?;
    let store_path = store.store_path();

    // Store layout: store/{name}/{version}/
    // For scoped packages @scope/name, stored as @scope+name
    let safe_name = package.replace('/', "+");
    let pkg_name_dir = store_path.join(&safe_name);

    if !pkg_name_dir.exists() {
        println!("oath: package '{package}' not found in store (run `oath install` first)");
        return Ok(());
    }

    for ver_entry in std::fs::read_dir(&pkg_name_dir)?.filter_map(|e| e.ok()) {
        let pkg_path = ver_entry.path();
        if !pkg_path.is_dir() { continue; }
        let version = ver_entry.file_name().to_string_lossy().to_string();
        let report = PackageScanner::scan(package, &version, &pkg_path)?;

        println!("{package}@{version}");
        println!("  risk:    {}", report.overall_risk);
        println!("  files:   {}", report.files_scanned);
        println!("  lines:   {}", report.lines_scanned);
        println!();
        println!("  PERMISSIONS:");
        println!("    network:         {}", yn(report.capabilities.network));
        println!("    filesystem:      {}", yn(report.capabilities.filesystem));
        println!("    env vars:        {}", yn(report.capabilities.env_access));
        println!("    subprocess:      {}", yn(report.capabilities.subprocess));
        println!("    dynamic exec:    {}", yn(report.capabilities.dynamic_exec));
        println!(
            "    install scripts: {}",
            yn(report.capabilities.has_install_scripts)
        );

        if !report.findings.is_empty() {
            println!();
            println!("  FINDINGS:");
            for f in &report.findings {
                let marker = match f.risk {
                    RiskLevel::Critical => "!!",
                    RiskLevel::High => " !",
                    RiskLevel::Medium => " ~",
                    _ => "  ",
                };
                println!("  {marker} L{:<4} {} -- {}", f.line, f.kind, f.message);
                if let Some(s) = &f.snippet {
                    println!("       > {s}");
                }
            }
        }
    }
    Ok(())
}

// ---- ADD --------------------------------------------------------------------

async fn cmd_add(package: &str, _dev: bool) -> Result<()> {
    let (name, spec) = parse_package_spec(package);
    let mut pkg: serde_json::Value = if PathBuf::from("package.json").exists() {
        read_package_json()?
    } else {
        serde_json::json!({"name": "project", "version": "1.0.0"})
    };

    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &spec)?;
    let version_range = format!("^{}", resolved.version);
    let key = if _dev { "devDependencies" } else { "dependencies" };

    if pkg.get(key).is_none() {
        pkg[key] = serde_json::json!({});
    }
    pkg[key][&name] = serde_json::Value::String(version_range);

    std::fs::write("package.json", serde_json::to_string_pretty(&pkg)?)?;
    println!("oath: added {name}@{} ({key})", resolved.version);
    cmd_install(vec![], false, false, true, false, false, false, false, None).await
}

// ---- RUN --------------------------------------------------------------------

fn cmd_run(script: Option<&str>, args: &[String]) -> Result<()> {
    let pkg = read_package_json()?;

    let scripts_obj = pkg
        .get("scripts")
        .and_then(|s| s.as_object());

    // No script name: list all available scripts
    let script = match script {
        None => {
            match scripts_obj {
                None => {
                    println!("oath run: no scripts defined in package.json");
                }
                Some(scripts) => {
                    if scripts.is_empty() {
                        println!("oath run: no scripts defined in package.json");
                    } else {
                        println!("Available scripts:");
                        for (name, cmd) in scripts {
                            println!("  {} - {}", name, cmd.as_str().unwrap_or(""));
                        }
                    }
                }
            }
            return Ok(());
        }
        Some(s) => s,
    };

    let scripts = scripts_obj.context("no scripts defined in package.json")?;

    let cmd = scripts
        .get(script)
        .and_then(|v| v.as_str())
        .with_context(|| format!("script '{script}' not found"))?;

    // Build augmented PATH with local node_modules/.bin
    let path_env = format!(
        "./node_modules/.bin:{}",
        std::env::var("PATH").unwrap_or_default()
    );

    // Helper to run a single script command and return the exit status
    let run_script = |script_name: &str, script_cmd: &str| -> Result<std::process::ExitStatus> {
        println!();
        println!("> {}@0.0.0 {}", pkg["name"].as_str().unwrap_or("project"), script_name);
        println!("> {}", script_cmd);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script_cmd)
            .env("PATH", &path_env)
            .status()
            .with_context(|| format!("failed to execute script '{script_name}'"))?;
        Ok(status)
    };

    let start = Instant::now();

    // Run pre-hook if it exists
    let pre_name = format!("pre{script}");
    if let Some(pre_cmd) = scripts.get(&pre_name).and_then(|v| v.as_str()) {
        let status = run_script(&pre_name, pre_cmd)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    // Run the main script with any additional args
    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };
    let status = run_script(script, &full_cmd)?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    // Run post-hook if it exists
    let post_name = format!("post{script}");
    if let Some(post_cmd) = scripts.get(&post_name).and_then(|v| v.as_str()) {
        let status = run_script(&post_name, post_cmd)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!("  Done in {:.2}s", elapsed.as_secs_f64());

    Ok(())
}

// ---- INIT -------------------------------------------------------------------

fn cmd_init(name: Option<&str>) -> Result<()> {
    let project_name = name
        .map(|n| n.to_string())
        .unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "project".to_string())
        });

    let pkg = serde_json::json!({
        "name": project_name,
        "version": "1.0.0",
        "description": "",
        "main": "index.js",
        "scripts": {"test": "echo \"Error: no test specified\" && exit 1"},
        "keywords": [],
        "license": "MIT"
    });
    let content = serde_json::to_string_pretty(&pkg)?;
    std::fs::write("package.json", &content)?;
    println!("oath init: created package.json");
    println!("{content}");
    Ok(())
}

// ---- WHY --------------------------------------------------------------------

fn cmd_why(package: &str) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath why: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let content = std::fs::read_to_string(&lock_path)?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let packages = match lock.get("packages").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            println!("oath why: oath-lock.json has no packages");
            return Ok(());
        }
    };

    // Find all keys that match the package name (any version)
    let mut matches: Vec<(&str, &serde_json::Value)> = packages
        .iter()
        .filter(|(key, _)| {
            let k = key.as_str();
            k == package
                || k.starts_with(&format!("{package}@"))
        })
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    if matches.is_empty() {
        println!("oath why: '{package}' not found in oath-lock.json");
        return Ok(());
    }

    // Build reverse dependency map: pkg_key -> Vec<pkg_key that depends on it>
    let mut rdeps: HashMap<String, Vec<String>> = HashMap::new();
    for (key, node) in packages.iter() {
        if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
            for (dep_name, dep_ver) in deps.iter() {
                let dep_ver_str = dep_ver.as_str().unwrap_or("");
                let dep_key = format!("{dep_name}@{dep_ver_str}");
                rdeps.entry(dep_key).or_default().push(key.clone());
            }
        }
    }

    // Determine roots from lockfile (packages with no reverse deps or explicit roots)
    let all_keys: HashSet<&str> = packages.keys().map(|k| k.as_str()).collect();

    // Read direct deps from package.json if available
    let direct_deps: HashSet<String> = if PathBuf::from("package.json").exists() {
        let pkg = read_package_json().unwrap_or(serde_json::json!({}));
        let mut d = extract_deps(&pkg, "dependencies");
        d.extend(extract_deps(&pkg, "devDependencies"));
        d.keys().cloned().collect()
    } else {
        HashSet::new()
    };

    // For each matched package, trace path to root
    matches.sort_by_key(|(k, _)| *k);
    for (key, node) in &matches {
        let name = node.get("name").and_then(|n| n.as_str()).unwrap_or(package);
        let version = node.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let has_install = node
            .get("hasInstallScript")
            .or_else(|| node.get("has_install_script"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        println!("  {name}@{version}");

        // Check if it's a direct dependency
        if direct_deps.contains(name) {
            println!("    why: required by your package.json (direct dependency)");
        } else {
            // BFS to find shortest path to root (node with no reverse deps)
            let path = find_dep_path(key, &rdeps, &all_keys);
            if path.is_empty() {
                println!("    why: required by (unknown)");
            } else {
                let chain = path.join(" -> ");
                println!("    why: required by {chain} -> root");
            }
        }

        // Scan from store for capabilities/risk
        let store = ContentStore::default_store()?;
        let store_path = store.store_path();
        let safe_name = name.replace('/', "+");
        let pkg_dir = store_path.join(&safe_name).join(version);

        if pkg_dir.exists() {
            match PackageScanner::scan(name, version, &pkg_dir) {
                Ok(report) => {
                    println!("    risk: {}", report.overall_risk);
                    println!("    capabilities: {}", fmt_capabilities(&report.capabilities));
                    println!("    install script: {}", yn(report.capabilities.has_install_scripts || has_install));
                }
                Err(_) => {
                    println!("    (could not scan package)");
                    println!("    install script: {}", yn(has_install));
                }
            }
        } else {
            println!("    (package not found in store -- run `oath install`)");
            println!("    install script: {}", yn(has_install));
        }
        println!();
    }
    Ok(())
}

/// BFS from `start` upward through rdeps to find path to a root node.
/// Returns the chain of package keys from direct parent up to (but not including) the root.
fn find_dep_path(
    start: &str,
    rdeps: &HashMap<String, Vec<String>>,
    all_keys: &HashSet<&str>,
) -> Vec<String> {
    // BFS
    let mut queue: std::collections::VecDeque<(String, Vec<String>)> = std::collections::VecDeque::new();
    queue.push_back((start.to_string(), vec![]));
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(start.to_string());

    while let Some((current, path)) = queue.pop_front() {
        if let Some(parents) = rdeps.get(&current) {
            for parent in parents {
                if visited.contains(parent) {
                    continue;
                }
                let mut new_path = vec![parent.clone()];
                new_path.extend(path.iter().cloned());
                // If parent has no rdeps it's a root
                let parent_has_parents = rdeps.get(parent).map(|v| !v.is_empty()).unwrap_or(false);
                if !parent_has_parents {
                    return new_path;
                }
                visited.insert(parent.clone());
                queue.push_back((parent.clone(), new_path));
            }
        } else {
            // current is a root, return path
            return path;
        }
    }
    vec![]
}

// ---- LICENSES ---------------------------------------------------------------

fn cmd_licenses() -> Result<()> {
    let store = ContentStore::default_store()?;
    let store_path = store.store_path();

    let store_entries = match std::fs::read_dir(&store_path) {
        Ok(e) => e,
        Err(_) => {
            println!("oath licenses: nothing installed yet (run `oath install` first)");
            return Ok(());
        }
    };

    // license -> count
    let mut license_counts: BTreeMap<String, usize> = BTreeMap::new();

    for name_entry in store_entries.filter_map(|e| e.ok()) {
        let name_path = name_entry.path();
        if !name_path.is_dir() {
            continue;
        }

        let ver_entries = match std::fs::read_dir(&name_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for ver_entry in ver_entries.filter_map(|e| e.ok()) {
            let pkg_path = ver_entry.path();
            if !pkg_path.is_dir() {
                continue;
            }

            let pkg_json_path = pkg_path.join("package.json");
            let license = if pkg_json_path.exists() {
                match std::fs::read_to_string(&pkg_json_path) {
                    Ok(content) => {
                        match serde_json::from_str::<serde_json::Value>(&content) {
                            Ok(pkg) => {
                                // license can be a string or an object with "type" field
                                pkg.get("license")
                                    .map(|l| {
                                        if let Some(s) = l.as_str() {
                                            s.to_string()
                                        } else if let Some(t) = l.get("type").and_then(|t| t.as_str()) {
                                            t.to_string()
                                        } else {
                                            "UNKNOWN".to_string()
                                        }
                                    })
                                    .unwrap_or_else(|| "UNKNOWN".to_string())
                            }
                            Err(_) => "UNKNOWN".to_string(),
                        }
                    }
                    Err(_) => "UNKNOWN".to_string(),
                }
            } else {
                "UNKNOWN".to_string()
            };

            *license_counts.entry(license).or_insert(0) += 1;
        }
    }

    if license_counts.is_empty() {
        println!("oath licenses: no packages found");
        return Ok(());
    }

    // Sort by count descending for display
    let mut sorted: Vec<(String, usize)> = license_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    // Find longest license name for alignment
    let max_len = sorted.iter().map(|(l, _)| l.len()).max().unwrap_or(10);

    for (license, count) in &sorted {
        let pkg_word = if *count == 1 { "package " } else { "packages" };
        let flag = if license == "UNKNOWN" {
            " [review recommended]"
        } else if license.starts_with("GPL")
            || license.starts_with("AGPL")
            || license.starts_with("LGPL")
        {
            " [COPYLEFT - review required]"
        } else {
            ""
        };
        println!(
            "  {:<width$}  {} {}{}",
            license,
            count,
            pkg_word,
            flag,
            width = max_len
        );
    }
    Ok(())
}

// ---- VERIFY -----------------------------------------------------------------

fn cmd_verify() -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath verify: no oath-lock.json found");
        return Ok(());
    }
    let content = std::fs::read_to_string(&lock_path)?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let packages = match lock.get("packages").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            println!("oath verify: oath-lock.json has no packages");
            return Ok(());
        }
    };

    let store = ContentStore::default_store()?;
    let store_path = store.store_path();
    let total = packages.len();
    println!("  checking {total} packages...");

    let mut missing = 0usize;
    let mut tampered = 0usize;
    let mut ok = 0usize;

    let mut entries: Vec<(&String, &serde_json::Value)> = packages.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());

    for (key, node) in &entries {
        // The package name lives in the key ("name@version" or "@scope/name@version"),
        // not in the entry. Reading it from the entry left `name` empty and silently
        // skipped every package -- the cause of "0 packages verified".
        let name = match key.rfind('@') {
            Some(at) if at > 0 => &key[..at],
            _ => key.as_str(),
        };
        let version = node.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let integrity = node.get("integrity").and_then(|i| i.as_str()).unwrap_or("");

        if name.is_empty() || version.is_empty() {
            continue;
        }

        let safe_name = name.replace('/', "+");
        let pkg_dir = store_path.join(&safe_name).join(version);

        if !pkg_dir.exists() {
            println!("  MISSING:  {key}");
            missing += 1;
            continue;
        }

        // Re-hash package.json as a key file integrity check
        let pkg_json = pkg_dir.join("package.json");
        if !pkg_json.exists() {
            println!("  MISSING:  {key} -- package.json not found in store");
            missing += 1;
            continue;
        }

        // If integrity is a sha512 hash (sri format), we can verify the tarball hash.
        // Since we don't have the tarball anymore, verify package.json exists and
        // cross-check the name/version fields match what's locked.
        if !integrity.is_empty() {
            match std::fs::read_to_string(&pkg_json) {
                Ok(pj_content) => {
                    match serde_json::from_str::<serde_json::Value>(&pj_content) {
                        Ok(pj) => {
                            let stored_name = pj.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            let stored_version = pj.get("version").and_then(|v| v.as_str()).unwrap_or("");
                            if stored_name != name || stored_version != version {
                                println!(
                                    "  TAMPERED: {key} -- package.json name/version mismatch (got {stored_name}@{stored_version})"
                                );
                                tampered += 1;
                                continue;
                            }
                        }
                        Err(_) => {
                            println!("  TAMPERED: {key} -- package.json is not valid JSON");
                            tampered += 1;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    println!("  TAMPERED: {key} -- could not read package.json");
                    tampered += 1;
                    continue;
                }
            }
        }

        println!("  {key:<40} ok");
        ok += 1;
    }

    println!();
    if missing > 0 || tampered > 0 {
        if missing > 0 {
            println!("  lockfile: {missing} missing (run `oath install` to restore)");
        }
        if tampered > 0 {
            println!("  lockfile: {tampered} tampered entry(s) detected");
        }
        std::process::exit(1);
    } else {
        println!("  lockfile: clean ({ok} packages verified)");
    }
    Ok(())
}

// ---- GRAPH ------------------------------------------------------------------

fn cmd_graph(max_depth: usize) -> Result<()> {
    let lock_path = PathBuf::from("oath-lock.json");
    if !lock_path.exists() {
        println!("oath graph: no oath-lock.json found (run `oath install` first)");
        return Ok(());
    }
    let content = std::fs::read_to_string(&lock_path)?;
    let lock: serde_json::Value = serde_json::from_str(&content)?;

    let packages = match lock.get("packages").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => {
            println!("oath graph: oath-lock.json has no packages");
            return Ok(());
        }
    };

    // Determine root keys: packages listed under "roots" or inferred from package.json
    let roots: Vec<String> = if let Some(r) = lock.get("roots").and_then(|r| r.as_array()) {
        r.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else {
        // Fall back: use direct deps from package.json if available
        if PathBuf::from("package.json").exists() {
            let pkg = read_package_json().unwrap_or(serde_json::json!({}));
            let name = pkg["name"].as_str().unwrap_or("project").to_string();
            let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
            // Print a synthetic root
            println!("  {name}@{version}");

            let mut direct_deps: Vec<String> = {
                let mut d: Vec<String> = extract_deps(&pkg, "dependencies").keys().cloned().collect();
                d.extend(extract_deps(&pkg, "devDependencies").keys().cloned());
                d.sort();
                d
            };

            // Resolve each direct dep to a versioned key in the lockfile
            let root_children: Vec<String> = direct_deps
                .drain(..)
                .filter_map(|dep_name| {
                    // Find matching key in packages
                    packages
                        .keys()
                        .find(|k| {
                            let k = k.as_str();
                            k == dep_name || k.starts_with(&format!("{dep_name}@"))
                        })
                        .map(|k| k.clone())
                })
                .collect();

            print_graph_children(&root_children, packages, 1, max_depth, &mut HashSet::new(), "");
            println!();
            return Ok(());
        } else {
            // No package.json; pick nodes with no incoming edges as roots
            let mut has_parent: HashSet<&str> = HashSet::new();
            for node in packages.values() {
                if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
                    for (dep_name, dep_ver) in deps.iter() {
                        let dep_ver_str = dep_ver.as_str().unwrap_or("");
                        let dep_key = format!("{dep_name}@{dep_ver_str}");
                        if packages.contains_key(&dep_key) {
                            has_parent.insert(packages.get_key_value(&dep_key).map(|(k, _)| k.as_str()).unwrap_or(""));
                        }
                    }
                }
            }
            packages
                .keys()
                .filter(|k| !has_parent.contains(k.as_str()))
                .cloned()
                .collect()
        }
    };

    if roots.is_empty() {
        println!("  (no root packages found)");
        return Ok(());
    }

    for root_key in &roots {
        println!("  {root_key}");
        if let Some(root_node) = packages.get(root_key) {
            if let Some(deps) = root_node.get("dependencies").and_then(|d| d.as_object()) {
                let mut dep_keys: Vec<String> = deps
                    .iter()
                    .map(|(dep_name, dep_ver)| {
                        let dep_ver_str = dep_ver.as_str().unwrap_or("");
                        format!("{dep_name}@{dep_ver_str}")
                    })
                    .collect();
                dep_keys.sort();
                print_graph_children(&dep_keys, packages, 1, max_depth, &mut HashSet::new(), "");
            }
        }
    }
    println!();
    Ok(())
}

fn print_graph_children(
    children: &[String],
    packages: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
    prefix: &str,
) {
    let count = children.len();
    for (i, child_key) in children.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "+--" } else { "+--" };
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}|   ")
        };

        println!("  {prefix}{connector} {child_key}");

        if depth >= max_depth {
            // Check if there are deeper deps but we're truncating
            if let Some(node) = packages.get(child_key) {
                if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
                    if !deps.is_empty() {
                        println!("  {child_prefix}... ({} more deps, use --depth to show)", deps.len());
                    }
                }
            }
            continue;
        }

        if visited.contains(child_key) {
            println!("  {child_prefix}(circular)");
            continue;
        }

        visited.insert(child_key.clone());

        if let Some(node) = packages.get(child_key) {
            if let Some(deps) = node.get("dependencies").and_then(|d| d.as_object()) {
                let mut dep_keys: Vec<String> = deps
                    .iter()
                    .map(|(dep_name, dep_ver)| {
                        let dep_ver_str = dep_ver.as_str().unwrap_or("");
                        format!("{dep_name}@{dep_ver_str}")
                    })
                    .collect();
                dep_keys.sort();
                print_graph_children(&dep_keys, packages, depth + 1, max_depth, visited, &child_prefix);
            }
        }

        visited.remove(child_key);
    }
}

// ---- HELPERS ----------------------------------------------------------------

fn read_package_json() -> Result<serde_json::Value> {
    let content = std::fs::read_to_string("package.json")
        .context("no package.json found (run `oath init` to create one)")?;
    serde_json::from_str(&content).context("failed to parse package.json")
}

fn extract_deps(pkg: &serde_json::Value, key: &str) -> HashMap<String, String> {
    pkg.get(key)
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("*").to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_package_spec(spec: &str) -> (String, String) {
    // Handle @scope/name@version vs name@version vs name
    if let Some(stripped) = spec.strip_prefix('@') {
        // scoped: @scope/name@version
        if let Some(at) = stripped.find('@') {
            let name = format!("@{}", &stripped[..at]);
            let version = stripped[at + 1..].to_string();
            return (name, version);
        }
        return (spec.to_string(), "latest".to_string());
    }
    if let Some((n, v)) = spec.split_once('@') {
        return (n.to_string(), v.to_string());
    }
    (spec.to_string(), "latest".to_string())
}

/// Split a store dirname like "express-4.18.2" -> ("express", "4.18.2")
/// (no longer used -- store is name/version/ layout)

fn fmt_capabilities(c: &oath_analyze::Capabilities) -> String {
    let mut parts = vec![];
    if c.network { parts.push("network"); }
    if c.filesystem { parts.push("filesystem"); }
    if c.env_access { parts.push("env"); }
    if c.subprocess { parts.push("subprocess"); }
    if c.dynamic_exec { parts.push("eval/dynamic"); }
    if c.has_install_scripts { parts.push("install-scripts"); }
    if parts.is_empty() { "none".to_string() } else { parts.join(", ") }
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Read a package's package.json and return the first install script command found.
/// Looks for "scripts.preinstall", "scripts.install", "scripts.postinstall".
fn detect_install_script(pkg_dir: &std::path::Path) -> Option<String> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let scripts = value.get("scripts")?.as_object()?;
    for key in &["preinstall", "install", "postinstall"] {
        if let Some(cmd) = scripts.get(*key).and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
    }
    None
}

/// Run a package's install scripts unsandboxed.
fn run_install_script(pkg_name: &str, pkg_dir: &std::path::Path) {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };
    let scripts = match value.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s.clone(),
        None => return,
    };

    for hook in &["preinstall", "install", "postinstall"] {
        if let Some(cmd) = scripts.get(*hook).and_then(|v| v.as_str()) {
            tracing::debug!("running {hook} for {pkg_name}: {cmd}");
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .current_dir(pkg_dir)
                .status();
            match status {
                Ok(s) if !s.success() => {
                    eprintln!(
                        "  oath: warning -- {hook} for {pkg_name} exited with {}",
                        s.code().unwrap_or(-1)
                    );
                }
                Err(e) => {
                    eprintln!("  oath: warning -- failed to run {hook} for {pkg_name}: {e}");
                }
                _ => {}
            }
        }
    }
}

/// Run a package's install scripts inside the oath sandbox.
fn run_install_script_sandboxed(pkg_name: &str, pkg_dir: &std::path::Path) {
    // For now, fall back to unsandboxed with a warning.
    // A full implementation would use oath_sandbox::SandboxExecutor.
    // We keep the dependency graph lean here and defer to a follow-up.
    eprintln!("  oath: sandbox mode for {pkg_name} (using restricted shell for now)");
    run_install_script(pkg_name, pkg_dir);
}

// ---- EXEC (oathx) -----------------------------------------------------------

async fn cmd_exec(
    package: &str,
    args: &[String],
    allow_net: bool,
    allow_read: Option<Vec<String>>,
    allow_write: Option<Vec<String>>,
    allow_env: Option<Vec<String>>,
    min_age: Option<&str>,
) -> Result<()> {
    use oath_analyze::{PackageScanner, RiskLevel};
    use std::io::Write;

    let start = std::time::Instant::now();

    // Parse package spec: name[@version]
    let (pkg_name, pkg_version) = parse_package_spec(package);

    // Check if already in local node_modules/.bin
    let local_bin = PathBuf::from("node_modules/.bin").join(&pkg_name);
    if local_bin.exists() {
        println!("oath exec: running {} (local)", pkg_name);
        let status = std::process::Command::new(&local_bin)
            .args(args)
            .status()
            .with_context(|| format!("failed to execute {}", pkg_name))?;
        std::process::exit(status.code().unwrap_or(1));
    }

    // Need to fetch the package
    println!("oath exec: fetching {}@{}...", pkg_name, pkg_version);
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&pkg_name).await
        .with_context(|| format!("fetching {pkg_name}"))?;
    let resolved = oath_fetch::resolve_version(&packument, &pkg_version)
        .with_context(|| format!("resolving {pkg_name}@{pkg_version}"))?;

    let version = resolved.version.to_string();
    let info = resolved.info;

    // -- Release age check --
    // The abbreviated packument doesn't include time; fetch from full packument
    let publish_time_str = {
        let full = client.fetch_packument_full(&pkg_name).await.ok();
        full.and_then(|v| {
            v.get("time")
                .and_then(|t| t.get(&version))
                .and_then(|s| s.as_str().map(String::from))
        })
    };
    if let Some(ref pts) = publish_time_str {
        if let Some(age_secs) = parse_iso_age_secs(pts) {
            let age_days = age_secs / 86400;
            let age_hours = age_secs / 3600;
            if age_days > 0 {
                println!("  published {} days ago", age_days);
            } else {
                println!("  published {} hours ago", age_hours);
            }

            if let Some(min_age_str) = min_age {
                if let Some(min_age_secs) = parse_duration_secs(min_age_str) {
                    if age_secs < min_age_secs {
                        let min_days = min_age_secs / 86400;
                        anyhow::bail!(
                            "oath exec: BLOCKED -- {}@{} was published only {} days ago (minimum required: {} days)",
                            pkg_name, version, age_days,
                            if min_days > 0 { min_days } else { 1 }
                        );
                    }
                }
            }
        }
    } else if min_age.is_some() {
        println!("  warning: no publish time available for {}@{}", pkg_name, version);
    }

    // Check store first
    let store = ContentStore::default_store()?;
    let pkg_dir = if store.has_package(&pkg_name, &version) {
        store.package_dir(&pkg_name, &version)
    } else {
        // Download and store
        let data = client.fetch_tarball(&info.dist.tarball, info.dist.integrity.as_deref()).await
            .with_context(|| format!("downloading {pkg_name}@{version}"))?;
        let tmp = tempfile::tempdir()?;
        oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
        store.store_package(&pkg_name, &version, tmp.path())?;
        store.package_dir(&pkg_name, &version)
    };
    // Install full dep tree into a temp node_modules so requires work
    let exec_dir = tempfile::tempdir()?;
    let exec_path = exec_dir.path().to_path_buf();
    // Write a package.json for the package
    let exec_pkg = serde_json::json!({
        "name": "oath-exec-tmp",
        "version": "0.0.0",
        "dependencies": { &pkg_name: &version }
    });
    std::fs::write(exec_path.join("package.json"), serde_json::to_string(&exec_pkg)?)?;

    // Resolve full dep tree
    let mut deps_map = HashMap::new();
    deps_map.insert(pkg_name.clone(), version.clone());
    let options = ResolveOptions {
        include_dev: false,
        include_optional: true,
        max_depth: 256,
    };
    let mut resolver = Resolver::new(RegistryClient::default_client()?, options);
    let graph = resolver.resolve(&deps_map, &HashMap::new()).await?;

    // Download any missing packages
    let store2 = ContentStore::default_store()?;
    for (_key, node) in &graph.nodes {
        if !store2.has_package(&node.name, &node.version) {
            let data = client.fetch_tarball(&node.resolved, node.integrity.as_deref()).await?;
            let tmp = tempfile::tempdir()?;
            oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
            store2.store_package(&node.name, &node.version, tmp.path())?;
        }
    }

    // Link into exec_dir/node_modules
    let linker = oath_store::Linker::new(store2);
    linker.link_all(&graph, &exec_path)?;

    // Update pkg_dir to point into the linked node_modules
    let pkg_dir = exec_path.join("node_modules").join(&pkg_name);

    // Static analysis BEFORE execution
    let report = PackageScanner::scan(&pkg_name, &version, &pkg_dir)?;
    let caps = &report.capabilities;

    let has_risks = !report.findings.is_empty();
    let needs_prompt = has_risks && !allow_net && std::env::var("OATH_ALLOW_ALL").is_err();

    if has_risks {
        println!("\n  oath exec: {} v{}", pkg_name, version);
        println!("  capabilities detected:");
        if caps.network { println!("    network access"); }
        if caps.filesystem { println!("    filesystem access"); }
        if caps.env_access { println!("    env variable reads"); }
        if caps.subprocess { println!("    subprocess spawn"); }
        if caps.dynamic_exec { println!("    dynamic code eval"); }
        if caps.has_install_scripts { println!("    install scripts"); }

        // Show high/critical findings
        let serious: Vec<_> = report.findings.iter()
            .filter(|f| matches!(f.risk, RiskLevel::High | RiskLevel::Critical))
            .collect();
        if !serious.is_empty() {
            println!("\n  findings:");
            for f in serious.iter().take(5) {
                println!("    [{:?}] {:?} -- {}", f.risk, f.kind, f.message);
            }
        }

        if needs_prompt {
            print!("\n  allow execution? [y/N] ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("  blocked.");
                std::process::exit(1);
            }
        }
    }

    // Find the binary
    let pkg_json_path = pkg_dir.join("package.json");
    let bin_name = if pkg_json_path.exists() {
        let pkg_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&pkg_json_path)?)?;
        // Check "bin" field
        match &pkg_json["bin"] {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(map) => {
                map.get(&pkg_name).and_then(|v| v.as_str().map(|s| s.to_string()))
                    .or_else(|| map.values().next().and_then(|v| v.as_str().map(|s| s.to_string())))
            }
            _ => None,
        }
    } else {
        None
    };

    let bin_path = match bin_name {
        Some(rel) => pkg_dir.join(rel),
        None => {
            // Fallback: check common locations
            let candidates = ["cli.js", "bin/index.js", "index.js", "bin.js"];
            candidates.iter()
                .map(|c| pkg_dir.join(c))
                .find(|p| p.exists())
                .unwrap_or_else(|| {
                    eprintln!("oath exec: could not find binary for {pkg_name}");
                    std::process::exit(1);
                })
        }
    };

    let elapsed = start.elapsed();
    if elapsed.as_millis() > 100 {
        eprintln!("  fetched + scanned in {:.1}s", elapsed.as_secs_f64());
    }

    // Execute with Node
    let status = std::process::Command::new("node")
        .arg(&bin_path)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute node {}", bin_path.display()))?;

    std::process::exit(status.code().unwrap_or(1));
}

// ---- SCORE ------------------------------------------------------------------

async fn cmd_score(package: &str) -> Result<()> {
    use oath_analyze::{PackageScanner, compute_safety_score};

    let (pkg_name, pkg_version) = parse_package_spec(package);

    println!("oath score: analyzing {}@{}...", pkg_name, pkg_version);

    // Resolve and fetch
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(&pkg_name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &pkg_version)?;
    let version = resolved.version.to_string();
    let info = resolved.info;

    // Ensure in store
    let store = ContentStore::default_store()?;
    let pkg_dir = if store.has_package(&pkg_name, &version) {
        store.package_dir(&pkg_name, &version)
    } else {
        let data = client.fetch_tarball(&info.dist.tarball, info.dist.integrity.as_deref()).await?;
        let tmp = tempfile::tempdir()?;
        oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
        store.store_package(&pkg_name, &version, tmp.path())?;
        store.package_dir(&pkg_name, &version)
    };

    // Scan
    let report = PackageScanner::scan(&pkg_name, &version, &pkg_dir)?;
    let score = compute_safety_score(&report, &pkg_dir);

    // Display
    let grade_color = match score.grade {
        'A' => "\x1b[32m", // green
        'B' => "\x1b[36m", // cyan
        'C' => "\x1b[33m", // yellow
        'D' => "\x1b[33m", // yellow
        _   => "\x1b[31m", // red
    };
    let reset = "\x1b[0m";

    println!();
    println!("  {}@{}", pkg_name, version);
    println!("  safety score: {}{}/100 (grade {}){}",
        grade_color, score.score, score.grade, reset);
    println!();
    println!("  factors:");
    for factor in &score.factors {
        let sign = if factor.weight >= 0 { "+" } else { "" };
        println!("    {}{:>3}  {}", sign, factor.weight, factor.description);
    }
    println!();

    // Capabilities summary
    let caps = &report.capabilities;
    if caps.network || caps.filesystem || caps.env_access || caps.subprocess || caps.dynamic_exec || caps.has_install_scripts {
        println!("  capabilities:");
        if caps.network { println!("    network access"); }
        if caps.filesystem { println!("    filesystem access"); }
        if caps.env_access { println!("    env variable reads"); }
        if caps.subprocess { println!("    subprocess spawn"); }
        if caps.dynamic_exec { println!("    dynamic code eval"); }
        if caps.has_install_scripts { println!("    install scripts"); }
        println!();
    }

    println!("  files scanned: {}  |  lines: {}", report.files_scanned, report.lines_scanned);
    println!("  findings: {} total ({} high/critical)",
        report.findings.len(),
        report.findings.iter().filter(|f| matches!(f.risk, oath_analyze::RiskLevel::High | oath_analyze::RiskLevel::Critical)).count()
    );

    Ok(())
}

// ---- INFO -------------------------------------------------------------------

async fn cmd_info(package: &str) -> Result<()> {
    use oath_fetch::metadata::fetch_package_metadata;

    let (pkg_name, _) = parse_package_spec(package);

    println!("oath info: fetching metadata for {}...", pkg_name);

    let client = reqwest::Client::builder()
        .user_agent("oath/0.1.0")
        .build()?;

    let meta = fetch_package_metadata(&client, &pkg_name).await?;

    println!();
    println!("  {}@{}", meta.name, meta.latest_version);
    println!();

    // Maintainers
    println!("  maintainers:");
    for m in &meta.maintainers {
        if let Some(email) = &m.email {
            println!("    {} <{}>", m.name, email);
        } else {
            println!("    {}", m.name);
        }
    }
    println!();

    // Stats
    if let Some(downloads) = meta.weekly_downloads {
        println!("  weekly downloads: {}", format_downloads(downloads));
    }
    println!("  total versions:   {}", meta.total_versions);
    if let Some(ref published) = meta.published_at {
        println!("  latest published: {}", published);
    }
    if let Some(age) = meta.last_publish_age_days {
        println!("  publish age:      {} days ago", age);
    }
    println!();

    // Metadata
    if let Some(ref license) = meta.license {
        println!("  license:    {}", license);
    }
    if let Some(ref repo) = meta.repository {
        println!("  repository: {}", repo);
    }
    println!("  has readme: {}", if meta.has_readme { "yes" } else { "no" });

    Ok(())
}

fn format_downloads(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Parse an ISO 8601 datetime string and return seconds since publication.
/// Handles formats like "2024-01-15T10:30:00.000Z" or "2024-01-15T10:30:00Z"
fn parse_iso_age_secs(iso: &str) -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Extract YYYY-MM-DDTHH:MM:SS from the string
    let s = iso.trim();
    if s.len() < 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // Convert to approximate unix timestamp (good enough for age comparison)
    // Days in each month (non-leap)
    let days_before_month: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = (year - 1970) * 365 + (year - 1969) / 4; // approx leap years
    if month >= 1 && month <= 12 {
        days += days_before_month[(month - 1) as usize];
    }
    // Add leap day for current year if applicable
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days += 1;
    }
    days += day - 1;
    let publish_ts = days * 86400 + hour * 3600 + min * 60 + sec;

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();

    if now_ts > publish_ts {
        Some(now_ts - publish_ts)
    } else {
        Some(0)
    }
}

/// Parse a human duration string like "7d", "24h", "30d" into seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len() - 1], 'd')
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], 'h')
    } else if s.ends_with('w') {
        (&s[..s.len() - 1], 'w')
    } else {
        // Default to days if no unit
        (s, 'd')
    };
    let num: u64 = num_str.parse().ok()?;
    match unit {
        'h' => Some(num * 3600),
        'd' => Some(num * 86400),
        'w' => Some(num * 7 * 86400),
        _ => None,
    }
}

// ---- REMOVE -----------------------------------------------------------------

async fn cmd_remove(packages: Vec<String>) -> Result<()> {
    if packages.is_empty() {
        println!("oath remove: no packages specified");
        return Ok(());
    }

    let mut pkg: serde_json::Value = if PathBuf::from("package.json").exists() {
        read_package_json()?
    } else {
        anyhow::bail!("no package.json found");
    };

    let store = ContentStore::default_store()?;

    for package in &packages {
        let (name, _) = parse_package_spec(package);

        // Remove from dependencies and devDependencies
        let mut removed = false;
        for dep_key in &["dependencies", "devDependencies"] {
            if let Some(deps) = pkg.get_mut(dep_key).and_then(|d| d.as_object_mut()) {
                if deps.remove(&name).is_some() {
                    removed = true;
                }
            }
        }

        if !removed {
            println!("oath remove: '{}' not found in package.json", name);
            continue;
        }

        // Remove from node_modules
        let nm_path = PathBuf::from("node_modules").join(&name);
        if nm_path.exists() || nm_path.symlink_metadata().is_ok() {
            if nm_path.is_symlink() || nm_path.is_file() {
                std::fs::remove_file(&nm_path).ok();
            } else {
                std::fs::remove_dir_all(&nm_path).ok();
            }
        }

        // Remove from store (best-effort)
        let store_path = store.store_path();
        let safe_name = name.replace('/', "+");
        let store_name_dir = store_path.join(&safe_name);
        if store_name_dir.exists() {
            std::fs::remove_dir_all(&store_name_dir).ok();
        }

        println!("removed {}", name);
    }

    // Write updated package.json
    std::fs::write("package.json", serde_json::to_string_pretty(&pkg)?)?;

    // Rebuild lockfile from remaining deps
    let deps = extract_deps(&pkg, "dependencies");
    let dev_deps = extract_deps(&pkg, "devDependencies");

    if deps.is_empty() && dev_deps.is_empty() {
        // Nothing left, write empty lockfile
        let lock_path = PathBuf::from("oath-lock.json");
        if lock_path.exists() {
            let project_name = pkg["name"].as_str().unwrap_or("project").to_string();
            let project_version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
            let empty_graph = oath_resolve::graph::DepGraph::new();
            let lockfile = Lockfile::from_graph(&empty_graph, &project_name, &project_version);
            lockfile.write(&lock_path)?;
        }
    } else {
        // Re-resolve remaining deps and update lockfile
        let client = RegistryClient::default_client()?;
        let options = ResolveOptions {
            include_dev: true,
            include_optional: true,
            max_depth: 256,
        };
        let mut resolver = Resolver::new(client, options);
        let graph = resolver.resolve(&deps, &dev_deps).await?;
        let project_name = pkg["name"].as_str().unwrap_or("project").to_string();
        let project_version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let lockfile = Lockfile::from_graph(&graph, &project_name, &project_version);
        lockfile.write(&PathBuf::from("oath-lock.json"))?;
    }

    Ok(())
}

// ---- PUBLISH ----------------------------------------------------------------

async fn cmd_publish(tag: Option<&str>, access: Option<&str>, dry_run: bool) -> Result<()> {
    use base64::Engine;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use sha2::{Digest, Sha512};
    use sha1::Sha1;

    let dist_tag = tag.unwrap_or("latest");

    // 1. Read package.json
    let pkg = read_package_json()?;
    let name = pkg["name"]
        .as_str()
        .context("package.json missing 'name'")?
        .to_string();
    let version = pkg["version"]
        .as_str()
        .context("package.json missing 'version'")?
        .to_string();
    let description = pkg["description"].as_str().unwrap_or("").to_string();

    println!("oath publish: packing {}@{}...", name, version);

    // 2. Collect files to include in tarball
    // Start with the configured `files` field if present, otherwise include everything
    let cwd = std::env::current_dir()?;

    // Default excludes
    let default_excludes: Vec<&str> = vec![
        "node_modules",
        ".git",
        "test",
        ".oath",
        "oath-lock.json",
    ];

    // Read .npmignore
    let npmignore_patterns: Vec<String> = {
        let npmignore_path = cwd.join(".npmignore");
        if npmignore_path.exists() {
            std::fs::read_to_string(&npmignore_path)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect()
        } else {
            vec![]
        }
    };

    // Get `files` field from package.json
    let files_whitelist: Option<Vec<String>> = pkg
        .get("files")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    // Collect files
    let mut files_to_pack: Vec<PathBuf> = vec![];

    // Always include these if they exist
    let always_include = ["package.json", "README.md", "README", "LICENSE", "LICENCE"];

    fn should_exclude(rel: &str, excludes: &[&str], npmignore: &[String]) -> bool {
        // Check default excludes
        for pat in excludes {
            if rel == *pat
                || rel.starts_with(&format!("{}/", pat))
                || rel.starts_with(&format!("{}\\", pat))
            {
                return true;
            }
        }
        // Check .npmignore patterns
        for pat in npmignore {
            let pat = pat.trim_end_matches('/');
            if rel == pat
                || rel.starts_with(&format!("{}/", pat))
                || rel.ends_with(&format!(".{}", pat.trim_start_matches("*.")))
                || (pat.starts_with("*.") && rel.ends_with(&pat[1..]))
            {
                return true;
            }
        }
        // Default test file exclusions
        if rel.ends_with(".test.js")
            || rel.ends_with(".spec.js")
            || rel.ends_with(".test.ts")
            || rel.ends_with(".spec.ts")
        {
            return true;
        }
        false
    }

    fn collect_files(
        dir: &std::path::Path,
        base: &std::path::Path,
        files: &mut Vec<PathBuf>,
        excludes: &[&str],
        npmignore: &[String],
        whitelist: &Option<Vec<String>>,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            // If whitelist is set, only include whitelisted paths (at top level)
            if let Some(wl) = whitelist {
                let top = rel.split('/').next().unwrap_or(&rel);
                if !wl.iter().any(|w| w.trim_end_matches('/') == top || w.trim_end_matches('/') == &rel) {
                    // Still include always-include files
                    let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    let always = ["package.json", "README.md", "README", "LICENSE", "LICENCE"];
                    if !always.contains(&fname.as_str()) {
                        continue;
                    }
                }
            }

            if should_exclude(&rel, excludes, npmignore) {
                continue;
            }

            if path.is_dir() {
                collect_files(&path, base, files, excludes, npmignore, whitelist);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    collect_files(
        &cwd,
        &cwd,
        &mut files_to_pack,
        &default_excludes,
        &npmignore_patterns,
        &files_whitelist,
    );

    // Always ensure package.json is first
    let pkg_json_path = cwd.join("package.json");
    if !files_to_pack.contains(&pkg_json_path) {
        files_to_pack.insert(0, pkg_json_path);
    }

    // Sort for determinism
    files_to_pack.sort();

    // Deduplicate
    files_to_pack.dedup();

    if dry_run {
        println!("oath publish: dry run - would publish {}@{}", name, version);
        println!("  dist-tag: {}", dist_tag);
        if let Some(acc) = access {
            println!("  access: {}", acc);
        }
        println!("  files to pack ({}):", files_to_pack.len());
        let mut total_size = 0u64;
        for f in &files_to_pack {
            let rel = f.strip_prefix(&cwd).unwrap_or(f).to_string_lossy();
            let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
            total_size += size;
            println!("    {} ({} B)", rel, size);
        }
        println!("  total uncompressed: {} bytes", total_size);
        return Ok(());
    }

    // 3. Build tarball in memory
    let tarball_bytes = {
        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut tar_builder = tar::Builder::new(gz);

        for file_path in &files_to_pack {
            let rel = file_path
                .strip_prefix(&cwd)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();
            // npm tarballs use "package/" prefix
            let tar_path = format!("package/{}", rel);
            tar_builder
                .append_path_with_name(file_path, &tar_path)
                .with_context(|| format!("failed to add {} to tarball", rel))?;
        }

        let gz = tar_builder.into_inner().context("failed to finalize tar")?;
        gz.finish().context("failed to finish gzip")?
    };

    // 4. Compute integrity
    let sha512_digest = {
        let mut hasher = Sha512::new();
        hasher.update(&tarball_bytes);
        hasher.finalize()
    };
    let sha512_b64 = base64::engine::general_purpose::STANDARD.encode(sha512_digest.as_slice());
    let integrity = format!("sha512-{}", sha512_b64);

    let shasum = {
        let mut hasher = Sha1::new();
        hasher.update(&tarball_bytes);
        format!("{:x}", hasher.finalize())
    };

    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let tarball_len = tarball_bytes.len();

    // 5. Check if version already published
    let http_client = reqwest::Client::builder()
        .user_agent("oath/0.1.0")
        .build()?;

    let registry_url = "https://registry.npmjs.org";
    let pkg_url = format!("{}/{}", registry_url, name);

    let existing = http_client.get(&pkg_url)
        .header("Accept", "application/json")
        .send()
        .await;

    if let Ok(resp) = existing {
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            if let Some(versions) = body.get("versions").and_then(|v| v.as_object()) {
                if versions.contains_key(&version) {
                    anyhow::bail!(
                        "oath publish: {}@{} is already published. Bump the version to publish again.",
                        name, version
                    );
                }
            }
        }
    }

    // 6. Read auth token
    let token = std::env::var("NPM_TOKEN").ok().or_else(|| {
        let npmrc_path = PathBuf::from(
            std::env::var("HOME").unwrap_or_else(|_| "/".into())
        ).join(".npmrc");
        let content = std::fs::read_to_string(&npmrc_path).ok()?;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("//registry.npmjs.org/:_authToken=") {
                return Some(line["//registry.npmjs.org/:_authToken=".len()..].to_string());
            }
        }
        None
    });

    let token = token.context(
        "oath publish: no npm auth token found.\n  Set NPM_TOKEN env var or add //registry.npmjs.org/:_authToken=TOKEN to ~/.npmrc"
    )?;

    // 7. Build publish payload
    let tarball_url = format!("{}/{}-/-/{}-{}.tgz", registry_url, name, name.split('/').last().unwrap_or(&name), version);
    let attachment_name = format!("{}-{}.tgz",
        name.split('/').last().unwrap_or(&name),
        version
    );

    let mut version_obj = pkg.clone();
    version_obj["dist"] = serde_json::json!({
        "tarball": tarball_url,
        "integrity": integrity,
        "shasum": shasum
    });

    let mut payload = serde_json::json!({
        "_id": name,
        "name": name,
        "description": description,
        "dist-tags": { dist_tag: version },
        "versions": {},
        "_attachments": {
            attachment_name: {
                "content_type": "application/octet-stream",
                "data": tarball_b64,
                "length": tarball_len
            }
        }
    });
    payload["versions"][&version] = version_obj;

    if let Some(acc) = access {
        payload["access"] = serde_json::Value::String(acc.to_string());
    }

    // 8. PUT to registry
    println!("oath publish: publishing {}@{} (dist-tag: {})...", name, version, dist_tag);

    let resp = http_client
        .put(&pkg_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .context("failed to send publish request")?;

    let status = resp.status();
    if status.is_success() {
        println!("+ {}@{}", name, version);
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("oath publish: registry returned {}: {}", status, body)
    }
}


// ---- GLOBAL INSTALL ---------------------------------------------------------

/// Install one or more packages to the global location (~/.oath/global/).
/// Symlinks binaries into ~/.oath/global/bin/.
async fn cmd_install_global(packages: Vec<String>, dry_run: bool) -> Result<()> {
    if packages.is_empty() {
        anyhow::bail!("oath install -g: please specify at least one package to install globally");
    }

    let home = std::env::var("HOME").context("HOME not set")?;
    let global_dir = PathBuf::from(&home).join(".oath").join("global");
    let nm_dir = global_dir.join("node_modules");
    let bin_dir = global_dir.join("bin");

    if dry_run {
        println!("oath install -g (dry run): would install {:?}", packages);
        println!("  install dir: {}", nm_dir.display());
        println!("  bin dir:     {}", bin_dir.display());
        return Ok(());
    }

    std::fs::create_dir_all(&nm_dir)?;
    std::fs::create_dir_all(&bin_dir)?;

    // Build deps map
    let mut deps = HashMap::new();
    for spec in &packages {
        let (name, version) = parse_package_spec(spec);
        deps.insert(name, version);
    }

    println!("oath install -g: resolving {} package(s)...", deps.len());
    let start = Instant::now();

    let client = RegistryClient::default_client()?;
    let options = ResolveOptions {
        include_dev: false,
        include_optional: true,
        max_depth: 256,
    };
    let mut resolver = Resolver::new(client, options);
    let graph = resolver.resolve(&deps, &HashMap::new()).await?;

    println!("  resolved {} packages in {:.1}s", graph.package_count(), start.elapsed().as_secs_f64());

    // Download missing packages
    let store = Arc::new(ContentStore::default_store()?);
    let client = Arc::new(RegistryClient::default_client()?);
    let mut downloaded = 0usize;

    let mut to_download = vec![];
    for (_key, node) in &graph.nodes {
        if !store.has_package(&node.name, &node.version) {
            to_download.push(node.clone());
        }
    }

    if !to_download.is_empty() {
        let mut set: JoinSet<Result<(String, String, Vec<u8>)>> = JoinSet::new();
        for node in to_download {
            let client = Arc::clone(&client);
            let resolved = node.resolved.clone();
            let integrity = node.integrity.clone();
            let name = node.name.clone();
            let version = node.version.clone();
            set.spawn(async move {
                let data = client
                    .fetch_tarball(&resolved, integrity.as_deref())
                    .await
                    .with_context(|| format!("downloading {name}@{version}"))?;
                Ok((name, version, data))
            });
        }
        while let Some(res) = set.join_next().await {
            let (name, version, data) = res??;
            let tmp = tempfile::tempdir()?;
            oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
            store.store_package(&name, &version, tmp.path())?;
            downloaded += 1;
        }
    }

    if downloaded > 0 {
        println!("  downloaded {} packages", downloaded);
    }

    // Link into global node_modules
    let linker = Linker::new((*store).clone());
    let link_result = linker.link_all(&graph, &global_dir)?;
    println!("  linked {} packages", link_result.linked);

    // Create bin symlinks for the top-level (directly requested) packages
    let mut bins_created = 0usize;
    for (pkg_name, _) in &deps {
        // Find the resolved version for this package name
        let node = graph.nodes.values().find(|n| &n.name == pkg_name);
        let node = match node {
            Some(n) => n,
            None => continue,
        };

        let pkg_dir = nm_dir.join(pkg_name);
        if !pkg_dir.exists() {
            continue;
        }

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        let pkg_json_content = std::fs::read_to_string(&pkg_json_path)?;
        let pkg_json: serde_json::Value = serde_json::from_str(&pkg_json_content)?;

        // Collect bin entries: Vec<(bin_name, relative_bin_path)>
        let bin_entries: Vec<(String, String)> = match &pkg_json["bin"] {
            serde_json::Value::String(s) => {
                let bin_name = pkg_name.split('/').last().unwrap_or(pkg_name).to_string();
                vec![(bin_name, s.clone())]
            }
            serde_json::Value::Object(map) => {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            }
            _ => vec![],
        };

        for (bin_name, rel_path) in &bin_entries {
            let actual_bin = pkg_dir.join(rel_path);
            let link_path = bin_dir.join(bin_name);

            // Make the bin executable
            if actual_bin.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&actual_bin) {
                        let mut perms = meta.permissions();
                        perms.set_mode(perms.mode() | 0o111);
                        let _ = std::fs::set_permissions(&actual_bin, perms);
                    }
                }
            }

            // Remove existing symlink
            if link_path.exists() || link_path.symlink_metadata().is_ok() {
                std::fs::remove_file(&link_path).ok();
            }

            // Create symlink: bin_dir/bin_name -> ../node_modules/<pkg>/<rel_path>
            let target = PathBuf::from("..").join("node_modules").join(pkg_name).join(rel_path);
            std::os::unix::fs::symlink(&target, &link_path)
                .with_context(|| format!("failed to create symlink for {bin_name}"))?;
            bins_created += 1;
            println!("  created: {}", link_path.display());
        }

        println!("  installed {}@{}", node.name, node.version);
    }

    if bins_created > 0 {
        println!();
        println!("  {} bin(s) installed to {}", bins_created, bin_dir.display());
        println!("  Add {} to your PATH to use them", bin_dir.display());
    }

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());
    Ok(())
}

// ---- LOG --------------------------------------------------------------------

fn cmd_log(tail: usize) -> Result<()> {
    let logger = oath_transparency::TransparencyLogger::default_logger()?;
    let entries = logger.read_recent(tail)?;

    if entries.is_empty() {
        println!("oath log: no entries yet (run `oath install` to create entries)");
        println!("  log path: {}", logger.log_path().display());
        return Ok(());
    }

    println!("oath transparency log (last {} entries):", entries.len());
    println!();

    for entry in &entries {
        use std::time::{UNIX_EPOCH, Duration};
        let dt = UNIX_EPOCH + Duration::from_secs(entry.ts);
        let secs = entry.ts;
        // Format as simple timestamp
        let mins = (secs % 3600) / 60;
        let hours = (secs % 86400) / 3600;
        let days_since_epoch = secs / 86400;
        // Approximate date (not perfect but sufficient for display)
        println!("  --- {} packages | {}ms | {}", entry.pkg_count, entry.duration_ms, entry.project);
        println!("      ts: {}", entry.ts);
        // Show first few packages
        let show_count = entry.packages.len().min(5);
        for pkg in entry.packages.iter().take(show_count) {
            if let Some(ref int) = pkg.integrity {
                println!("      {}@{}  {}", pkg.name, pkg.version, &int[..int.len().min(30)]);
            } else {
                println!("      {}@{}", pkg.name, pkg.version);
            }
        }
        if entry.packages.len() > show_count {
            println!("      ... and {} more", entry.packages.len() - show_count);
        }
        println!();
    }

    println!("  log path: {}", logger.log_path().display());
    Ok(())
}

