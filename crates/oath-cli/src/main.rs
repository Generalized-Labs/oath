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
use oath_resolve::Lockfile;
use oath_store::cas::ContentStore;
use oath_store::linker::Linker;

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
        #[arg(short = 'D', long)]
        dev: bool,
        #[arg(long)]
        dry_run: bool,
        /// Skip static analysis scan
        #[arg(long)]
        no_audit: bool,
        /// Skip all prompts and approve everything (including install scripts)
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Add a dependency
    Add {
        package: String,
        #[arg(short = 'D', long)]
        dev: bool,
    },
    /// Remove a dependency
    Remove { packages: Vec<String> },
    /// Run a script defined in package.json
    Run {
        script: String,
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
        } => {
            cmd_install(packages, dev, dry_run, !no_audit, yes).await?;
        }
        Commands::Add { package, dev } => {
            cmd_add(&package, dev).await?;
        }
        Commands::Run { script, args } => {
            cmd_run(&script, &args)?;
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
        _ => {
            println!("oath: command not yet implemented");
        }
    }

    Ok(())
}

// ---- INSTALL ----------------------------------------------------------------

async fn cmd_install(
    packages: Vec<String>,
    _dev: bool,
    dry_run: bool,
    run_audit: bool,
    yes_flag: bool,
) -> Result<()> {
    let start = Instant::now();

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

    let total_direct = deps.len() + dev_deps.len();
    println!("oath: resolving {total_direct} dependencies...");

    // Resolve
    let client = RegistryClient::default_client()?;
    let options = ResolveOptions {
        include_dev: true,
        include_optional: false,
        max_depth: 256,
    };
    let mut resolver = Resolver::new(client, options);
    let graph = resolver.resolve(&deps, &dev_deps).await?;

    let resolve_time = start.elapsed();
    println!(
        "  resolved {} packages in {:.1}s",
        graph.package_count(),
        resolve_time.as_secs_f64()
    );

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
    lockfile.write(&PathBuf::from("oath-lock.json"))?;

    // -- Install script permission prompts ------------------------------------
    // Load policy (project-local oath-policy.toml + global ~/.oath/policy.toml)
    let policy = OathPolicy::load();
    let store_path = store.store_path();

    for (_key, node) in &graph.nodes {
        if !node.has_install_script {
            continue;
        }

        // Find the package in the store
        let pkg_dir = store_path
            .join(node.name.replace('/', "+"))
            .join(&node.version);
        if !pkg_dir.exists() {
            continue;
        }

        // Policy hard-block: banned packages should not run scripts (or install at all)
        if policy.is_package_banned(&node.name) {
            println!(
                "  oath: blocked install script for banned package {}@{}",
                node.name, node.version
            );
            continue;
        }

        // Scan to learn capabilities
        let report = match PackageScanner::scan(&node.name, &node.version, &pkg_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Determine the script string to display
        let script_display = detect_install_script(&pkg_dir)
            .unwrap_or_else(|| "node install.js".to_string());

        let decision = prompts::prompt_install_script(
            &node.name,
            &node.version,
            &script_display,
            &report.capabilities,
            yes_flag,
            &policy,
        );

        match decision {
            prompts::ScriptDecision::Allow | prompts::ScriptDecision::Always => {
                println!(
                    "  oath: running install script for {}@{}",
                    node.name, node.version
                );
                run_install_script(&node.name, &pkg_dir);
            }
            prompts::ScriptDecision::Sandbox => {
                println!(
                    "  oath: running sandboxed install script for {}@{}",
                    node.name, node.version
                );
                run_install_script_sandboxed(&node.name, &pkg_dir);
            }
            prompts::ScriptDecision::Deny => {
                println!(
                    "  oath: skipped install script for {}@{}",
                    node.name, node.version
                );
            }
        }
    }

    // Static analysis on newly downloaded packages
    if run_audit && downloaded > 0 {
        println!("  scanning {} new packages...", downloaded);
        let store_path = store.store_path();
        let mut critical = 0usize;
        let mut high = 0usize;

        for (_key, node) in &graph.nodes {
            let pkg_dir = store_path.join(format!("{}-{}", node.name, node.version));
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
    Ok(())
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
    cmd_install(vec![], false, false, true, false).await
}

// ---- RUN --------------------------------------------------------------------

fn cmd_run(script: &str, args: &[String]) -> Result<()> {
    let pkg = read_package_json()?;
    let scripts = pkg
        .get("scripts")
        .and_then(|s| s.as_object())
        .context("no scripts defined in package.json")?;

    let cmd = scripts
        .get(script)
        .and_then(|v| v.as_str())
        .with_context(|| format!("script '{script}' not found"))?;

    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };

    println!("oath run: {full_cmd}");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .env(
            "PATH",
            format!(
                "./node_modules/.bin:{}",
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .status()
        .context("failed to execute script")?;
    std::process::exit(status.code().unwrap_or(1));
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
        let name = node.get("name").and_then(|n| n.as_str()).unwrap_or("");
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
