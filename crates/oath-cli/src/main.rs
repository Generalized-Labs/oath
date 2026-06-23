use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;

use oath_analyze::{PackageScanner, RiskLevel};
use oath_fetch::RegistryClient;
use oath_resolve::resolver::{ResolveOptions, Resolver};
use oath_resolve::Lockfile;
use oath_store::cas::ContentStore;
use oath_store::linker::Linker;

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
        } => {
            cmd_install(packages, dev, dry_run, !no_audit).await?;
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
    cmd_install(vec![], false, false, true).await
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
