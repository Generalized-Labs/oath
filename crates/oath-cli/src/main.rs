use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use oath_fetch::RegistryClient;
use oath_resolve::resolver::{ResolveOptions, Resolver};
use oath_resolve::Lockfile;
use oath_store::cas::ContentStore;
use oath_store::linker::Linker;

#[derive(Parser)]
#[command(name = "oath", version, about = "Secure package management for the JavaScript ecosystem")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install dependencies from package.json
    Install {
        /// Specific packages to install (if empty, reads package.json)
        packages: Vec<String>,
        /// Save as dev dependency
        #[arg(short = 'D', long)]
        dev: bool,
        /// Skip linking (resolve only)
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a dependency
    Add {
        /// Package specifier (name or name@version)
        package: String,
        #[arg(short = 'D', long)]
        dev: bool,
    },
    /// Remove a dependency
    Remove {
        packages: Vec<String>,
    },
    /// Run a script defined in package.json
    Run {
        script: String,
        /// Arguments to pass to the script
        args: Vec<String>,
    },
    /// Execute a package binary (like npx, but sandboxed)
    Exec {
        /// Package to execute
        package: String,
        /// Arguments
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Grant network access
        #[arg(long)]
        allow_net: bool,
        /// Grant filesystem read access
        #[arg(long)]
        allow_read: Option<Vec<String>>,
        /// Grant filesystem write access
        #[arg(long)]
        allow_write: Option<Vec<String>>,
        /// Grant environment variable access
        #[arg(long)]
        allow_env: Option<Vec<String>>,
    },
    /// Audit dependencies for vulnerabilities and malicious behavior
    Audit {
        /// Only audit production dependencies
        #[arg(long)]
        production: bool,
    },
    /// Show package permissions/capabilities
    Perms {
        /// Package name
        package: String,
    },
    /// Verify package integrity against transparency log
    Verify {
        /// Package specifier
        package: Option<String>,
        /// Verify entire lockfile
        #[arg(long)]
        all: bool,
    },
    /// Initialize a new project
    Init {
        /// Project name
        name: Option<String>,
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
        Commands::Install { packages, dev, dry_run } => {
            cmd_install(packages, dev, dry_run).await?;
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
        Commands::Audit { production } => {
            let scope = if production { "production" } else { "all" };
            println!("oath audit: scanning {scope} dependencies...");
            println!("  (behavioral analysis not yet implemented)");
        }
        Commands::Perms { package } => {
            println!("oath perms: {package}");
            println!("  (not yet implemented)");
        }
        Commands::Verify { package, all } => {
            if all {
                println!("oath verify: checking all lockfile entries...");
            } else if let Some(pkg) = package {
                println!("oath verify: checking {pkg}...");
            }
            println!("  (transparency log not yet implemented)");
        }
        _ => {
            println!("oath: command not yet implemented");
        }
    }

    Ok(())
}

/// Read package.json from the current directory
fn read_package_json() -> Result<serde_json::Value> {
    let path = PathBuf::from("package.json");
    let content = std::fs::read_to_string(&path).context(
        "no package.json found in current directory (run `oath init` to create one)",
    )?;
    serde_json::from_str(&content).context("failed to parse package.json")
}

/// Extract dependencies map from package.json value
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

/// oath install
async fn cmd_install(packages: Vec<String>, dev: bool, dry_run: bool) -> Result<()> {
    let start = Instant::now();

    let (deps, dev_deps, project_name, project_version) = if packages.is_empty() {
        // Read from package.json
        let pkg = read_package_json()?;
        let name = pkg["name"].as_str().unwrap_or("unnamed").to_string();
        let version = pkg["version"].as_str().unwrap_or("0.0.0").to_string();
        let deps = extract_deps(&pkg, "dependencies");
        let dev_deps = extract_deps(&pkg, "devDependencies");
        (deps, dev_deps, name, version)
    } else {
        // Install specific packages
        let mut deps = HashMap::new();
        for spec in &packages {
            let (name, version) = if let Some((n, v)) = spec.split_once('@') {
                (n.to_string(), v.to_string())
            } else {
                (spec.clone(), "latest".to_string())
            };
            deps.insert(name, version);
        }
        let dev_deps = HashMap::new();
        (deps, dev_deps, "project".to_string(), "0.0.0".to_string())
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

    // Download and store
    let download_start = Instant::now();
    let client = RegistryClient::default_client()?;
    let store = ContentStore::default_store()?;
    let mut downloaded = 0usize;
    let mut cached = 0usize;
    let mut download_bytes = 0u64;

    for (_key, node) in &graph.nodes {
        if store.has_package(&node.name, &node.version) {
            cached += 1;
            continue;
        }

        // Download tarball
        let data = client
            .fetch_tarball(&node.resolved, node.integrity.as_deref())
            .await
            .with_context(|| format!("downloading {}@{}", node.name, node.version))?;

        download_bytes += data.len() as u64;

        // Extract to temp dir, then store
        let tmp = tempfile::tempdir()?;
        oath_fetch::tarball::extract_tarball(&data, tmp.path())?;
        store.store_package(&node.name, &node.version, tmp.path())?;

        downloaded += 1;
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

    // Link into node_modules
    let link_start = Instant::now();
    let store = ContentStore::default_store()?;
    let linker = Linker::new(store);
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

    let total_time = start.elapsed();
    println!("  done in {:.1}s", total_time.as_secs_f64());

    Ok(())
}

/// oath add <package>
async fn cmd_add(package: &str, dev: bool) -> Result<()> {
    let (name, spec) = if let Some((n, v)) = package.split_once('@') {
        (n, v.to_string())
    } else {
        (package, "latest".to_string())
    };

    // Read existing package.json or create minimal one
    let mut pkg: serde_json::Value = if PathBuf::from("package.json").exists() {
        read_package_json()?
    } else {
        serde_json::json!({
            "name": "project",
            "version": "1.0.0"
        })
    };

    // Resolve to get the exact version
    let client = RegistryClient::default_client()?;
    let packument = client.fetch_packument(name).await?;
    let resolved = oath_fetch::resolve_version(&packument, &spec)?;

    let version_range = format!("^{}", resolved.version);
    let key = if dev { "devDependencies" } else { "dependencies" };

    // Add to package.json
    if pkg.get(key).is_none() {
        pkg[key] = serde_json::json!({});
    }
    pkg[key][name] = serde_json::Value::String(version_range.clone());

    // Write back
    let content = serde_json::to_string_pretty(&pkg)?;
    std::fs::write("package.json", content)?;

    println!("oath: added {name}@{} ({key})", resolved.version);

    // Run install
    cmd_install(vec![], false, false).await?;

    Ok(())
}

/// oath run <script>
fn cmd_run(script: &str, args: &[String]) -> Result<()> {
    let pkg = read_package_json()?;
    let scripts = pkg
        .get("scripts")
        .and_then(|s| s.as_object())
        .context("no scripts defined in package.json")?;

    let cmd = scripts
        .get(script)
        .and_then(|v| v.as_str())
        .with_context(|| format!("script '{script}' not found in package.json"))?;

    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };

    println!("oath run: {full_cmd}");

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .env("PATH", format!("./node_modules/.bin:{}", std::env::var("PATH").unwrap_or_default()))
        .status()
        .context("failed to execute script")?;

    std::process::exit(status.code().unwrap_or(1));
}

/// oath init
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
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1"
        },
        "keywords": [],
        "license": "MIT"
    });

    let content = serde_json::to_string_pretty(&pkg)?;
    std::fs::write("package.json", &content)?;
    println!("oath init: created package.json");
    println!("{content}");
    Ok(())
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
