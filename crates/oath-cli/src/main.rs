use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "oath", version, about = "Secure package management for the JavaScript ecosystem")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install dependencies
    Install {
        /// Specific packages to install
        packages: Vec<String>,
        /// Save as dev dependency
        #[arg(short = 'D', long)]
        dev: bool,
    },
    /// Add a dependency
    Add {
        /// Package specifier (name@version)
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
        /// Output format
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Publish a package to the registry
    Publish {
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Query dependencies (CSS-like selector syntax)
    Query {
        /// Selector expression (e.g., ":risky", ":outdated > 1y")
        selector: String,
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
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install { packages, dev } => {
            if packages.is_empty() {
                println!("oath: resolving dependencies...");
            } else {
                let target = if dev { "dev" } else { "prod" };
                println!("oath: installing {} ({target})", packages.join(", "));
            }
            // TODO: wire up oath-resolve + oath-fetch + oath-store
        }
        Commands::Exec { package, args, allow_net, allow_read, allow_write, allow_env } => {
            println!("oathx: executing {package} in sandbox");
            println!("  permissions:");
            println!("    network: {}", if allow_net { "granted" } else { "DENIED" });
            println!("    fs_read: {:?}", allow_read.unwrap_or_default());
            println!("    fs_write: {:?}", allow_write.unwrap_or_default());
            println!("    env: {:?}", allow_env.unwrap_or_default());
            // TODO: wire up oath-sandbox
        }
        Commands::Audit { production, format: _ } => {
            let scope = if production { "production" } else { "all" };
            println!("oath audit: scanning {scope} dependencies...");
            // TODO: wire up oath-analyze
        }
        Commands::Verify { package, all } => {
            if all {
                println!("oath verify: checking all lockfile entries against transparency log...");
            } else if let Some(pkg) = package {
                println!("oath verify: checking {pkg} against transparency log...");
            }
            // TODO: wire up oath-index
        }
        Commands::Perms { package } => {
            println!("oath perms: capabilities declared by {package}:");
            println!("  (not yet implemented)");
            // TODO: read manifest.permissions
        }
        _ => {
            println!("oath: command not yet implemented");
        }
    }

    Ok(())
}
