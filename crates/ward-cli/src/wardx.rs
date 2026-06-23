use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wardx", version, about = "Execute packages in a secure sandbox")]
struct Cli {
    /// Package to execute
    package: String,

    /// Arguments to pass
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,

    /// Grant network access (optionally scoped: --allow-net=example.com)
    #[arg(long)]
    allow_net: Option<Option<String>>,

    /// Grant filesystem read access (optionally scoped: --allow-read=./src)
    #[arg(long)]
    allow_read: Option<Option<String>>,

    /// Grant filesystem write access
    #[arg(long)]
    allow_write: Option<Option<String>>,

    /// Grant environment variable access
    #[arg(long)]
    allow_env: Option<Option<String>>,

    /// Grant all permissions (equivalent to npx behavior -- UNSAFE)
    #[arg(short = 'A', long)]
    allow_all: bool,

    /// Trust the package's declared permissions without prompting
    #[arg(long)]
    trust: bool,

    /// Show what permissions would be requested without executing
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.dry_run {
        println!("wardx: {}", cli.package);
        println!("  declared permissions:");
        println!("    (would fetch manifest and display)");
        return Ok(());
    }

    if cli.allow_all {
        eprintln!("wardx: WARNING -- running with all permissions (no sandbox)");
    }

    println!("wardx: resolving {}...", cli.package);
    println!("wardx: sandbox active");

    // TODO: resolve package -> fetch -> sandbox -> execute

    Ok(())
}
