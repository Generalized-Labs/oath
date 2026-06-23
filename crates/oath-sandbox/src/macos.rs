//! macOS sandbox-exec profile generation
//!
//! Uses Apple's Seatbelt (sandbox-exec) to restrict processes.
//! This is the same tech macOS uses for App Sandbox.

use crate::policy::{Permission, SandboxPolicy};
use std::path::PathBuf;

/// Build a sandbox-exec profile (Scheme-like DSL) from an oath policy
pub fn build_profile(policy: &SandboxPolicy) -> String {
    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        // Always allow process execution of the binary itself
        "(allow process-exec)".to_string(),
        "(allow process-fork)".to_string(),
        // Allow sysctl (node needs this)
        "(allow sysctl-read)".to_string(),
        // Allow mach lookups (IPC, needed for basic process operation)
        "(allow mach-lookup)".to_string(),
        // Allow signal handling
        "(allow signal (target self))".to_string(),
    ];

    // Filesystem reads
    let mut read_paths: Vec<PathBuf> = vec![
        // Always allow reading system libs and node itself
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/opt/homebrew"),
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/urandom"),
        PathBuf::from("/dev/random"),
        // Allow reading the workdir by default
        policy.workdir.clone(),
    ];

    // Node.js needs to read its own binary and modules
    if let Ok(node_path) = which_node() {
        read_paths.push(node_path.clone());
        // Allow reading the node_modules in the store
        if let Ok(home) = std::env::var("HOME") {
            read_paths.push(PathBuf::from(&home).join(".oath"));
            read_paths.push(PathBuf::from(&home).join(".node"));
            read_paths.push(PathBuf::from(&home).join(".nvm"));
            read_paths.push(PathBuf::from(&home).join(".volta"));
        }
    }

    for perm in &policy.permissions {
        match perm {
            Permission::ReadFs(paths) => {
                for p in paths {
                    read_paths.push(p.clone());
                }
            }
            Permission::Unrestricted => {
                return "(version 1)\n(allow default)\n".to_string();
            }
            _ => {}
        }
    }

    // Deduplicate and emit read rules
    read_paths.sort();
    read_paths.dedup();
    for path in &read_paths {
        let p = path.display();
        lines.push(format!(
            "(allow file-read* (subpath \"{p}\"))"
        ));
    }

    // Filesystem writes
    let mut write_paths: Vec<PathBuf> = vec![
        PathBuf::from("/dev/null"),
    ];
    // Allow writing to tmp (many tools need this)
    if let Ok(tmp) = std::env::var("TMPDIR") {
        write_paths.push(PathBuf::from(tmp));
    }
    write_paths.push(PathBuf::from("/tmp"));
    write_paths.push(PathBuf::from("/private/tmp"));

    for perm in &policy.permissions {
        if let Permission::WriteFs(paths) = perm {
            for p in paths {
                write_paths.push(p.clone());
            }
        }
    }

    write_paths.sort();
    write_paths.dedup();
    for path in &write_paths {
        let p = path.display();
        lines.push(format!(
            "(allow file-write* (subpath \"{p}\"))"
        ));
    }

    // Network
    if policy.allows_network() {
        lines.push("(allow network*)".to_string());
    }

    // Environment (sandbox-exec doesn't directly control env, but we strip them in executor)

    lines.join("\n") + "\n"
}

/// Find the node binary path
fn which_node() -> Result<PathBuf, ()> {
    let output = std::process::Command::new("which")
        .arg("node")
        .output()
        .map_err(|_| ())?;
    if output.status.success() {
        let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(PathBuf::from(p))
    } else {
        Err(())
    }
}

/// Check if we're running on macOS AND sandbox-exec works with restrictions
pub fn is_available() -> bool {
    // sandbox-exec with deny-default profiles crashes on macOS 15+ (Sonoma)
    // Apple deprecated Seatbelt; restrict profiles abort. Only (allow default) works.
    // Until Apple ships a replacement API, we fall back to env-stripping + timeout.
    false
}
