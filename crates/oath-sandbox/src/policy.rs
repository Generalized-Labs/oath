//! Sandbox policy: what a package is allowed to do
//!
//! Permissions are deny-by-default. A package must declare what it needs,
//! and the user must grant it (or oathx prompts interactively).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single permission grant
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Permission {
    /// Read files under these paths
    ReadFs(Vec<PathBuf>),
    /// Write files under these paths
    WriteFs(Vec<PathBuf>),
    /// Access network (optionally restricted to hosts)
    Network(Vec<String>),
    /// Read environment variables (optionally restricted to names)
    Env(Vec<String>),
    /// Spawn subprocesses (binary names allowed)
    Subprocess(Vec<String>),
    /// Full unrestricted access (--allow-all)
    Unrestricted,
}

/// Complete sandbox policy for an execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Package name being executed
    pub package: String,
    /// Granted permissions
    pub permissions: Vec<Permission>,
    /// Working directory (the project root)
    pub workdir: PathBuf,
    /// Time limit in seconds (0 = no limit)
    pub timeout_secs: u64,
    /// Max memory in bytes (0 = no limit)
    pub max_memory: u64,
}

impl SandboxPolicy {
    /// Create a minimal policy: read project dir, nothing else
    pub fn minimal(package: &str, workdir: PathBuf) -> Self {
        Self {
            package: package.to_string(),
            permissions: vec![Permission::ReadFs(vec![workdir.clone()])],
            workdir,
            timeout_secs: 30,
            max_memory: 512 * 1024 * 1024, // 512MB
        }
    }

    /// Check if a specific permission type is granted
    pub fn allows_network(&self) -> bool {
        self.permissions.iter().any(|p| matches!(p, Permission::Network(_) | Permission::Unrestricted))
    }

    pub fn allows_write(&self, path: &std::path::Path) -> bool {
        self.permissions.iter().any(|p| match p {
            Permission::WriteFs(paths) => paths.iter().any(|allowed| path.starts_with(allowed)),
            Permission::Unrestricted => true,
            _ => false,
        })
    }

    pub fn allows_read(&self, path: &std::path::Path) -> bool {
        self.permissions.iter().any(|p| match p {
            Permission::ReadFs(paths) => paths.iter().any(|allowed| path.starts_with(allowed)),
            Permission::Unrestricted => true,
            _ => false,
        })
    }

    pub fn allows_env(&self, name: &str) -> bool {
        self.permissions.iter().any(|p| match p {
            Permission::Env(names) => names.is_empty() || names.iter().any(|n| n == name),
            Permission::Unrestricted => true,
            _ => false,
        })
    }

    pub fn allows_subprocess(&self, bin: &str) -> bool {
        self.permissions.iter().any(|p| match p {
            Permission::Subprocess(bins) => bins.is_empty() || bins.iter().any(|b| b == bin),
            Permission::Unrestricted => true,
            _ => false,
        })
    }

    /// Build the macOS sandbox-exec profile string from this policy
    pub fn to_sandbox_profile(&self) -> String {
        crate::macos::build_profile(self)
    }
}
