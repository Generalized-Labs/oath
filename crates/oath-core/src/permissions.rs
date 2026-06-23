//! Package capability/permission declarations
//!
//! Every package declares what system resources it needs.
//! The sandbox enforces these at runtime.

use serde::{Deserialize, Serialize};

/// Permissions declared in a package manifest
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Permissions {
    /// Network access (list of allowed hosts/patterns, empty = no network)
    #[serde(default)]
    pub net: Vec<String>,

    /// Filesystem read access (glob patterns relative to package root)
    #[serde(default)]
    pub fs_read: Vec<String>,

    /// Filesystem write access (glob patterns)
    #[serde(default)]
    pub fs_write: Vec<String>,

    /// Environment variables the package may read
    #[serde(default)]
    pub env: Vec<String>,

    /// Subprocess execution (list of allowed commands)
    #[serde(default)]
    pub run: Vec<String>,

    /// FFI / native code (dangerous -- requires explicit user approval)
    #[serde(default)]
    pub ffi: bool,

    /// Install scripts (must be explicitly declared and approved)
    #[serde(default)]
    pub install_scripts: bool,
}

impl Permissions {
    pub fn is_sandboxed(&self) -> bool {
        // A package with no permissions is fully sandboxed (pure compute)
        self.net.is_empty()
            && self.fs_read.is_empty()
            && self.fs_write.is_empty()
            && self.env.is_empty()
            && self.run.is_empty()
            && !self.ffi
            && !self.install_scripts
    }

    /// Human-readable summary of what this package can do
    pub fn summary(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.net.is_empty() {
            lines.push(format!("network: {}", self.net.join(", ")));
        }
        if !self.fs_read.is_empty() {
            lines.push(format!("read: {}", self.fs_read.join(", ")));
        }
        if !self.fs_write.is_empty() {
            lines.push(format!("write: {}", self.fs_write.join(", ")));
        }
        if !self.env.is_empty() {
            lines.push(format!("env: {}", self.env.join(", ")));
        }
        if !self.run.is_empty() {
            lines.push(format!("exec: {}", self.run.join(", ")));
        }
        if self.ffi {
            lines.push("ffi: YES (native code)".into());
        }
        if self.install_scripts {
            lines.push("install scripts: YES".into());
        }
        if lines.is_empty() {
            lines.push("pure (no system access)".into());
        }
        lines
    }
}

/// Risk level computed from permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No permissions -- pure computation
    None,
    /// Read-only filesystem or limited env
    Low,
    /// Network access or filesystem writes
    Medium,
    /// Install scripts, FFI, or unrestricted access
    High,
    /// Known malicious or flagged by behavioral analysis
    Critical,
}

impl Permissions {
    pub fn risk_level(&self) -> RiskLevel {
        if self.ffi || self.install_scripts {
            return RiskLevel::High;
        }
        if !self.net.is_empty() || !self.fs_write.is_empty() || !self.run.is_empty() {
            return RiskLevel::Medium;
        }
        if !self.fs_read.is_empty() || !self.env.is_empty() {
            return RiskLevel::Low;
        }
        RiskLevel::None
    }
}
