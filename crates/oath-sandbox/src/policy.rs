use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SANDBOX_PLAN_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Deny,
    Inherit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub timeout_secs: u64,
    pub max_processes: u64,
    pub max_open_files: u64,
    pub max_file_bytes: u64,
    #[serde(default = "default_max_memory_bytes")]
    pub max_memory_bytes: u64,
}

const fn default_max_memory_bytes() -> u64 {
    1024 * 1024 * 1024
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_processes: 64,
            max_open_files: 256,
            max_file_bytes: 512 * 1024 * 1024,
            max_memory_bytes: default_max_memory_bytes(),
        }
    }
}

/// Stable contract shared by assessment output, enforcement, and audit logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPlan {
    pub version: u32,
    pub package: String,
    pub workdir: PathBuf,
    pub read_only_paths: Vec<PathBuf>,
    pub writable_paths: Vec<PathBuf>,
    pub environment_allowlist: Vec<String>,
    pub network: NetworkMode,
    pub allow_subprocesses: bool,
    pub limits: ResourceLimits,
}

impl SandboxPlan {
    pub fn strict(package: impl Into<String>, workdir: PathBuf) -> Self {
        #[cfg(target_os = "windows")]
        let environment_allowlist = {
            let mut names = vec!["PATH".into(), "TERM".into()];
            names.extend(
                ["SystemRoot", "SystemDrive", "ComSpec", "PATHEXT"]
                    .into_iter()
                    .map(String::from),
            );
            names
        };
        #[cfg(not(target_os = "windows"))]
        let environment_allowlist = vec!["PATH".into(), "TERM".into()];
        Self {
            version: SANDBOX_PLAN_VERSION,
            package: package.into(),
            read_only_paths: vec![workdir.clone()],
            writable_paths: vec![workdir.clone()],
            workdir,
            environment_allowlist,
            network: NetworkMode::Deny,
            allow_subprocesses: true,
            limits: ResourceLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    Network(Vec<String>),
    Read(Vec<PathBuf>),
    Write(Vec<PathBuf>),
    Env(Vec<String>),
    Subprocess(Vec<String>),
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub package: String,
    pub workdir: PathBuf,
    pub permissions: Vec<Permission>,
    pub timeout_secs: u64,
}

impl SandboxPolicy {
    pub fn minimal(package: impl Into<String>, workdir: PathBuf) -> Self {
        Self {
            package: package.into(),
            workdir,
            permissions: Vec::new(),
            timeout_secs: 30,
        }
    }

    pub fn allows_network(&self) -> bool {
        self.permissions.iter().any(|permission| {
            matches!(
                permission,
                Permission::Network(_) | Permission::Unrestricted
            )
        })
    }

    pub fn allows_read(&self, path: &Path) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        path.starts_with(&self.workdir)
            || self.permissions.iter().any(|permission| match permission {
                Permission::Read(paths) => paths.iter().any(|allowed| path.starts_with(allowed)),
                _ => false,
            })
    }

    pub fn allows_write(&self, path: &Path) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        self.permissions.iter().any(|permission| match permission {
            Permission::Write(paths) => paths.iter().any(|allowed| path.starts_with(allowed)),
            _ => false,
        })
    }

    pub fn allows_env(&self, name: &str) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        self.permissions.iter().any(|permission| match permission {
            Permission::Env(names) => names.iter().any(|allowed| allowed == name),
            _ => false,
        })
    }

    pub fn allows_subprocess(&self, command: &str) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        self.permissions.iter().any(|permission| match permission {
            Permission::Subprocess(commands) => commands.iter().any(|allowed| allowed == command),
            _ => false,
        })
    }

    pub fn to_sandbox_profile(&self) -> String {
        let mut profile = String::from("(version 1)\n(deny default)\n");
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            self.workdir.display()
        ));
        if self.allows_network() {
            profile.push_str("(allow network*)\n");
        }
        if self.is_unrestricted() {
            profile.push_str("(allow default)\n");
        }
        profile
    }

    pub fn allowed_env_names(&self) -> Vec<String> {
        if self.is_unrestricted() {
            return std::env::vars().map(|(name, _)| name).collect();
        }
        let mut names = Vec::new();
        for permission in &self.permissions {
            if let Permission::Env(allowed) = permission {
                for name in allowed {
                    if !names.contains(name) {
                        names.push(name.clone());
                    }
                }
            }
        }
        names
    }

    pub fn to_plan(&self) -> SandboxPlan {
        let mut plan = SandboxPlan::strict(self.package.clone(), self.workdir.clone());
        let requested_environment = self.allowed_env_names();
        #[cfg(not(target_os = "windows"))]
        {
            plan.environment_allowlist = requested_environment;
        }
        #[cfg(target_os = "windows")]
        for name in requested_environment {
            if !plan.environment_allowlist.contains(&name) {
                plan.environment_allowlist.push(name);
            }
        }
        plan.network = if self.allows_network() {
            NetworkMode::Inherit
        } else {
            NetworkMode::Deny
        };
        plan.limits.timeout_secs = self.timeout_secs;
        for permission in &self.permissions {
            match permission {
                Permission::Read(paths) => plan.read_only_paths.extend(paths.iter().cloned()),
                Permission::Write(paths) => plan.writable_paths.extend(paths.iter().cloned()),
                _ => {}
            }
        }
        plan
    }

    fn is_unrestricted(&self) -> bool {
        self.permissions
            .iter()
            .any(|permission| matches!(permission, Permission::Unrestricted))
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn strict_plan_denies_network_and_versions_the_contract() {
        let plan = SandboxPlan::strict("demo", PathBuf::from("/work"));
        assert_eq!(plan.version, SANDBOX_PLAN_VERSION);
        assert_eq!(plan.network, NetworkMode::Deny);
        assert_eq!(plan.writable_paths, vec![PathBuf::from("/work")]);
        assert!(
            !plan
                .environment_allowlist
                .iter()
                .any(|v| v.contains("TOKEN"))
        );
    }

    #[test]
    fn policy_translation_grants_only_declared_capabilities() {
        let mut policy = SandboxPolicy::minimal("demo", PathBuf::from("/work"));
        policy
            .permissions
            .push(Permission::Network(vec!["registry.npmjs.org".into()]));
        policy
            .permissions
            .push(Permission::Env(vec!["TERM".into()]));
        let plan = policy.to_plan();
        assert_eq!(plan.network, NetworkMode::Inherit);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(plan.environment_allowlist, vec!["TERM"]);
        #[cfg(target_os = "windows")]
        assert!(plan.environment_allowlist.contains(&"TERM".to_string()));
    }
}
