use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

    fn is_unrestricted(&self) -> bool {
        self.permissions
            .iter()
            .any(|permission| matches!(permission, Permission::Unrestricted))
    }
}
