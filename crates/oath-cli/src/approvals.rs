use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecApproval {
    pub package: String,
    pub version: String,
    pub integrity: String,
    pub capabilities: Vec<String>,
    pub sandbox_backend: String,
    pub deny_network: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ApprovalFile {
    schema_version: u32,
    approvals: Vec<ExecApproval>,
}

pub struct ApprovalStore {
    path: PathBuf,
}

impl ApprovalStore {
    pub fn default_store() -> Result<Self> {
        let home = oath_core::home_dir()
            .context("HOME or USERPROFILE is required for approval storage")?;
        Ok(Self {
            path: home.join(".oath").join("exec-approvals.json"),
        })
    }

    #[cfg(test)]
    fn at(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<ApprovalFile> {
        if !self.path.exists() {
            return Ok(ApprovalFile {
                schema_version: 1,
                approvals: vec![],
            });
        }
        serde_json::from_slice(&std::fs::read(&self.path)?).context("invalid exec approval store")
    }

    pub fn contains(&self, approval: &ExecApproval) -> Result<bool> {
        Ok(self.load()?.approvals.contains(approval))
    }

    pub fn remember(&self, approval: ExecApproval) -> Result<()> {
        let mut file = self.load()?;
        if !file.approvals.contains(&approval) {
            file.approvals.push(approval);
        }
        file.approvals.sort_by(|a, b| {
            (&a.package, &a.version, &a.integrity).cmp(&(&b.package, &b.version, &b.integrity))
        });
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(tmp, &self.path).context("atomically committing exec approval")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval(integrity: &str) -> ExecApproval {
        ExecApproval {
            package: "demo".into(),
            version: "1.0.0".into(),
            integrity: integrity.into(),
            capabilities: vec!["network".into()],
            sandbox_backend: "native".into(),
            deny_network: true,
        }
    }

    #[test]
    fn approvals_are_bound_to_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = ApprovalStore::at(dir.path().join("approvals.json"));
        store.remember(approval("sha512-one")).unwrap();
        assert!(store.contains(&approval("sha512-one")).unwrap());
        assert!(!store.contains(&approval("sha512-two")).unwrap());
    }
}
