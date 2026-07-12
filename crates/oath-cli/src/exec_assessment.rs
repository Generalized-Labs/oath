use oath_sandbox::{BackendCapabilities, SandboxPlan};
use serde::Serialize;

pub const EXEC_ASSESSMENT_VERSION: u32 = 2;

#[derive(Debug, Serialize)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub binary: Option<String>,
    pub registry: String,
    pub integrity: Option<String>,
    pub publisher: Option<String>,
    pub publish_age_days: Option<u64>,
    pub repository: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PackageEvidence {
    pub unpacked_bytes: u64,
    pub dependency_count: usize,
    pub readable_source: bool,
    pub obfuscated: bool,
    pub native_code: bool,
    pub lifecycle_hooks: bool,
    pub capabilities: Vec<String>,
    pub findings: Vec<String>,
    pub limitations: Vec<&'static str>,
    pub version_diff: Option<VersionDiff>,
}

#[derive(Debug, Serialize)]
pub struct VersionDiff {
    pub previous_version: String,
    pub previous_integrity: Option<String>,
    pub publisher_changed: Option<bool>,
    pub lifecycle_hooks_changed: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicyDecision {
    pub decision: &'static str,
    pub reason_code: &'static str,
    pub grade: String,
    pub score: u8,
}

#[derive(Debug, Serialize)]
pub struct ExecAssessment {
    pub schema_version: u32,
    pub identity: PackageIdentity,
    pub evidence: PackageEvidence,
    pub policy: PolicyDecision,
    pub sandbox: BackendCapabilities,
    pub sandbox_plan: Option<SandboxPlan>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_schema_is_stable_and_machine_readable() {
        let assessment = ExecAssessment {
            schema_version: EXEC_ASSESSMENT_VERSION,
            identity: PackageIdentity {
                name: "demo".into(),
                version: "1.0.0".into(),
                binary: None,
                registry: "npm".into(),
                integrity: Some("sha512-test".into()),
                publisher: None,
                publish_age_days: None,
                repository: None,
            },
            evidence: PackageEvidence {
                unpacked_bytes: 1,
                dependency_count: 0,
                readable_source: true,
                obfuscated: false,
                native_code: false,
                lifecycle_hooks: false,
                capabilities: vec![],
                findings: vec![],
                limitations: vec!["Static analysis cannot prove safety"],
                version_diff: None,
            },
            policy: PolicyDecision {
                decision: "allow",
                reason_code: "OATH_EXEC_ALLOWED",
                grade: "A".into(),
                score: 100,
            },
            sandbox: oath_sandbox::BackendCapabilities {
                backend: "off".into(),
                available: true,
                filesystem_isolation: false,
                network_isolation: false,
                process_isolation: false,
                resource_limits: false,
                degraded_reason: None,
            },
            sandbox_plan: None,
        };
        let value = serde_json::to_value(assessment).unwrap();
        assert_eq!(value["schema_version"], EXEC_ASSESSMENT_VERSION);
        assert_eq!(value["policy"]["reason_code"], "OATH_EXEC_ALLOWED");
        assert_eq!(value["identity"]["integrity"], "sha512-test");
    }
}
