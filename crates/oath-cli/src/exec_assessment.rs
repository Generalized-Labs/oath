use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use oath_contracts::{
    Decision, ExecAssessmentV3, PackageEvidence as PackageEvidenceV3,
    PackageIdentity as PackageIdentityV3, PolicyDecision as PolicyDecisionV3, ReasonCode,
    SandboxEvidence, VersionDiff as VersionDiffV3,
};
use oath_sandbox::{BackendCapabilities, SandboxPlan};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::Path};

pub const EXEC_ASSESSMENT_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct VersionDiff {
    pub previous_version: String,
    pub previous_integrity: Option<String>,
    pub publisher_changed: Option<bool>,
    pub lifecycle_hooks_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub decision: &'static str,
    pub reason_code: ReasonCode,
    pub grade: String,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecAssessment {
    pub schema_version: u32,
    pub identity: PackageIdentity,
    pub evidence: PackageEvidence,
    pub policy: PolicyDecision,
    pub sandbox: BackendCapabilities,
    pub sandbox_plan: Option<SandboxPlan>,
}

pub fn signed_v3(
    assessment: &ExecAssessment,
    generated_at: u64,
    policy_digest: String,
) -> Result<ExecAssessmentV3> {
    let evidence = PackageEvidenceV3 {
        unpacked_bytes: assessment.evidence.unpacked_bytes,
        dependency_count: assessment.evidence.dependency_count,
        readable_source: assessment.evidence.readable_source,
        obfuscated: assessment.evidence.obfuscated,
        native_code: assessment.evidence.native_code,
        lifecycle_hooks: assessment.evidence.lifecycle_hooks,
        capabilities: assessment.evidence.capabilities.clone(),
        findings: assessment.evidence.findings.clone(),
        limitations: assessment
            .evidence
            .limitations
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        version_diff: assessment
            .evidence
            .version_diff
            .as_ref()
            .map(|diff| VersionDiffV3 {
                previous_version: diff.previous_version.clone(),
                previous_integrity: diff.previous_integrity.clone(),
                publisher_changed: diff.publisher_changed,
                lifecycle_hooks_changed: diff.lifecycle_hooks_changed,
            }),
    };
    let evidence_digest = oath_contracts::digest_json(&evidence)?;
    let sandbox = SandboxEvidence {
        backend: assessment.sandbox.backend.clone(),
        available: assessment.sandbox.available,
        filesystem_isolation: assessment.sandbox.filesystem_isolation,
        network_isolation: assessment.sandbox.network_isolation,
        process_isolation: assessment.sandbox.process_isolation,
        resource_limits: assessment.sandbox.resource_limits,
        degraded_reason: assessment.sandbox.degraded_reason.clone(),
    };
    let mut result = ExecAssessmentV3 {
        schema_version: oath_contracts::EXEC_ASSESSMENT_VERSION,
        generated_at,
        expires_at: generated_at.saturating_add(3600),
        identity: PackageIdentityV3 {
            name: assessment.identity.name.clone(),
            version: assessment.identity.version.clone(),
            registry: assessment.identity.registry.clone(),
            integrity: assessment.identity.integrity.clone(),
            publisher: assessment.identity.publisher.clone(),
            publish_age_days: assessment.identity.publish_age_days,
            repository: assessment.identity.repository.clone(),
        },
        evidence,
        policy: PolicyDecisionV3 {
            decision: if assessment.policy.decision == "allow" {
                Decision::Allow
            } else {
                Decision::Deny
            },
            reason_code: assessment.policy.reason_code,
            grade: assessment.policy.grade.clone(),
            score: assessment.policy.score,
        },
        sandbox,
        policy_digest,
        evidence_digest,
        rule_bundle_version: format!("oath-rules/{}", env!("CARGO_PKG_VERSION")),
        signature: None,
    };
    result.signature = Some(oath_contracts::sign_json(
        &result,
        &decision_signing_key()?,
    )?);
    Ok(result)
}

fn decision_signing_key() -> Result<SigningKey> {
    let home =
        oath_core::home_dir().context("HOME or USERPROFILE is required for verdict signing")?;
    let path = home.join(".oath").join("decision-signing.key");
    load_or_create_key(&path)
}

fn load_or_create_key(path: &Path) -> Result<SigningKey> {
    fn read_key(path: &Path) -> Result<SigningKey> {
        let bytes: [u8; 32] = std::fs::read(path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid decision signing key length"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    if path.exists() {
        return read_key(path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("decision key generation failed: {error}"))?;
    let suffix = u64::from_le_bytes(bytes[..8].try_into().expect("eight-byte key prefix"));
    let temp_path = path.with_extension(format!("{suffix:016x}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let result = match std::fs::hard_link(&temp_path, path) {
        Ok(()) => Ok(SigningKey::from_bytes(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_key(path),
        Err(error) => Err(error.into()),
    };
    let _ = std::fs::remove_file(temp_path);
    result
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
                reason_code: ReasonCode::ExecAllowed,
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

    #[test]
    fn concurrent_key_creation_converges() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("decision.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_key(&path).unwrap().to_bytes()
                })
            })
            .collect::<Vec<_>>();
        let keys = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(std::fs::read(path).unwrap().len(), 32);
    }
}
