use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use oath_contracts::{
    Decision, ExecAssessmentV3, PackageEvidence, PackageIdentity, PolicyDecision,
    PublishAssessmentV2, PublishDiff, PublishFile, ReasonCode, RegistryVerdictV1, SandboxEvidence,
    digest_json, sign_json,
};

fn write_json(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    Ok(())
}

fn identity() -> PackageIdentity {
    PackageIdentity {
        name: "@oath/example".into(),
        version: "1.2.3".into(),
        registry: "https://registry.npmjs.org".into(),
        integrity: Some("sha512-example-integrity".into()),
        publisher: Some("oath-example-publisher".into()),
        publish_age_days: Some(30),
        repository: Some("https://github.com/Generalized-Labs/oath".into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("contracts/examples"));
    std::fs::create_dir_all(&output)?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let generated_at = 1_800_000_000;

    let evidence = PackageEvidence {
        unpacked_bytes: 4096,
        dependency_count: 2,
        readable_source: true,
        obfuscated: false,
        native_code: false,
        lifecycle_hooks: false,
        capabilities: vec!["filesystem-read".into()],
        findings: Vec::new(),
        limitations: vec!["Static analysis cannot prove package safety".into()],
        version_diff: None,
    };
    let mut exec = ExecAssessmentV3 {
        schema_version: oath_contracts::EXEC_ASSESSMENT_VERSION,
        generated_at,
        expires_at: generated_at + 3600,
        identity: identity(),
        evidence_digest: digest_json(&evidence)?,
        evidence,
        policy: PolicyDecision {
            decision: Decision::Allow,
            reason_code: ReasonCode::ExecAllowed,
            grade: "A".into(),
            score: 96,
        },
        sandbox: SandboxEvidence {
            backend: "linux-bwrap-v1".into(),
            available: true,
            filesystem_isolation: true,
            network_isolation: true,
            process_isolation: true,
            resource_limits: true,
            degraded_reason: None,
        },
        policy_digest: digest_json(&serde_json::json!({"minimum_grade":"B","network":"deny"}))?,
        rule_bundle_version: "oath-rules/1".into(),
        signature: None,
    };
    exec.signature = Some(sign_json(&exec, &key)?);
    write_json(&output.join("exec-assessment-v3.signed.json"), &exec)?;

    let files = vec![
        PublishFile {
            path: "index.js".into(),
            bytes: 32,
            sha256: "11".repeat(32),
        },
        PublishFile {
            path: "package.json".into(),
            bytes: 96,
            sha256: "22".repeat(32),
        },
    ];
    let mut publish = PublishAssessmentV2 {
        schema_version: oath_contracts::PUBLISH_ASSESSMENT_VERSION,
        generated_at,
        expires_at: generated_at + 3600,
        name: "@oath/example".into(),
        version: "1.2.3".into(),
        tag: "latest".into(),
        access: Some("public".into()),
        package_digest: format!("sha256:{}", "33".repeat(32)),
        unpacked_bytes: 128,
        evidence_digest: digest_json(&files)?,
        files,
        dependency_count: 2,
        lifecycle_hooks: Vec::new(),
        capabilities: vec!["filesystem".into()],
        source_available: true,
        secret_findings: Vec::new(),
        decision: Decision::Allow,
        reason_code: ReasonCode::PublishAllowed,
        previous_release: Some(PublishDiff {
            previous_version: "1.2.2".into(),
            added_files: Vec::new(),
            removed_files: Vec::new(),
            changed_files: vec!["index.js".into()],
            capabilities_added: Vec::new(),
            capabilities_removed: Vec::new(),
        }),
        policy_digest: digest_json(&serde_json::json!({"secrets":"deny"}))?,
        rule_bundle_version: "oath-rules/1".into(),
        limitations: vec!["Static analysis cannot prove package safety".into()],
        signature: None,
    };
    publish.signature = Some(sign_json(&publish, &key)?);
    write_json(&output.join("publish-assessment-v2.signed.json"), &publish)?;

    let registry_evidence = serde_json::json!({
        "package_digest": format!("sha256:{}", "33".repeat(32)),
        "risk_score": 4,
        "source_available": true
    });
    let mut registry = RegistryVerdictV1 {
        schema_version: oath_contracts::REGISTRY_VERDICT_VERSION,
        generated_at,
        expires_at: generated_at + 86_400,
        package: identity(),
        decision: Decision::Allow,
        reason_code: ReasonCode::RegistryAllowed,
        risk_score: 4,
        package_digest: format!("sha256:{}", "33".repeat(32)),
        assessment_digest: digest_json(&registry_evidence)?,
        policy_digest: digest_json(&serde_json::json!({"critical":"deny"}))?,
        rule_bundle_version: "oath-rules/1".into(),
        limitations: vec!["Runtime containment remains required".into()],
        signature: None,
    };
    registry.signature = Some(sign_json(&registry, &key)?);
    write_json(&output.join("registry-verdict-v1.signed.json"), &registry)?;
    Ok(())
}
