//! Stable, machine-readable contracts shared by Oath clients and services.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EXEC_ASSESSMENT_VERSION: u32 = 3;
pub const PUBLISH_ASSESSMENT_VERSION: u32 = 2;
pub const REGISTRY_VERDICT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Review,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub algorithm: String,
    pub canonicalization: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub registry: String,
    pub integrity: Option<String>,
    pub publisher: Option<String>,
    pub publish_age_days: Option<u64>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionDiff {
    pub previous_version: String,
    pub previous_integrity: Option<String>,
    pub publisher_changed: Option<bool>,
    pub lifecycle_hooks_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEvidence {
    pub unpacked_bytes: u64,
    pub dependency_count: usize,
    pub readable_source: bool,
    pub obfuscated: bool,
    pub native_code: bool,
    pub lifecycle_hooks: bool,
    pub capabilities: Vec<String>,
    pub findings: Vec<String>,
    pub limitations: Vec<String>,
    pub version_diff: Option<VersionDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason_code: String,
    pub grade: String,
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxEvidence {
    pub backend: String,
    pub available: bool,
    pub filesystem_isolation: bool,
    pub network_isolation: bool,
    pub process_isolation: bool,
    pub resource_limits: bool,
    pub degraded_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecAssessmentV3 {
    pub schema_version: u32,
    pub generated_at: u64,
    pub expires_at: u64,
    pub identity: PackageIdentity,
    pub evidence: PackageEvidence,
    pub policy: PolicyDecision,
    pub sandbox: SandboxEvidence,
    pub policy_digest: String,
    pub evidence_digest: String,
    pub rule_bundle_version: String,
    pub signature: Option<DetachedSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryVerdictV1 {
    pub schema_version: u32,
    pub generated_at: u64,
    pub expires_at: u64,
    pub package: PackageIdentity,
    pub decision: Decision,
    pub reason_code: String,
    pub risk_score: u8,
    pub package_digest: String,
    pub assessment_digest: String,
    pub policy_digest: String,
    pub rule_bundle_version: String,
    pub limitations: Vec<String>,
    pub signature: Option<DetachedSignature>,
}

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unsupported signature canonicalization: {0}")]
    UnsupportedCanonicalization(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

pub fn digest_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json_bytes(value)?)
    ))
}

/// Oath JSON v1: compact JSON with object keys sorted lexicographically at
/// every depth. Published contracts use only integers, so number encoding is
/// the stable serde_json representation.
pub fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    fn write(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        match value {
            serde_json::Value::Null => output.extend_from_slice(b"null"),
            serde_json::Value::Bool(value) => {
                output.extend_from_slice(if *value { b"true" } else { b"false" })
            }
            serde_json::Value::Number(value) => {
                output.extend_from_slice(value.to_string().as_bytes())
            }
            serde_json::Value::String(value) => serde_json::to_writer(&mut *output, value)?,
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(value, output)?;
                }
                output.push(b']');
            }
            serde_json::Value::Object(values) => {
                output.push(b'{');
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_by_key(|(key, _)| *key);
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write(value, output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let value = serde_json::to_value(value)?;
    let mut output = Vec::new();
    write(&value, &mut output)?;
    Ok(output)
}

pub fn sign_json(
    value: &impl Serialize,
    key: &SigningKey,
) -> Result<DetachedSignature, serde_json::Error> {
    let signature = key.sign(&canonical_json_bytes(value)?);
    Ok(DetachedSignature {
        algorithm: "ed25519".into(),
        canonicalization: "oath-json-v1".into(),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().to_bytes()),
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })
}

pub fn verify_json(
    value: &impl Serialize,
    detached: &DetachedSignature,
) -> Result<(), ContractError> {
    if detached.algorithm != "ed25519" {
        return Err(ContractError::UnsupportedAlgorithm(
            detached.algorithm.clone(),
        ));
    }
    if detached.canonicalization != "oath-json-v1" {
        return Err(ContractError::UnsupportedCanonicalization(
            detached.canonicalization.clone(),
        ));
    }
    let key: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&detached.public_key)?
        .try_into()
        .map_err(|_| ContractError::InvalidPublicKey)?;
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(&detached.signature)?
        .try_into()
        .map_err(|_| ContractError::InvalidSignature)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| ContractError::InvalidPublicKey)?
        .verify(
            &canonical_json_bytes(value)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ContractError::InvalidSignature)
}

pub fn verify_exec_assessment(value: &ExecAssessmentV3) -> Result<(), ContractError> {
    let signature = value
        .signature
        .as_ref()
        .ok_or(ContractError::InvalidSignature)?
        .clone();
    let mut unsigned = value.clone();
    unsigned.signature = None;
    verify_json(&unsigned, &signature)
}

pub fn verify_registry_verdict(value: &RegistryVerdictV1) -> Result<(), ContractError> {
    let signature = value
        .signature
        .as_ref()
        .ok_or(ContractError::InvalidSignature)?
        .clone();
    let mut unsigned = value.clone();
    unsigned.signature = None;
    verify_json(&unsigned, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_contract_round_trips_and_detects_changes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut value = serde_json::json!({"decision":"allow","digest":"abc"});
        let signature = sign_json(&value, &key).unwrap();
        verify_json(&value, &signature).unwrap();
        let mut unsupported = signature.clone();
        unsupported.canonicalization = "future-json".into();
        assert!(matches!(
            verify_json(&value, &unsupported),
            Err(ContractError::UnsupportedCanonicalization(_))
        ));
        value["decision"] = "deny".into();
        assert!(verify_json(&value, &signature).is_err());
    }

    #[test]
    fn canonical_json_is_independent_of_struct_field_order() {
        #[derive(Serialize)]
        struct First {
            z: u8,
            a: u8,
        }
        #[derive(Serialize)]
        struct Second {
            a: u8,
            z: u8,
        }
        assert_eq!(
            canonical_json_bytes(&First { z: 1, a: 2 }).unwrap(),
            canonical_json_bytes(&Second { a: 2, z: 1 }).unwrap()
        );
        assert_eq!(
            canonical_json_bytes(&First { z: 1, a: 2 }).unwrap(),
            br#"{"a":2,"z":1}"#
        );
    }

    #[test]
    fn decisions_have_stable_wire_values() {
        assert_eq!(
            serde_json::to_string(&Decision::Review).unwrap(),
            "\"review\""
        );
        assert_eq!(
            serde_json::from_str::<Decision>("\"deny\"").unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn published_contract_files_parse_and_keep_their_versions() {
        let contracts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
        for (file, version) in [
            ("exec-assessment-v3.schema.json", 3),
            ("publish-assessment-v2.schema.json", 2),
            ("registry-verdict-v1.schema.json", 1),
        ] {
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(contracts.join(file)).unwrap()).unwrap();
            assert_eq!(
                value["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(value["properties"]["schema_version"]["const"], version);
            assert_eq!(value["additionalProperties"], false);
        }

        let openapi: serde_yaml::Value = serde_yaml::from_slice(
            &std::fs::read(contracts.join("registry-openapi.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(openapi["openapi"], "3.1.0");
        for path in [
            "/livez",
            "/readyz",
            "/v1/verdicts/{name}/{version}",
            "/v1/security/osv",
            "/-/oath/transparency/inclusion/{sequence}",
            "/-/oath/transparency/consistency",
        ] {
            assert!(
                openapi["paths"][path].is_mapping(),
                "missing OpenAPI path {path}"
            );
        }
    }
}
