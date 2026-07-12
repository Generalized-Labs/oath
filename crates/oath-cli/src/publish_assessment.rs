use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const PUBLISH_ASSESSMENT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishAssessment {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub tag: String,
    pub access: Option<String>,
    pub package_digest: String,
    pub unpacked_bytes: u64,
    pub files: Vec<PublishFile>,
    pub dependency_count: usize,
    pub lifecycle_hooks: Vec<String>,
    pub capabilities: Vec<String>,
    pub source_available: bool,
    pub secret_findings: Vec<String>,
    pub decision: String,
    pub reason_code: String,
    pub previous_release: Option<PublishDiff>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishDiff {
    pub previous_version: String,
    pub added_files: Vec<String>,
    pub removed_files: Vec<String>,
    pub changed_files: Vec<String>,
    pub capabilities_added: Vec<String>,
    pub capabilities_removed: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PersistedEvidence {
    pub directory: String,
    pub assessment_signature: String,
    pub signing_public_key: String,
    pub sbom_path: String,
    pub provenance_path: String,
}

pub fn spdx_sbom(package: &serde_json::Value, assessment: &PublishAssessment) -> serde_json::Value {
    let mut packages = vec![serde_json::json!({
        "SPDXID": "SPDXRef-RootPackage", "name": assessment.name, "versionInfo": assessment.version,
        "downloadLocation": "NOASSERTION", "filesAnalyzed": true,
        "checksums": [{ "algorithm": "SHA256", "checksumValue": assessment.package_digest.trim_start_matches("sha256:") }]
    })];
    for key in ["dependencies", "optionalDependencies", "peerDependencies"] {
        if let Some(deps) = package.get(key).and_then(|v| v.as_object()) {
            for (name, version) in deps {
                packages.push(serde_json::json!({ "SPDXID": format!("SPDXRef-Dependency-{}", name.replace(['@', '/'], "-")), "name": name, "versionInfo": version.as_str().unwrap_or("NOASSERTION"), "downloadLocation": "NOASSERTION", "filesAnalyzed": false }));
            }
        }
    }
    serde_json::json!({
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}-{}", assessment.name, assessment.version),
        "documentNamespace": format!("https://oath.dev/spdx/{}/{}", assessment.name, assessment.package_digest.trim_start_matches("sha256:")),
        "creationInfo": { "created": "1970-01-01T00:00:00Z", "creators": [format!("Tool: oath-{}", env!("CARGO_PKG_VERSION"))] },
        "packages": packages
    })
}

pub fn slsa_provenance(assessment: &PublishAssessment) -> serde_json::Value {
    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{ "name": format!("{}@{}", assessment.name, assessment.version), "digest": { "sha256": assessment.package_digest.trim_start_matches("sha256:") } }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": { "buildType": "https://oath.dev/buildtypes/npm-package/v1", "externalParameters": { "tag": assessment.tag, "access": assessment.access }, "internalParameters": {}, "resolvedDependencies": [] },
            "runDetails": { "builder": { "id": format!("https://github.com/Generalized-Labs/oath@{}", env!("CARGO_PKG_VERSION")) }, "metadata": { "invocationId": assessment.package_digest } }
        }
    })
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn signing_key() -> Result<SigningKey> {
    let home = std::env::var("HOME").context("HOME is required for publish signing")?;
    let path = PathBuf::from(home)
        .join(".oath")
        .join("publish-signing.key");
    if path.exists() {
        let bytes: [u8; 32] = std::fs::read(&path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid publish signing key length"))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("failed to generate publish signing key: {error}"))?;
    std::fs::write(&path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn persist_signed(
    root: &Path,
    assessment: &PublishAssessment,
    package: &serde_json::Value,
) -> Result<PersistedEvidence> {
    let safe_name = assessment.name.replace(['@', '/'], "-");
    let digest = assessment.package_digest.trim_start_matches("sha256:");
    let directory = root.join(".oath").join("publish-assessments").join(format!(
        "{}-{}-{}",
        safe_name,
        assessment.version,
        &digest[..digest.len().min(12)]
    ));
    std::fs::create_dir_all(&directory)?;
    let assessment_path = directory.join("assessment.json");
    let sbom_path = directory.join("sbom.spdx.json");
    let provenance_path = directory.join("provenance.intoto.json");
    atomic_json(&assessment_path, assessment)?;
    atomic_json(&sbom_path, &spdx_sbom(package, assessment))?;
    atomic_json(&provenance_path, &slsa_provenance(assessment))?;
    let key = signing_key()?;
    let canonical = serde_json::to_vec(assessment)?;
    let signature = key.sign(&canonical);
    let encoded_signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    atomic_json(
        &directory.join("signature.json"),
        &serde_json::json!({ "algorithm": "ed25519", "signature": encoded_signature, "public_key": public_key, "subject": "assessment.json" }),
    )?;
    Ok(PersistedEvidence {
        directory: directory.display().to_string(),
        assessment_signature: encoded_signature,
        signing_public_key: public_key,
        sbom_path: sbom_path.display().to_string(),
        provenance_path: provenance_path.display().to_string(),
    })
}

fn looks_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == ".env"
        || lower.ends_with("/.env")
        || lower.ends_with(".pem")
        || lower.ends_with("id_rsa")
        || lower.ends_with(".npmrc")
        || lower.contains("credentials")
}

fn content_secret_marker(bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    [
        ("-----BEGIN PRIVATE KEY-----", "private-key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "rsa-private-key"),
        ("AKIA", "aws-access-key-id"),
        ("ghp_", "github-token"),
        ("npm_", "npm-token"),
    ]
    .into_iter()
    .find_map(|(marker, reason)| text.contains(marker).then_some(reason))
}

fn inferred_capabilities(contents: &[Vec<u8>]) -> Vec<String> {
    let joined = contents
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .collect::<Vec<_>>()
        .join("\n");
    let mut capabilities = Vec::new();
    for (name, markers) in [
        (
            "network",
            &["fetch(", "http.request", "https.request", "node:net"][..],
        ),
        (
            "filesystem",
            &["node:fs", "require('fs')", "require(\"fs\")"][..],
        ),
        ("environment", &["process.env"][..]),
        ("subprocess", &["child_process", "node:child_process"][..]),
        ("dynamic-exec", &["eval(", "new Function("][..]),
    ] {
        if markers.iter().any(|marker| joined.contains(marker)) {
            capabilities.push(name.into());
        }
    }
    capabilities
}

pub fn assess(
    root: &Path,
    files: &[PathBuf],
    package: &serde_json::Value,
    tag: &str,
    access: Option<&str>,
) -> Result<PublishAssessment> {
    let name = package
        .get("name")
        .and_then(|v| v.as_str())
        .context("package name missing")?;
    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .context("package version missing")?;
    let mut manifest = Vec::new();
    let mut secret_findings = Vec::new();
    let mut total = 0;
    let mut contents = Vec::new();
    for file in files {
        let bytes = std::fs::read(file)?;
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        contents.push(bytes.clone());
        total += bytes.len() as u64;
        if looks_sensitive_path(&rel) {
            secret_findings.push(format!("sensitive-path:{rel}"));
        }
        if let Some(marker) = content_secret_marker(&bytes) {
            secret_findings.push(format!("{marker}:{rel}"));
        }
        manifest.push(PublishFile {
            path: rel,
            bytes: bytes.len() as u64,
            sha256: digest,
        });
    }
    manifest.sort_by(|a, b| a.path.cmp(&b.path));
    secret_findings.sort();
    secret_findings.dedup();
    let mut package_hasher = Sha256::new();
    for file in &manifest {
        package_hasher.update(file.path.as_bytes());
        package_hasher.update([0]);
        package_hasher.update(file.sha256.as_bytes());
        package_hasher.update(b"\n");
    }
    let lifecycle_hooks = package
        .get("scripts")
        .and_then(|v| v.as_object())
        .map(|scripts| {
            scripts
                .keys()
                .filter(|name| {
                    matches!(
                        name.as_str(),
                        "preinstall" | "install" | "postinstall" | "prepare" | "prepublishOnly"
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let dependency_count = ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|key| package.get(key).and_then(|v| v.as_object()))
        .map(|deps| deps.len())
        .sum();
    let blocked = !secret_findings.is_empty();
    let capabilities = inferred_capabilities(&contents);
    Ok(PublishAssessment {
        schema_version: PUBLISH_ASSESSMENT_VERSION,
        name: name.into(),
        version: version.into(),
        tag: tag.into(),
        access: access.map(String::from),
        package_digest: format!("sha256:{:x}", package_hasher.finalize()),
        unpacked_bytes: total,
        files: manifest,
        dependency_count,
        lifecycle_hooks,
        capabilities,
        source_available: package.get("repository").is_some(),
        secret_findings,
        decision: if blocked {
            "block".into()
        } else {
            "allow".into()
        },
        reason_code: if blocked {
            "OATH_PUBLISH_SECRET_DETECTED".into()
        } else {
            "OATH_PUBLISH_ALLOWED".into()
        },
        previous_release: None,
    })
}

pub fn attach_previous_release(root: &Path, assessment: &mut PublishAssessment) -> Result<()> {
    let base = root.join(".oath").join("publish-assessments");
    if !base.exists() {
        return Ok(());
    }
    let current = assessment.version.parse::<node_semver::Version>().ok();
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(base)?.flatten() {
        let path = entry.path().join("assessment.json");
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(previous) = serde_json::from_slice::<PublishAssessment>(&bytes) else {
            continue;
        };
        if previous.name != assessment.name {
            continue;
        }
        let Some(version) = previous.version.parse::<node_semver::Version>().ok() else {
            continue;
        };
        if current
            .as_ref()
            .map(|value| version < *value)
            .unwrap_or(false)
        {
            candidates.push((version, previous));
        }
    }
    let Some((_, previous)) = candidates.into_iter().max_by(|(a, _), (b, _)| a.cmp(b)) else {
        return Ok(());
    };
    let old: std::collections::BTreeMap<_, _> = previous
        .files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect();
    let new: std::collections::BTreeMap<_, _> = assessment
        .files
        .iter()
        .map(|file| (file.path.clone(), file.sha256.clone()))
        .collect();
    let added_files = new
        .keys()
        .filter(|path| !old.contains_key(*path))
        .cloned()
        .collect();
    let removed_files = old
        .keys()
        .filter(|path| !new.contains_key(*path))
        .cloned()
        .collect();
    let changed_files = new
        .iter()
        .filter(|(path, digest)| old.get(*path).map(|old| old != *digest).unwrap_or(false))
        .map(|(path, _)| path.clone())
        .collect();
    let capabilities_added = assessment
        .capabilities
        .iter()
        .filter(|cap| !previous.capabilities.contains(*cap))
        .cloned()
        .collect();
    let capabilities_removed = previous
        .capabilities
        .iter()
        .filter(|cap| !assessment.capabilities.contains(*cap))
        .cloned()
        .collect();
    assessment.previous_release = Some(PublishDiff {
        previous_version: previous.version,
        added_files,
        removed_files,
        changed_files,
        capabilities_added,
        capabilities_removed,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assessment_is_deterministic_and_blocks_private_keys() {
        let dir = tempfile::tempdir().unwrap();
        let package_path = dir.path().join("package.json");
        let key_path = dir.path().join("secret.pem");
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.0.0"}"#).unwrap();
        std::fs::write(&key_path, "-----BEGIN PRIVATE KEY-----").unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let assessment = assess(
            dir.path(),
            &[package_path, key_path],
            &package,
            "latest",
            None,
        )
        .unwrap();
        assert_eq!(assessment.decision, "block");
        assert_eq!(assessment.reason_code, "OATH_PUBLISH_SECRET_DETECTED");
        assert!(assessment.package_digest.starts_with("sha256:"));
        let sbom = spdx_sbom(&package, &assessment);
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        let provenance = slsa_provenance(&assessment);
        assert_eq!(
            provenance["predicateType"],
            "https://slsa.dev/provenance/v1"
        );
    }

    #[test]
    fn previous_release_reports_file_and_capability_changes() {
        let dir = tempfile::tempdir().unwrap();
        let package_path = dir.path().join("package.json");
        let source_path = dir.path().join("index.js");
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.0.0"}"#).unwrap();
        std::fs::write(&source_path, "module.exports = 1").unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let previous = assess(
            dir.path(),
            &[package_path.clone(), source_path.clone()],
            &package,
            "latest",
            None,
        )
        .unwrap();
        let previous_dir = dir.path().join(".oath/publish-assessments/demo-1");
        std::fs::create_dir_all(&previous_dir).unwrap();
        std::fs::write(
            previous_dir.join("assessment.json"),
            serde_json::to_vec(&previous).unwrap(),
        )
        .unwrap();
        std::fs::write(&package_path, r#"{"name":"demo","version":"1.1.0"}"#).unwrap();
        std::fs::write(
            &source_path,
            "const fs = require('fs'); module.exports = fs",
        )
        .unwrap();
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
        let mut current = assess(
            dir.path(),
            &[package_path, source_path],
            &package,
            "latest",
            None,
        )
        .unwrap();
        attach_previous_release(dir.path(), &mut current).unwrap();
        let diff = current.previous_release.unwrap();
        assert_eq!(diff.previous_version, "1.0.0");
        assert!(diff.changed_files.contains(&"index.js".into()));
        assert!(diff.capabilities_added.contains(&"filesystem".into()));
    }
}
