use anyhow::Result;
use serde::Serialize;

const COMPATIBILITY_MANIFEST: &str =
    include_str!("../../../contracts/npm-compatibility-manifest-v1.json");

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub schema_version: u32,
    pub product: &'static str,
    pub version: &'static str,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub compatibility: CompatibilityCapabilities,
    pub containment: oath_sandbox::BackendCapabilities,
    pub evidence: EvidenceCapabilities,
    pub signing: SigningCapabilities,
}

#[derive(Debug, Serialize)]
pub struct CompatibilityCapabilities {
    pub target: String,
    pub manifest_version: u64,
    pub ga_required_commands: Vec<String>,
    pub supported_commands: Vec<String>,
    pub preview_commands: Vec<String>,
    pub missing_ga_commands: Vec<String>,
    pub intentional_exceptions: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceCapabilities {
    pub verify: bool,
    pub replay: bool,
    pub supported_contracts: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SigningCapabilities {
    pub detached_document_algorithm: &'static str,
    pub canonicalization: &'static str,
    pub platform_release_signing_required: bool,
    pub sigstore_provenance_required: bool,
}

pub fn report() -> Result<CapabilityReport> {
    let manifest: serde_json::Value = serde_json::from_str(COMPATIBILITY_MANIFEST)?;
    let strings = |key: &str| -> Vec<String> {
        manifest[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect()
    };
    let required = strings("ga_required_commands");
    let supported = strings("supported_commands");
    let missing = required
        .iter()
        .filter(|command| !supported.contains(command))
        .cloned()
        .collect();
    Ok(CapabilityReport {
        schema_version: 1,
        product: "oath-cli",
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        compatibility: CompatibilityCapabilities {
            target: manifest["compatibility_target"]
                .as_str()
                .unwrap_or("npm/npx")
                .to_owned(),
            manifest_version: manifest["schema_version"].as_u64().unwrap_or(1),
            ga_required_commands: required,
            supported_commands: supported,
            preview_commands: strings("preview_commands"),
            missing_ga_commands: missing,
            intentional_exceptions: manifest["intentional_exceptions"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        },
        containment: oath_sandbox::verified_native_capabilities(),
        evidence: EvidenceCapabilities {
            verify: true,
            replay: true,
            supported_contracts: vec![
                "CompatibilityEvidence/v1",
                "DetectionEvidenceReport/v2",
                "PerformanceEvidence/v1",
                "PerformanceEvidence/v2",
                "OperationalDrillReport/v2",
                "ProductionDeploymentEvidence/v1",
                "TransparencyCheckpoint/v3",
                "IndependentAuditReport/v1",
            ],
        },
        signing: SigningCapabilities {
            detached_document_algorithm: "ed25519",
            canonicalization: "oath-json-v1",
            platform_release_signing_required: true,
            sigstore_provenance_required: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_exposes_complete_command_surface() {
        let report = report().unwrap();
        assert!(
            report
                .compatibility
                .supported_commands
                .contains(&"install".into())
        );
        assert!(report.compatibility.missing_ga_commands.is_empty());
        assert_eq!(report.compatibility.manifest_version, 1);
    }
}
