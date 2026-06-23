//! PackageScanner: walks a package directory, analyzes every JS/TS file,
//! and aggregates results into a single AnalysisReport.

use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

use crate::analyzer::Analyzer;
use crate::report::{AnalysisReport, Capabilities, Finding, FindingKind, RiskLevel};

pub struct PackageScanner;

impl PackageScanner {
    /// Scan an extracted package directory (e.g. ~/.oath/store/express@4.18.2/)
    pub fn scan(package_name: &str, package_version: &str, package_dir: &Path) -> Result<AnalysisReport> {
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut files_scanned = 0usize;
        let mut lines_scanned = 0usize;

        // Check for install scripts in package.json first
        let pkg_json_path = package_dir.join("package.json");
        if pkg_json_path.exists() {
            let content = std::fs::read_to_string(&pkg_json_path)?;
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                let scripts = json.get("scripts");
                for hook in &["preinstall", "install", "postinstall"] {
                    if let Some(script) = scripts.and_then(|s| s.get(hook)) {
                        if let Some(cmd) = script.as_str() {
                            all_findings.push(Finding {
                                kind: FindingKind::InstallScript,
                                risk: RiskLevel::Medium,
                                message: format!("{hook} script: {cmd}"),
                                file: "package.json".to_string(),
                                line: 0,
                                snippet: Some(cmd.chars().take(120).collect()),
                            });
                        }
                    }
                }
            }
        }

        // Walk all JS/TS files
        for entry in WalkDir::new(package_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            // Only analyze JS/TS source files, skip minified/test files
            if !matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx") {
                continue;
            }

            // Skip known non-threatening paths
            let path_str = path.to_string_lossy();
            if path_str.contains("test") || path_str.contains("spec") || path_str.contains("__tests__") {
                continue;
            }

            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue, // skip binary-looking files
            };

            // Skip massive minified bundles (>500KB -- not useful to scan)
            if source.len() > 500_000 {
                continue;
            }

            let relative_path = path
                .strip_prefix(package_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            lines_scanned += source.lines().count();
            files_scanned += 1;

            let mut analyzer = Analyzer::new(source, relative_path);
            analyzer.analyze()?;
            all_findings.extend(analyzer.findings);
        }

        // Deduplicate findings by (kind, file, line)
        all_findings.dedup_by(|a, b| a.kind == b.kind && a.file == b.file && a.line == b.line);

        // Aggregate capabilities
        let mut capabilities = Capabilities::default();
        for f in &all_findings {
            match f.kind {
                FindingKind::Network | FindingKind::DataExfiltration => capabilities.network = true,
                FindingKind::Filesystem => capabilities.filesystem = true,
                FindingKind::EnvAccess => capabilities.env_access = true,
                FindingKind::Subprocess => capabilities.subprocess = true,
                FindingKind::DynamicExec => capabilities.dynamic_exec = true,
                FindingKind::InstallScript => capabilities.has_install_scripts = true,
                _ => {}
            }
        }

        // Overall risk = max finding risk
        let overall_risk = all_findings
            .iter()
            .map(|f| f.risk.clone())
            .max()
            .unwrap_or(RiskLevel::Clean);

        Ok(AnalysisReport {
            package_name: package_name.to_string(),
            package_version: package_version.to_string(),
            overall_risk,
            findings: all_findings,
            files_scanned,
            lines_scanned,
            capabilities,
        })
    }
}
